// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2021 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include "main.h"
#include "bind.h"
#include "netlink.h"
#include "sock.h"
#include "peer.h"
#include "stats_counters.h"
#include "proto.h"
#include "crypto.h"
#include "skb.h"
#include "tcp.h"
#include "udp.h"

#include <linux/workqueue.h>
#include <uapi/linux/if_ether.h>

static const unsigned char ovpn_keepalive_message[] = {
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

static const unsigned char ovpn_explicit_exit_notify_message[] = {
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
	6 // OCC_EXIT
};

/* Is keepalive message?
 * Assumes that single byte at skb->data is defined.
 */
static bool ovpn_is_keepalive(struct sk_buff *skb)
{
	if (*skb->data != OVPN_KEEPALIVE_FIRST_BYTE)
		return false;

	if (!pskb_may_pull(skb, sizeof(ovpn_keepalive_message)))
		return false;

	return !memcmp(skb->data, ovpn_keepalive_message,
		       sizeof(ovpn_keepalive_message));
}

int ovpn_struct_init(struct net_device *dev)
{
	struct ovpn_struct *ovpn = netdev_priv(dev);
	int err;

	memset(ovpn, 0, sizeof(*ovpn));

	ovpn->dev = dev;

	err = ovpn_netlink_init(ovpn);
	if (err < 0)
		return err;

	spin_lock_init(&ovpn->lock);
	spin_lock_init(&ovpn->peers.lock);

	ovpn->crypto_wq = alloc_workqueue("ovpn-crypto-wq-%s",
					  WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 0,
					  dev->name);
	if (!ovpn->crypto_wq)
		return -ENOMEM;

	ovpn->events_wq = alloc_workqueue("ovpn-event-wq-%s", 0, 0, dev->name);
	if (!ovpn->events_wq)
		return -ENOMEM;

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	err = security_tun_dev_alloc_security(&ovpn->security);
	if (err < 0)
		return err;

	/* kernel -> userspace tun queue length */
	ovpn->max_tun_queue_len = OVPN_MAX_TUN_QUEUE_LEN;

	return 0;
}

/* Called after decrypt to write IP packet to tun netdev.
 * This method is expected to manage/free skb.
 */
static void tun_netdev_write(struct ovpn_peer *peer, struct sk_buff *skb)
{
	/* packet integrity was verified on the VPN layer - no need to perform
	 * any additional check along the stack
	 */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->csum_level = ~0;

	/* skb hash for transport packet no longer valid after decapsulation */
	skb_clear_hash(skb);

	/* post-decrypt scrub -- prepare to inject encapsulated packet onto tun
	 * interface, based on __skb_tunnel_rx() in dst.h
	 */
	skb->dev = peer->ovpn->dev;
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, true);

	/* set transport header */
	skb->transport_header = 0;
	skb_probe_transport_header(skb);

	/* update per-cpu RX stats with the stored size of encrypted packet */

	/* we are in softirq context - hence no locking nor disable preemption needed */
	dev_sw_netstats_rx_add(peer->ovpn->dev, OVPN_SKB_CB(skb)->rx_stats_size);

	/* cause packet to be "received" by tun interface */
	napi_gro_receive(&peer->napi, skb);
}

int ovpn_napi_poll(struct napi_struct *napi, int budget)
{
	struct ovpn_peer *peer = container_of(napi, struct ovpn_peer, napi);
	struct sk_buff *skb;
	int work_done = 0;

	if (unlikely(budget <= 0))
		return 0;
	/* this function should schedule at most 'budget' number of
	 * packets for delivery to the tun interface.
	 * If in the queue we have more packets than what allowed by the
	 * budget, the next polling will take care of those
	 */
	while ((work_done < budget) &&
	       (skb = __ptr_ring_consume(&peer->netif_rx_ring))) {
		tun_netdev_write(peer, skb);
		work_done++;
	}

	if (work_done < budget) {
		napi_complete_done(napi, work_done);

		if (!__ptr_ring_empty(&peer->netif_rx_ring))
			napi_schedule(&peer->napi);
	}

	return work_done;
}

static int ovpn_transport_to_userspace(struct ovpn_struct *ovpn, const struct ovpn_peer *peer,
				       struct sk_buff *skb)
{
	int ret;

	ret = skb_linearize(skb);
	if (ret < 0)
		return ret;

	ret = ovpn_netlink_send_packet(ovpn, peer, skb->data, skb->len);
	if (ret < 0)
		return ret;

	consume_skb(skb);
	return 0;
}

/* Entry point for processing an incoming packet (in skb form)
 *
 * Enqueue the packet and schedule RX consumer.
 * Reference to peer is dropped only in case of success.
 *
 * Return 0  if the packet was handled (and consumed)
 * Return <0 in case of error (return value is error code)
 */
int ovpn_recv(struct ovpn_struct *ovpn, struct ovpn_peer *peer, struct sk_buff *skb)
{
	int ret;

	/* At this point we know the packet is from a configured peer.
	 * DATA_V2 packets are handled in kernel space, the rest goes to user space.
	 *
	 * Packets are sent to userspace via netlink API in order to be consistenbt across
	 * UDP and TCP.
	 */
	if (unlikely(ovpn_opcode_from_skb(skb, 0) != OVPN_DATA_V2)) {
		ret = ovpn_transport_to_userspace(ovpn, peer, skb);
		if (ret < 0)
			return ret;

		ovpn_peer_put(peer);
		return 0;
	}

	ret = __ptr_ring_produce(&peer->rx_ring, skb);
	if (unlikely(ret < 0))
		return -ENOSPC;

	if (!queue_work(ovpn->crypto_wq, &peer->decrypt_work))
		ovpn_peer_put(peer);

	return 0;
}

static int ovpn_decrypt_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;
	unsigned int rx_stats_size;
	__be16 proto;
	int ret = -1;
	u8 key_id;

	/* save original packet size for stats accounting */
	OVPN_SKB_CB(skb)->rx_stats_size = skb->len;

	/* get the key slot matching the key Id in the received packet */
	key_id = ovpn_key_id_from_skb(skb);
	ks = ovpn_crypto_key_id_to_slot(&peer->crypto, key_id);
	if (unlikely(!ks)) {
		pr_info_ratelimited("%s: no available key for peer %u, key-id: %u\n", __func__,
				    peer->id, key_id);
		goto drop;
	}

	/* decrypt */
	ret = ks->ops->decrypt(ks, skb);

	ovpn_crypto_key_slot_put(ks);

	if (unlikely(ret < 0)) {
		pr_err_ratelimited("%s: error during decryption for peer %u, key-id %u: %d\n",
				   __func__, peer->id, key_id, ret);
		goto drop;
	}

	/* note event of authenticated packet received for keepalive */
	ovpn_peer_keepalive_recv_reset(peer);

	/* increment RX stats */
	rx_stats_size = OVPN_SKB_CB(skb)->rx_stats_size;
	ovpn_peer_stats_increment_rx(peer, rx_stats_size);

	/* check if this is a valid datapacket that has to be delivered to the
	 * tun interface
	 */
	skb_reset_network_header(skb);
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto)) {
		/* check if null packet */
		if (unlikely(!pskb_may_pull(skb, 1))) {
			ret = -EINVAL;
			goto drop;
		}

		/* check if special OpenVPN message */
		if (ovpn_is_keepalive(skb)) {
			pr_debug("ping received\n");
			/* not an error */
			consume_skb(skb);
			/* inform the caller that NAPI should not be scheduled
			 * for this packet
			 */
			return -1;
		}

		ret = -EPROTONOSUPPORT;
		goto drop;
	}
	skb->protocol = proto;

	ret = __ptr_ring_produce(&peer->netif_rx_ring, skb);
drop:
	if (unlikely(ret < 0))
		kfree_skb(skb);

	return ret;
}

/* pick packet from RX queue, decrypt and forward it to the tun device */
void ovpn_decrypt_work(struct work_struct *work)
{
	struct ovpn_peer *peer;
	struct sk_buff *skb;

	peer = container_of(work, struct ovpn_peer, decrypt_work);
	while ((skb = __ptr_ring_consume(&peer->rx_ring))) {
		if (likely(ovpn_decrypt_one(peer, skb) == 0)) {
			/* if a packet has been enqueued for NAPI, signal
			 * availability to the networking stack
			 */
			local_bh_disable();
			napi_schedule(&peer->napi);
			local_bh_enable();
		}

		/* give a chance to be rescheduled if needed */
		if (need_resched())
			cond_resched();
	}
	ovpn_peer_put(peer);
}

static bool ovpn_encrypt_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;
	bool success = false;
	int ret;

	/* get primary key to be used for encrypting data */
	ks = ovpn_crypto_key_slot_primary(&peer->crypto);
	if (unlikely(!ks)) {
		pr_info_ratelimited("%s: error while retrieving primary key slot\n", __func__);
		return false;
	}

	/* init packet ID to undef in case we err before setting real value */
	OVPN_SKB_CB(skb)->pktid = 0;

	if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL &&
		     skb_checksum_help(skb))) {
		pr_err_ratelimited("%s: cannot compute checksum for outgoing packet\n", __func__);
		goto err;
	}

	/* encrypt */
	ret = ks->ops->encrypt(ks, skb, peer->id);
	if (unlikely(ret < 0)) {
		pr_err_ratelimited("%s: error during encryption: %d\n", __func__, ret);
		goto err;
	}

	success = true;
err:
	ovpn_crypto_key_slot_put(ks);
	return success;
}

/* Process packets in TX queue in a transport-specific way.
 *
 * UDP transport - encrypt and send across the tunnel.
 * TCP transport - encrypt and put into TCP TX queue.
 */
void ovpn_encrypt_work(struct work_struct *work)
{
	struct sk_buff *skb, *curr, *next;
	struct ovpn_peer *peer;

	peer = container_of(work, struct ovpn_peer, encrypt_work);
	while ((skb = __ptr_ring_consume(&peer->tx_ring))) {
		/* this might be a GSO-segmented skb list: process each skb
		 * independently
		 */
		skb_list_walk_safe(skb, curr, next) {
			/* if one segment fails encryption, we drop the entire
			 * packet, because it does not really make sense to send
			 * only part of it at this point
			 */
			if (unlikely(!ovpn_encrypt_one(peer, curr))) {
				kfree_skb_list(skb);
				skb = NULL;
				break;
			}
		}

		/* successful encryption */
		if (skb) {
			skb_list_walk_safe(skb, curr, next) {
				skb_mark_not_on_list(curr);

				switch (peer->sock->sock->sk->sk_protocol) {
				case IPPROTO_UDP:
					ovpn_udp_send_skb(peer->ovpn, peer, curr);
					break;
				case IPPROTO_TCP:
					ovpn_tcp_send_skb(peer, curr);
					break;
				default:
					/* no transport configured yet */
					consume_skb(skb);
					break;
				}
			}
		}

		/* give a chance to be rescheduled if needed */
		if (need_resched())
			cond_resched();
	}
	ovpn_peer_put(peer);
}

/* Put skb into TX queue and schedule a consumer */
static void ovpn_queue_skb(struct ovpn_struct *ovpn, struct sk_buff *skb, struct ovpn_peer *peer)
{
	int ret;

	if (likely(!peer))
		peer = ovpn_peer_lookup_vpn_addr(ovpn, skb);
	if (unlikely(!peer)) {
		pr_info_ratelimited("%s: no peer to send data to\n", __func__);
		goto drop;
	}

	ret = __ptr_ring_produce(&peer->tx_ring, skb);
	if (unlikely(ret < 0)) {
		pr_err_ratelimited("%s: cannot queue packet to TX ring\n", __func__);
		goto drop;
	}

	if (!queue_work(ovpn->crypto_wq, &peer->encrypt_work))
		ovpn_peer_put(peer);

	return;
drop:
	if (peer)
		ovpn_peer_put(peer);
	kfree_skb_list(skb);
}

/* Net device start xmit
 */
netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ovpn_struct *ovpn = netdev_priv(dev);
	struct sk_buff *segments, *tmp, *curr, *next;
	struct sk_buff_head skb_list;
	__be16 proto;
	int ret;

	/* reset netfilter state */
	nf_reset_ct(skb);

	/* verify IP header size in network packet */
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto || (skb->protocol != proto))) {
		net_dbg_ratelimited("%s: dropping malformed payload packet\n",
				    dev->name);
		goto drop;
	}

	if (skb_is_gso(skb)) {
		segments = skb_gso_segment(skb, 0);
		if (IS_ERR(segments)) {
			ret = PTR_ERR(segments);
			net_dbg_ratelimited("%s: cannot segment packet: %d\n", dev->name, ret);
			goto drop;
		}

		consume_skb(skb);
		skb = segments;
	}

	/* from this moment on, "skb" might be a list */

	__skb_queue_head_init(&skb_list);
	skb_list_walk_safe(skb, curr, next) {
		skb_mark_not_on_list(curr);

		tmp = skb_share_check(curr, GFP_ATOMIC);
		if (unlikely(!tmp)) {
			kfree_skb_list(next);
			net_dbg_ratelimited("%s: skb_share_check failed\n", dev->name);
			goto drop_list;
		}

		__skb_queue_tail(&skb_list, tmp);
	}
	skb_list.prev->next = NULL;

	ovpn_queue_skb(ovpn, skb_list.next, NULL);

	return NETDEV_TX_OK;

drop_list:
	skb_queue_walk_safe(&skb_list, curr, next)
		kfree_skb(curr);
drop:
	skb_tx_error(skb);
	kfree_skb_list(skb);
	return NET_XMIT_DROP;
}

/* Encrypt and transmit a special message to peer, such as keepalive
 * or explicit-exit-notify.  Called from softirq context.
 * Assumes that caller holds a reference to peer.
 */
static void ovpn_xmit_special(struct ovpn_peer *peer, const void *data,
			      const unsigned int len)
{
	struct ovpn_struct *ovpn;
	struct sk_buff *skb;

	ovpn = peer->ovpn;
	if (unlikely(!ovpn))
		return;

	skb = alloc_skb(256 + len, GFP_ATOMIC);
	if (unlikely(!skb))
		return;

	skb_reserve(skb, 128);
	skb->priority = TC_PRIO_BESTEFFORT;
	memcpy(__skb_put(skb, len), data, len);

	/* increase reference counter when passing peer to sending queue */
	if (!ovpn_peer_hold(peer)) {
		pr_debug("%s: cannot hold peer reference for sending special packet\n", __func__);
		kfree_skb(skb);
		return;
	}

	ovpn_queue_skb(ovpn, skb, peer);
}

void ovpn_keepalive_xmit(struct ovpn_peer *peer)
{
	ovpn_xmit_special(peer, ovpn_keepalive_message,
			  sizeof(ovpn_keepalive_message));
}

/* Transmit explicit exit notification.
 * Called from process context.
 */
void ovpn_explicit_exit_notify_xmit(struct ovpn_peer *peer)
{
	ovpn_xmit_special(peer, ovpn_explicit_exit_notify_message,
			  sizeof(ovpn_explicit_exit_notify_message));
}

/* Copy buffer into skb and send it across the tunnel.
 *
 * For UDP transport: just sent the skb to peer
 * For TCP transport: put skb into TX queue
 */
int ovpn_send_data(struct ovpn_struct *ovpn, u32 peer_id, const u8 *data, size_t len)
{
	u16 skb_len = SKB_HEADER_LEN + len;
	struct ovpn_peer *peer;
	struct sk_buff *skb;
	bool tcp = false;
	int ret = 0;

	peer = ovpn_peer_lookup_id(ovpn, peer_id);
	if (unlikely(!peer)) {
		pr_debug("no peer to send data to\n");
		return -EHOSTUNREACH;
	}

	if (peer->sock->sock->sk->sk_protocol == IPPROTO_TCP) {
		skb_len += sizeof(u16);
		tcp = true;
	}

	skb = alloc_skb(skb_len, GFP_ATOMIC);
	if (unlikely(!skb)) {
		ret = -ENOMEM;
		goto out;
	}

	skb_reserve(skb, SKB_HEADER_LEN);
	skb_put_data(skb, data, len);

	/* prepend TCP packet with size, as required by OpenVPN protocol */
	if (tcp) {
		*(__be16 *)__skb_push(skb, sizeof(u16)) = htons(len);
		ovpn_queue_tcp_skb(peer, skb);
	} else {
		ovpn_udp_send_skb(ovpn, peer, skb);
	}
out:
	ovpn_peer_put(peer);
	return ret;
}
