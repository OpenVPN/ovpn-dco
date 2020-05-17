// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2020 OpenVPN, Inc.
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
#include "work.h"
#include "skb.h"
#include "udp.h"

#include <linux/workqueue.h>
#include <uapi/linux/if_ether.h>

int ovpn_struct_init(struct net_device *dev)
{
	struct ovpn_struct *ovpn = netdev_priv(dev);
	int err;

	ovpn->dev = dev;

	err = ovpn_netlink_init(ovpn);
	if (err < 0)
		return err;

	spin_lock_init(&ovpn->lock);
	RCU_INIT_POINTER(ovpn->peer, NULL);

	ovpn->crypto_wq = alloc_workqueue("ovpn-crypto-wq-%s",
					  WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 0,
					  dev->name);
	if (!ovpn->crypto_wq)
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
static int tun_netdev_write(struct ovpn_peer *peer, struct sk_buff *skb)
{
	unsigned int rx_stats_size;
	int ret;

	/* note event of authenticated packet received for keepalive */
	ovpn_peer_update_keepalive_expire(peer);

	/* increment RX stats */
	rx_stats_size = OVPN_SKB_CB(skb)->rx_stats_size;
	ovpn_peer_stats_increment_rx(peer, rx_stats_size);

	/* verify IP header size, set skb->protocol,
	 * set skb network header, and possibly stash shim
	 */
	skb_reset_network_header(skb);
	ret = ovpn_ip_header_probe(skb);
	if (unlikely(ret < 0)) {
		/* check if null packet */
		if (unlikely(!pskb_may_pull(skb, 1))) {
			ret = -EINVAL;
			goto drop;
		}

		/* check if special OpenVPN message */
		if (ovpn_is_keepalive(skb)) {
#if DEBUG_PING
			ovpn_dbg_ping_received(skb, ovpn, peer);
#endif
			/* openvpn keepalive - not an error */
			ret = 0;
		}

		goto drop;
	}

#if DEBUG_IN
	ovpn_dbg_kovpn_in(skb, peer);
#endif

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

	/* cause packet to be "received" by tun interface */
	netif_rx_ni(skb);
	return 0;

drop:
	if (ret < 0)
		kfree_skb(skb);
	else
		consume_skb(skb);
	return ret;
}

static int ovpn_transport_to_userspace(struct ovpn_struct *ovpn,
				       struct sk_buff *skb)
{
	int ret;

	ret = skb_linearize(skb);
	if (ret < 0)
		return ret;

	ret = ovpn_netlink_send_packet(ovpn, skb->data, skb->len);
	if (ret < 0)
		return ret;

	consume_skb(skb);
	return 0;
}

/* enqueue the packet and schedule RX consumer */
void ovpn_recv(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
	       struct sk_buff *skb)
{
	int ret;

	ret = ptr_ring_produce_bh(&peer->rx_ring, skb);
	if (ret < 0) {
		ovpn_peer_put(peer);
		return;
	}

	queue_work(ovpn->crypto_wq, &peer->decrypt_work);
}

static void ovpn_decrypt_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;
	int ret, key_id;
	u32 op;

	/* get opcode */
	op = ovpn_op32_from_skb(skb, NULL);

	/* save original packet size for stats accounting */
	OVPN_SKB_CB(skb)->rx_stats_size = skb->len;

	/* we only handle OVPN_DATA_Vx packets from known peers here.
	 *
	 * all other packets are sent to userspace via netlink
	 */
	if (unlikely(!ovpn_opcode_is_data(op))) {
		ret = ovpn_transport_to_userspace(peer->ovpn, skb);
		if (ret < 0)
			goto drop;
		return;
	}

	/* get the key slot matching the key Id in the received packet */
	key_id = ovpn_key_id_extract(op);
	ks = ovpn_crypto_key_id_to_slot(&peer->crypto, key_id);
	if (unlikely(!ks))
		goto drop;

	/* decrypt */
	ret = ks->ops->decrypt(ks, skb, op);
	if (unlikely(ret < 0)) {
		pr_err("error during decryption\n");
		goto drop;
	}

	/* successful decryption */
	ovpn_crypto_key_slot_put(ks);
	tun_netdev_write(peer, skb);
drop:
	if (unlikely(ret < 0))
		kfree_skb(skb);
}

/* pick packet from RX queue, decrypt and forward it to the tun device */
void ovpn_decrypt_work(struct work_struct *work)
{
	struct ovpn_peer *peer;
	struct sk_buff *skb;

	peer = container_of(work, struct ovpn_peer, decrypt_work);
	while ((skb = ptr_ring_consume_bh(&peer->rx_ring))) {
		ovpn_decrypt_one(peer, skb);
		ovpn_peer_put(peer);

		/* give a chance to be rescheduled if needed */
		if (need_resched())
			cond_resched();
	}
}

static void ovpn_encrypt_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;
	int ret;

	/* get primary key to be used for encrypting data */
	ks = ovpn_crypto_key_slot_primary(&peer->crypto);
	if (unlikely(!ks))
		goto drop;

	/* init packet ID to undef in case we err before setting real value */
	OVPN_SKB_CB(skb)->pktid = 0;

	/* encrypt */
	ret = ks->ops->encrypt(ks, skb);
	if (unlikely(ret < 0)) {
		pr_err("error during encryption\n");
		goto drop;
	}

	ovpn_crypto_key_slot_put(ks);
	/* successful encryption */
	ovpn_udp_send_skb(peer->ovpn, peer, skb);
drop:
	if (unlikely(ret < 0))
		kfree_skb(skb);

}

/* pick packet from TX queue, encrypt and send it to peer */
void ovpn_encrypt_work(struct work_struct *work)
{
	struct ovpn_peer *peer;
	struct sk_buff *skb;

	peer = container_of(work, struct ovpn_peer, encrypt_work);
	while ((skb = ptr_ring_consume_bh(&peer->tx_ring))) {
		ovpn_encrypt_one(peer, skb);
		ovpn_peer_put(peer);

		/* give a chance to be rescheduled if needed */
		if (need_resched())
			cond_resched();
	}
}

/* enqueue packet and schedule TX consumer
 *
 * On success, 0 is returned, skb ownership is transferred,
 * On error, a value < 0 is returned, the skb is not owned/released.
 */
static int ovpn_net_xmit_skb(struct ovpn_struct *ovpn, struct sk_buff *skb)
{
	struct ovpn_peer *peer;
	int ret;

	/* HW checksum offload is set, therefore attempt computing the checksum
	 * of the inner packet
	 */
	if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL &&
		     skb_checksum_help(skb)))
		return -EINVAL;

	peer = ovpn_peer_get(ovpn);
	if (unlikely(!peer))
		return -ENOLINK;

	ret = ptr_ring_produce_bh(&peer->tx_ring, skb);
	if (ret < 0) {
		ovpn_peer_put(peer);
		return ret;
	}

	queue_work(ovpn->crypto_wq, &peer->encrypt_work);

	return 0;
}

/* Net device start xmit
 */
netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ovpn_struct *ovpn = netdev_priv(dev);
	int ret;

	/* reset netfilter state */
	nf_reset_ct(skb);

	/* verify IP header size in network packet */
	ret = ovpn_ip_check_protocol(skb);
	if (unlikely(ret < 0)) {
		net_dbg_ratelimited("%s: dropping malformed payload packet\n",
				    dev->name);
		goto drop;
	}

	ret = ovpn_net_xmit_skb(ovpn, skb);
	if (unlikely(ret < 0))
		goto drop;

	return NETDEV_TX_OK;

drop:
	skb_tx_error(skb);
	kfree_skb(skb);
	return NET_XMIT_DROP;
}

/* Encrypt and transmit a special message to peer, such as keepalive
 * or explicit-exit-notify.  Called from softirq context.
 * Assumes that caller holds a reference to peer.
 */
void ovpn_xmit_special(struct ovpn_peer *peer, const void *data,
		       const unsigned int len)
{
	struct ovpn_struct *ovpn;
	struct sk_buff *skb;
	int err;

	ovpn = peer->ovpn;
	if (unlikely(!ovpn))
		return;

	skb = alloc_skb(256 + len, GFP_ATOMIC);
	if (unlikely(!skb))
		return;

	skb_reserve(skb, 128);
	skb->priority = TC_PRIO_BESTEFFORT;
	memcpy(__skb_put(skb, len), data, len);

	err = ovpn_net_xmit_skb(ovpn, skb);
	if (likely(err < 0))
		kfree_skb(skb);
}
