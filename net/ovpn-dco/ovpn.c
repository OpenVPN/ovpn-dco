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

#include <net/route.h>
#include <net/ip6_route.h>
#include <net/ip6_checksum.h>
#include <net/udp.h>
#include <uapi/linux/if_ether.h>

int ovpn_struct_init(struct net_device *dev)
{
	struct ovpn_struct *ovpn = netdev_priv(dev);
	int err;

	ovpn->dev = dev;
	ovpn->omit_csum = true;

	err = ovpn_netlink_init(ovpn);
	if (err < 0)
		return err;

	spin_lock_init(&ovpn->lock);
	RCU_INIT_POINTER(ovpn->peer, NULL);

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
static int tun_netdev_write(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
			    struct sk_buff *skb)
{
	unsigned int rx_stats_size;
	int ret;

	rcu_read_lock();

	/* note event of authenticated packet received for keepalive */
	ovpn_peer_update_keepalive_expire(peer);

	/* increment RX stats */
	rx_stats_size = OVPN_SKB_CB(skb)->rx_stats_size;
	ovpn_peer_stats_increment_rx(peer, rx_stats_size);

	/* verify IP header size, set skb->protocol,
	 * set skb network header, and possibly stash shim
	 */
	ret = ovpn_ip_header_probe(skb, OVPN_PROBE_SET_SKB);
	if (unlikely(ret < 0)) {
		/* check if null packet */
		if (unlikely(!pskb_may_pull(skb, 1))) {
			ret = -OVPN_ERR_NULL_IP_PKT;
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

	/* omit_csum tells us to neither calculate nor verify the checksum */
	if (ovpn->omit_csum) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->csum_level = 3;
	} else {
		skb->ip_summed = CHECKSUM_NONE;
	}

	/* skb hash for transport packet no longer valid after decapsulation */
	skb_clear_hash(skb);

	/* post-decrypt scrub -- prepare to inject encapsulated packet onto tun
	 * interface, based on __skb_tunnel_rx() in dst.h
	 */
	skb->dev = ovpn->dev;
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, true);

	/* set transport header */
	skb->transport_header = 0;
	skb_probe_transport_header(skb);

	rcu_read_unlock();

	/* cause packet to be "received" by tun interface */
	netif_rx(skb);
	return 0;

drop:
	if (ret < 0)
		kfree_skb(skb);
	else
		consume_skb(skb);
	rcu_read_unlock();
	return ret;
}

static void post_decrypt(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
			 struct ovpn_crypto_context *cc, struct sk_buff *skb,
			 int err, struct ovpn_work *work)
{
	/* free workspace */
	kfree(work);

	/* test decrypt status */
	if (unlikely(err)) {
		/* decryption failed */
		kfree_skb(skb);
		goto error;
	}

	/* successful decryption */
	tun_netdev_write(ovpn, peer, skb);

error:
	ovpn_crypto_context_put(cc);
	ovpn_peer_put(peer);
}

static void post_decrypt_callback(struct sk_buff *skb, int err)
{
	struct ovpn_work *work = OVPN_SKB_CB(skb)->work;

	post_decrypt(work->cc->peer->ovpn, work->cc->peer, work->cc, skb, err,
		     work);
}

/* Lookup ovpn_peer using incoming encrypted transport packet.
 * This is for looking up transport -> ovpn packets.
 */
static struct ovpn_peer *
ovpn_lookup_peer_via_transport(struct ovpn_struct *ovpn,
			       struct sk_buff *skb)
{
	struct ovpn_peer *peer;
	struct ovpn_bind *bind;

	rcu_read_lock();
	peer = ovpn_peer_get(ovpn);
	if (!peer)
		goto err;

	bind = rcu_dereference(peer->bind);
	if (!bind)
		goto err;

	/* only one peer is supported at the moment. check if it's the one the
	 * skb was received from and return it
	 */
	if (!ovpn_bind_skb_match(bind, skb))
		goto err;

	rcu_read_unlock();
	return peer;

err:
	ovpn_peer_put(peer);
	rcu_read_unlock();
	return NULL;
}

static int ovpn_transport_to_userspace(struct ovpn_struct *ovpn,
				       struct ovpn_peer *peer,
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

/* Receive an encrypted packet from transport (UDP or TCP).
 * Should be called with rcu_read_lock held, but will be released
 * before return.  Takes ownership of skb.
 */
static void ovpn_recv_crypto(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
			     const unsigned int op, struct sk_buff *skb)
{
	struct ovpn_crypto_context *cc;
	int key_id;
	int ret;

	/* save original packet size for stats accounting */
	OVPN_SKB_CB(skb)->rx_stats_size = skb->len;

	/* we only handle OVPN_DATA_Vx packets from known peers here --
	 * all other packets are sent to userspace via the tun dev
	 * and are prepended with an ovpn_tun_head and possibly a
	 * ovpn_sockaddr_pair as well
	 */
	if (unlikely(!peer || !ovpn_opcode_is_data(op))) {
		ret = ovpn_transport_to_userspace(ovpn, peer, skb);
		if (peer)
			ovpn_peer_put(peer);
		if (ret < 0)
			goto drop;
		return;
	}

	/* get the crypto context */
	key_id = ovpn_key_id_extract(op);
	cc = ovpn_crypto_context_from_state(&peer->crypto, key_id);
	if (unlikely(!cc))
		goto drop;

	/* decrypt */
	ret = cc->ops->decrypt(cc, skb, key_id, op, post_decrypt_callback);
	if (likely(ret != -EINPROGRESS))
		post_decrypt(ovpn, peer, cc, skb, ret, OVPN_SKB_CB(skb)->work);

	return;

drop:
	kfree_skb(skb);
}

/* Dispatch received transport packet (UDP or TCP)
 * to the appropriate handler (crypto or relay).
 * Should be called with rcu_read_lock held, but will be released
 * before return.  Takes ownership of skb.
 */
static void ovpn_recv(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
		      const unsigned int op, struct sk_buff *skb)
{
	ovpn_recv_crypto(ovpn, peer, op, skb);
}

/* UDP encapsulation receive handler.  See net/ipv[46]/udp.c.
 * Here we look at an incoming OpenVPN UDP packet.  If we are able
 * to process it, we will send it directly to tun interface.
 * Otherwise, send it up to userspace.
 * Called in softirq context.
 *
 * Return codes:
 *  0 : we consumed or dropped packet
 * >0 : skb should be passed up to userspace as UDP (packet not consumed)
 * <0 : skb should be resubmitted as proto -N (packet not consumed)
 */
int ovpn_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct ovpn_struct *ovpn;
	struct ovpn_peer *peer;
	unsigned int op;

	/* ensure accurate L4 hash for packets assembled from IP fragments */
	skb_clear_hash_if_not_l4(skb);

	/* pre-decrypt scrub */
	/* TODO */

	/* pop off outer UDP header */
	__skb_pull(skb, sizeof(struct udphdr));

	ovpn = ovpn_from_udp_sock(sk);
	if (!ovpn)
		goto drop;

	/* get opcode */
	op = ovpn_op32_from_skb(skb, NULL);

	/* lookup peer */
	peer = ovpn_lookup_peer_via_transport(ovpn, skb);

	ovpn_recv(ovpn, peer, op, skb);
	return 0;

drop:
	kfree_skb(skb);
	return 0;
}

static int ovpn_udp4_output(struct ovpn_struct *ovpn, struct ovpn_bind *bind,
			    struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udphdr *uh;
	struct rtable *rt;
	struct iphdr *iph;

	rt = ip_route_output_ports(sock_net(sk), &inet->cork.fl.u.ip4, sk,
				   bind->sapair.remote.u.in4.sin_addr.s_addr,
				   bind->sapair.local.u.in4.sin_addr.s_addr,
				   bind->sapair.remote.u.in4.sin_port,
				   bind->sapair.local.u.in4.sin_port,
				   sk->sk_protocol, RT_CONN_FLAGS(sk),
				   sk->sk_bound_dev_if);
	if (IS_ERR(rt))
		return -OVPN_ERR_ADDR4_BIND;

	/* set dst from binding */
	skb_dst_set(skb, &rt->dst);

	uh = udp_hdr(skb);

	/* UDP header */
	uh->source = bind->sapair.local.u.in4.sin_port;
	uh->dest = bind->sapair.remote.u.in4.sin_port;
	uh->len = htons(skb->len);

	/* UDP checksum */
	skb->ip_summed = CHECKSUM_NONE;
	udp_set_csum(sk->sk_no_check_tx, skb,
		     bind->sapair.local.u.in4.sin_addr.s_addr,
		     bind->sapair.remote.u.in4.sin_addr.s_addr,
		     skb->len);

	/* setup IPv4 header */
	if (unlikely(skb_headroom(skb)
		     < sizeof(struct iphdr) + sizeof(struct ethhdr))) {
		ip_rt_put(rt);
		return -OVPN_ERR_SKB_NOT_ENOUGH_HEADROOM;
	}

	__skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->tos = 0;
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = bind->sapair.local.u.in4.sin_addr.s_addr;
	iph->daddr = bind->sapair.remote.u.in4.sin_addr.s_addr;

	/* Transmit IPv4 UDP packet using ip_local_out which
	 * will set iph->tot_len and iph->check.
	 */
	ip_local_out(dev_net(ovpn->dev), sk, skb);
	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int ovpn_udp6_output(struct ovpn_struct *ovpn, struct ovpn_bind *bind,
			    struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst;
	struct ipv6hdr *ip6;
	struct udphdr *uh;
	int ret;

	struct flowi6 fl6 = {
		.flowi6_proto = sk->sk_protocol,
		.daddr = bind->sapair.remote.u.in6.sin6_addr,
		.saddr = bind->sapair.local.u.in6.sin6_addr,
		.fl6_dport = bind->sapair.remote.u.in6.sin6_port,
		.fl6_sport = bind->sapair.local.u.in6.sin6_port,
		.flowi6_mark = sk->sk_mark,
		.flowi6_oif = sk->sk_bound_dev_if,
	};

	/* based on scope ID usage from net/ipv6/udp.c */
	if (bind->sapair.remote.u.in6.sin6_scope_id &&
	    __ipv6_addr_needs_scope_id(__ipv6_addr_type(&fl6.daddr)))
		fl6.flowi6_oif = bind->sapair.remote.u.in6.sin6_scope_id;

	dst = ip6_route_output(sock_net(sk), sk, &fl6);
	if (unlikely(dst->error < 0)) {
		ret = -OVPN_ERR_ADDR6_BIND;
		goto rel_dst;
	}

	/* set dst from binding */
	skb_dst_set(skb, dst);

	uh = udp_hdr(skb);

	/* UDP header */
	uh->source = bind->sapair.local.u.in6.sin6_port;
	uh->dest = bind->sapair.remote.u.in6.sin6_port;
	uh->len = htons(skb->len);

	/* UDP checksum */
	skb->ip_summed = CHECKSUM_NONE;
	udp6_set_csum(udp_get_no_check6_tx(sk), skb,
		      &bind->sapair.local.u.in6.sin6_addr,
		      &bind->sapair.remote.u.in6.sin6_addr,
		      skb->len);

	/* setup IPv6 header */
	if (unlikely(skb_headroom(skb)
		     < sizeof(struct ipv6hdr) + sizeof(struct ethhdr))) {
		ret = -OVPN_ERR_SKB_NOT_ENOUGH_HEADROOM;
		goto rel_dst;
	}
	__skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);

	ip6 = ipv6_hdr(skb);
	ip6->version = 6;
	ip6->priority = 0;
	memset(ip6->flow_lbl, 0, sizeof(ip6->flow_lbl));
	ip6->nexthdr = IPPROTO_UDP;
	ip6->hop_limit = 64;
	ip6->saddr = bind->sapair.local.u.in6.sin6_addr;
	ip6->daddr = bind->sapair.remote.u.in6.sin6_addr;

	/* Transmit IPv6 UDP packet using ip6_local_out.
	 * which will set ip6->payload_len.
	 */
	ip6_local_out(dev_net(ovpn->dev), sk, skb);
	return 0;
rel_dst:
	dst_release(dst);
	return ret;
}
#endif

/* Prepend UDP transport and IP headers to skb (using
 * address/ports from binding) and transmit the packet
 * using ip_local_out.
 *
 * rcu_read_lock should be held on entry.
 * On return, the skb is consumed and rcu_read_lock
 * is released, even on error return.
 */
static int ovpn_udp_output(struct ovpn_struct *ovpn, struct ovpn_bind *bind,
			   struct sock *sk, struct sk_buff *skb)
{
	int ret;

	ovpn_rcu_lockdep_assert_held();

	/* set sk to null if skb is already orphaned */
	if (!skb->destructor)
		skb->sk = NULL;

	/* grab headroom for UDP header */
	if (unlikely(skb_headroom(skb) < sizeof(struct udphdr)))
		return -OVPN_ERR_SKB_NOT_ENOUGH_HEADROOM;

	__skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);

	switch (bind->sapair.local.family) {
	case AF_INET:
		ret = ovpn_udp4_output(ovpn, bind, sk, skb);
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		ret = ovpn_udp6_output(ovpn, bind, sk, skb);
		break;
#endif
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

/* Called after encrypt to write IP packet to UDP port.
 * This method is expected to manage/free skb.
 */
static void ovpn_udp_write(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
			   struct sk_buff *skb)
{
	struct ovpn_bind *bind;
	struct socket *sock;
	int ret = -1;

	/* get socket info */
	sock = peer->sock;
	if (unlikely(!sock))
		goto out;

	/* post-encrypt -- scrub packet prior to UDP encapsulation */
	ovpn_skb_scrub(skb);

	rcu_read_lock();
	/* get binding */
	bind = rcu_dereference(peer->bind);
	if (unlikely(!bind))
		goto out_unlock;

	/* note event of authenticated packet xmit for keepalive */
	ovpn_peer_update_keepalive_xmit(peer);

	/* crypto layer -> transport (UDP) */
	ret = ovpn_udp_output(ovpn, bind, sock->sk, skb);

out_unlock:
	rcu_read_unlock();
out:
	if (ret < 0)
		kfree_skb(skb);
}

#define SKB_HEADER_LEN                                       \
	(max(sizeof(struct iphdr), sizeof(struct ipv6hdr)) + \
	 sizeof(struct udphdr) + NET_SKB_PAD)

int ovpn_udp_send_data(struct ovpn_struct *ovpn, const u8 *data, size_t len)
{
	struct ovpn_peer *peer;
	struct sk_buff *skb;
	int ret = 0;

	peer = ovpn_peer_get(ovpn);
	if (!peer) {
		pr_debug("no peer to send data to\n");
		return -EHOSTUNREACH;
	}

	skb = alloc_skb(SKB_HEADER_LEN + len, GFP_ATOMIC);
	if (unlikely(!skb)) {
		ret = -ENOMEM;
		goto out;
	}

	skb_reserve(skb, SKB_HEADER_LEN);
	skb_put_data(skb, data, len);

	ovpn_udp_write(ovpn, peer, skb);
out:
	ovpn_peer_put(peer);
	return ret;
}

static void post_encrypt(struct ovpn_struct *ovpn,
			 struct ovpn_peer *peer, struct ovpn_crypto_context *cc,
			 struct sk_buff *skb, int err, struct ovpn_work *work)
{
	/* free workspace */
	kfree(work);

	/* test encrypt status */
	if (unlikely(err)) {
		kfree_skb(skb);
		goto error;
	}

	/* successful encryption */
	ovpn_udp_write(ovpn, peer, skb);

error:
	/* release our reference to crypto context */
	ovpn_crypto_context_put(cc);
	ovpn_peer_put(peer);
}

static void post_encrypt_callback(struct sk_buff *skb, int err)
{
	struct ovpn_crypto_context *cc;
	struct ovpn_struct *ovpn;
	struct ovpn_work *work;
	struct ovpn_peer *peer;

	work = OVPN_SKB_CB(skb)->work;
	cc = work->cc;
	peer = cc->peer;

	ovpn = peer->ovpn;

	post_encrypt(ovpn, peer, cc, skb, err, work);
}

/* rcu_read_lock must be held on entry.
 * On success, 0 is returned, skb ownership is transferred,
 * On error, a value < 0 is returned, the skb is not owned/released.
 */
static int do_ovpn_net_xmit(struct ovpn_struct *ovpn, struct sk_buff *skb,
			    const bool is_ip_packet)
{
	struct ovpn_crypto_context *cc;
	struct ovpn_peer *peer;
	struct ovpn_bind *bind;
	unsigned int headroom;
	int key_id;
	int ret = -1;

	peer = ovpn_peer_get(ovpn);
	if (unlikely(!peer))
		return -ENOLINK;

	rcu_read_lock();
	bind = rcu_dereference(peer->bind);
	if (unlikely(!bind)) {
		ret = -ENOENT;
		goto drop;
	}

	/* set minimum encapsulation headroom for encrypt */
	headroom = ovpn_bind_udp_encap_overhead(bind, ETH_HLEN);
	if (unlikely(headroom < 0))
		goto drop;

	/* get crypto context */
	cc = ovpn_crypto_context_primary(&peer->crypto, &key_id);
	if (unlikely(!cc)) {
		ret = -ENODEV;
		goto drop;
	}
	rcu_read_unlock();

	/* init packet ID to undef in case we err before setting real value */
	OVPN_SKB_CB(skb)->pktid = 0;

	/* encrypt */
	ret = cc->ops->encrypt(cc, skb, headroom, key_id,
			       post_encrypt_callback);
	if (likely(ret != -EINPROGRESS))
		post_encrypt(ovpn, peer, cc, skb, ret,
			     OVPN_SKB_CB(skb)->work);

	return 0;

drop:
	rcu_read_unlock();
	ovpn_peer_put(peer);
	return ret;
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
	ret = ovpn_ip_header_probe(skb, 0);
	if (unlikely(ret < 0))
		goto drop;

	skb_reset_network_header(skb);

	ret = do_ovpn_net_xmit(ovpn, skb, true);
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

	err = do_ovpn_net_xmit(ovpn, skb, false);
	if (likely(err < 0))
		kfree_skb(skb);
}
