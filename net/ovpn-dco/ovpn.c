/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

#include "main.h"
#include "debug.h"
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

/*
 * Called after decrypt to write IP packet to tun netdev.
 * This method is expected to manage/free skb.
 */
static int tun_netdev_write(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
			    struct sk_buff *skb)
{
	unsigned int rx_stats_size;
	int ret;

	rcu_read_lock();

	/* check if we should record peer addr,
	   so we know where to send return packets */
	//if (unlikely(ovpn_bind_test_peer(&peer->bind, skb))) {
	//	ovpn_bind_record_peer(ovpn, peer, skb, &peer->lock);
	//	rcu_read_lock();
	//}

	/* note event of authenticated packet received for keepalive */
	ovpn_peer_update_keepalive_expire(peer);

	/* increment RX stats */
	rx_stats_size = OVPN_SKB_CB(skb)->rx_stats_size;
	ovpn_increment_rx_stats(ovpn, rx_stats_size);
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

	/* post-decrypt scrub -- prepare to inject encapsulated packet onto tun interface,
	   based on __skb_tunnel_rx() in dst.h */
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
		goto error;
	}

	/* successful decryption */
	tun_netdev_write(ovpn, peer, skb);

	ovpn_crypto_context_put(cc);
	return;

error:
	ovpn_crypto_context_put(cc);
	kfree_skb(skb);
}

static void post_decrypt_callback(struct sk_buff *skb, int err)
{
	struct ovpn_work *work;
	struct ovpn_struct *ovpn;
	struct ovpn_peer *peer;
	struct ovpn_crypto_context *cc;

	work = OVPN_SKB_CB(skb)->work;
	cc = work->cc;
	peer = cc->peer;
	ovpn = rcu_dereference_protected(peer->ovpn, true);

	post_decrypt(ovpn, peer, cc, skb, err, work);
}

/*
 * Lookup ovpn_peer using incoming encrypted transport packet.
 * This is for looking up transport -> ovpn packets.
 */
static struct ovpn_peer *
ovpn_lookup_peer_via_transport(struct ovpn_struct *ovpn,
			       struct sk_buff *skb)
{
	/* only one peer is supported at the moment. check if it's the one the
	 * skb was received from and return it
	 */
	if (!ovpn_bind_skb_match(rcu_dereference(ovpn->peer->bind.ob), skb))
		return NULL;

	return ovpn->peer;
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

/*
 * Receive an encrypted packet from transport (UDP or TCP).
 * Should be called with rcu_read_lock held, but will be released
 * before return.  Takes ownership of skb.
 */
static void ovpn_recv_crypto(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
			     const unsigned int op, struct sk_buff *skb)
{
	struct ovpn_crypto_context *cc;
	int key_id;
	int ret;

	ovpn_rcu_lockdep_assert_held();

	/* save original packet size for stats accounting */
	OVPN_SKB_CB(skb)->rx_stats_size = skb->len;

	/* we only handle OVPN_DATA_Vx packets from known peers here --
	   all other packets are sent to userspace via the tun dev
	   and are prepended with an ovpn_tun_head and possibly a
	   ovpn_sockaddr_pair as well */
	if (unlikely(!peer || !ovpn_opcode_is_data(op))) {
		ret = ovpn_transport_to_userspace(ovpn, peer, skb);
		if (unlikely(ret < 0))
			goto drop;
		return;
	}

	/* get the crypto context */
	key_id = ovpn_key_id_extract(op);
	cc = ovpn_crypto_context_from_state(&peer->crypto, key_id);
	if (unlikely(!cc))
		goto drop;

	/* we need to increment crypto context refcount in case we go async in crypto API */
	if (unlikely(!ovpn_crypto_context_hold(cc)))
		goto drop;

	rcu_read_unlock();

	/* decrypt */
	ret = cc->ops->decrypt(cc, skb, key_id, op, post_decrypt_callback);
	if (likely(ret != -EINPROGRESS))
		post_decrypt(ovpn, peer, cc, skb, ret, OVPN_SKB_CB(skb)->work);

	return;

drop:
	rcu_read_unlock();
	kfree_skb(skb);
}

/*
 * Dispatch received transport packet (UDP or TCP)
 * to the appropriate handler (crypto or relay).
 * Should be called with rcu_read_lock held, but will be released
 * before return.  Takes ownership of skb.
 */
static void ovpn_recv(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
		      const unsigned int op, struct sk_buff *skb)
{
	ovpn_recv_crypto(ovpn, peer, op, skb);
}

/*
 * UDP encapsulation receive handler.  See net/ipv[46]/udp.c.
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

	/* need to ensure accurate L4 hash for packets assembled from IP fragments */
	skb_clear_hash_if_not_l4(skb);

	/* pre-decrypt scrub */
	/* TODO */

	/* pop off outer UDP header */
	__skb_pull(skb, sizeof(struct udphdr));

	rcu_read_lock();
	ovpn = ovpn_from_udp_sock(sk);
	if (!ovpn)
		goto drop;

	/* get opcode */
	op = ovpn_op32_from_skb(skb, NULL);

	/* lookup peer */
	peer = ovpn_lookup_peer_via_transport(ovpn, skb);
	if (!peer)
		goto drop;

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
	int ret;

	rt = ip_route_output_ports(sock_net(sk), &inet->cork.fl.u.ip4,
				   sk, bind->sapair.remote.u.in4.sin_addr.s_addr,
				   bind->sapair.local.u.in4.sin_addr.s_addr,
				   bind->sapair.remote.u.in4.sin_port,
				   bind->sapair.local.u.in4.sin_port,
				   sk->sk_protocol, RT_CONN_FLAGS(sk),
				   sk->sk_bound_dev_if);
	if (unlikely(IS_ERR(rt)))
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
		ret = -OVPN_ERR_SKB_NOT_ENOUGH_HEADROOM;
		goto rel_rt;
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

	rcu_read_unlock();
	/*
	 * Transmit IPv4 UDP packet using ip_local_out which
	 * will set iph->tot_len and iph->check.
	 */
	ip_local_out(dev_net(ovpn->dev), sk, skb);
	return 0;
rel_rt:
	ip_rt_put(rt);
	return ret;
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

	rcu_read_unlock();

	/*
	 * Transmit IPv6 UDP packet using ip6_local_out.
	 * which will set ip6->payload_len.
	 */
        ip6_local_out(dev_net(ovpn->dev), sk, skb);
	return 0;
rel_dst:
	dst_release(dst);
	return ret;
}
#endif

/*
 * Prepend UDP transport and IP headers to skb (using
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
		ret = -ENOTSUPP;
		break;
	}

	return ret;
}

/*
 * Called after encrypt to write IP packet to UDP port.
 * This method is expected to manage/free skb.
 */
static void ovpn_udp_write(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
			   struct sk_buff *skb)
{
	struct socket *sock;
	struct ovpn_bind *bind;
	int ret;

	rcu_read_lock();

	/* get socket info */
	sock = rcu_dereference(peer->sock);
	if (unlikely(!sock)) {
		ret = -OVPN_ERR_NO_TRANSPORT_SOCK;
		goto out;
	}

	/* post-encrypt -- scrub packet prior to encapsulation in a UDP packet */
	ovpn_skb_scrub(skb);

	/* get binding */
	bind = rcu_dereference(peer->bind.ob);
	if (unlikely(!bind)) {
		ret = -OVPN_ERR_NO_PEER_BINDING;
		goto out;
	}

	/* note event of authenticated packet xmit for keepalive */
	ovpn_peer_update_keepalive_xmit(peer);

	/* crypto layer -> transport (UDP) */
	ret = ovpn_udp_output(ovpn, bind, sock->sk, skb);

out:
	/* in case of success, all cleanup has been performed by the
	 * ovpn_udp_output() function
	 */
	if (!ret)
		return;

	rcu_read_unlock();
	kfree_skb(skb);
}

static void post_encrypt(struct ovpn_struct *ovpn,
			 struct ovpn_peer *peer, struct ovpn_crypto_context *cc,
			 struct sk_buff *skb, int err, struct ovpn_work *work)
{
	/* free workspace */
	kfree(work);

	/* test encrypt status */
	if (unlikely(err))
		goto error;

	/* successful encryption */
	ovpn_udp_write(ovpn, peer, skb);

done:
	/* release our reference to crypto context */
	ovpn_crypto_context_put(cc);
	return;

error:
	kfree_skb(skb);
	goto done;
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

/*
 * rcu_read_lock must be held on entry.
 * On success, 0 is returned, skb ownership is transferred,
 * and rcu_read lock is released.  On error, a value < 0 is returned,
 * the skb is not owned/released, and rcu_read_lock is not released.
 */
static int do_ovpn_net_xmit(struct ovpn_struct *ovpn, struct sk_buff *skb,
			    const bool is_ip_packet)
{
	struct ovpn_peer *peer = rcu_dereference(ovpn->peer);
	unsigned int headroom;
	struct ovpn_crypto_context *cc;
	int key_id;
	int ret;

	/* set minimum encapsulation headroom for encrypt */
	headroom = ovpn_bind_udp_encap_overhead(&peer->bind, ETH_HLEN);
	if (unlikely(headroom < 0))
		goto drop;

	/* get crypto context */
	cc = ovpn_crypto_context_primary(&peer->crypto, &key_id);
	if (unlikely(!cc)) {
		ret = -OVPN_ERR_NO_PRIMARY_KEY;
		goto drop;
	}

	/* we need to increment crypto context refcount in case we go async in crypto API */
	if (unlikely(!ovpn_crypto_context_hold(cc))) {
		ret = -OVPN_ERR_CANNOT_GRAB_CRYPTO_REF;
		goto drop;
	}

	/* init packet ID to undef in case we err before setting real value */
	OVPN_SKB_CB(skb)->pktid = 0;

	/* encrypt */
	ret = cc->ops->encrypt(cc, skb, headroom, key_id,
			       post_encrypt_callback);
	if (likely(ret != -EINPROGRESS))
		post_encrypt(ovpn, ovpn->peer, cc, skb, ret,
			     OVPN_SKB_CB(skb)->work);

	return 0;

drop:
	return ret;

}

/*
 * Net device start xmit
 */
netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ovpn_struct *ovpn = netdev_priv(dev);
	int ret;

	rcu_read_lock();

	/* reset netfilter state */
	nf_reset_ct(skb);
	/* pop MAC header if it exists - AQ: should not */
	//skb_pop_mac_header(skb);
	ovpn_debug(KERN_INFO,
		   "ovpn_net_xmit: mac_header_was_set=%d mac_header_len=%u",
		   skb_mac_header_was_set(skb), skb_mac_header_len(skb));

	/* verify IP header size in network packet */
	ret = ovpn_ip_header_probe(skb, 0);
	if (unlikely(ret < 0))
		goto drop;

	skb_reset_network_header(skb);

	ret = do_ovpn_net_xmit(ovpn, skb, true);
	if (unlikely(ret < 0))
		goto drop;

	rcu_read_unlock();

	return NETDEV_TX_OK;

drop:
	skb_tx_error(skb);
	kfree_skb(skb);
	rcu_read_unlock();
	return NET_XMIT_DROP;
}

/*
 * Encrypt and transmit a special message to peer, such as keepalive
 * or explicit-exit-notify.  Called from softirq context.
 * Assumes that caller holds a reference to peer.
 */
 void ovpn_xmit_special(struct ovpn_peer *peer, const void *data,
			const unsigned int len)
{
	struct ovpn_struct *ovpn;
	struct sk_buff *skb;
	int err;

	rcu_read_lock();

	ovpn = peer->ovpn;
	if (unlikely(!ovpn)) {
		err = -OVPN_ERR_NO_OVPN_CONTEXT;
		goto unlock;
	}

	skb = alloc_skb(256 + len, GFP_ATOMIC);
	if (unlikely(!skb)) {
		err = -ENOMEM;
		goto unlock;
	}
	skb_reserve(skb, 128);
	skb->priority = TC_PRIO_BESTEFFORT;
	memcpy(__skb_put(skb, len), data, len);

	err = do_ovpn_net_xmit(ovpn, skb, false);
	if (likely(err < 0))
		goto free_skb;

	rcu_read_unlock();

	return;
free_skb:
	kfree_skb(skb);
unlock:
	rcu_read_unlock();
	return;
}
