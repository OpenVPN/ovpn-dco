// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include "main.h"
#include "bind.h"
#include "ovpn.h"
#include "ovpnstruct.h"
#include "peer.h"
#include "proto.h"
#include "udp.h"

#include <net/route.h>
#include <net/ip6_route.h>
#include <net/udp_tunnel.h>

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
	struct rtable *rt;
	struct flowi4 fl = {
		.saddr = bind->sapair.local.u.in4.sin_addr.s_addr,
		.daddr = bind->sapair.remote.u.in4.sin_addr.s_addr,
		.fl4_sport = bind->sapair.local.u.in4.sin_port,
		.fl4_dport = bind->sapair.remote.u.in4.sin_port,
		.flowi4_proto = sk->sk_protocol,
		.flowi4_mark = sk->sk_mark,
		.flowi4_oif = sk->sk_bound_dev_if,
	};

	rt = ip_route_output_flow(sock_net(sk), &fl, sk);
	if (IS_ERR(rt)) {
		net_dbg_ratelimited("%s: no route to host %pISpc\n",
				    ovpn->dev->name,
				    &bind->sapair.remote.u.in4);
		return -EHOSTUNREACH;
	}

	udp_tunnel_xmit_skb(rt, sk, skb, fl.saddr, fl.daddr, 0,
			    ip4_dst_hoplimit(&rt->dst), 0, fl.fl4_sport,
			    fl.fl4_dport, false, sk->sk_no_check_tx);
	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int ovpn_udp6_output(struct ovpn_struct *ovpn, struct ovpn_bind *bind,
			    struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst;
	int ret;

	struct flowi6 fl = {
		.saddr = bind->sapair.local.u.in6.sin6_addr,
		.daddr = bind->sapair.remote.u.in6.sin6_addr,
		.fl6_sport = bind->sapair.local.u.in6.sin6_port,
		.fl6_dport = bind->sapair.remote.u.in6.sin6_port,
		.flowi6_proto = sk->sk_protocol,
		.flowi6_mark = sk->sk_mark,
		.flowi6_oif = sk->sk_bound_dev_if,
	};

	/* based on scope ID usage from net/ipv6/udp.c */
	if (bind->sapair.remote.u.in6.sin6_scope_id &&
	    __ipv6_addr_needs_scope_id(__ipv6_addr_type(&fl.daddr)))
		fl.flowi6_oif = bind->sapair.remote.u.in6.sin6_scope_id;

	dst = ip6_route_output(sock_net(sk), sk, &fl);
	if (unlikely(dst->error < 0)) {
		ret = dst->error;
		dst_release(dst);
		return ret;
	}

	udp_tunnel6_xmit_skb(dst, sk, skb, skb->dev, &fl.saddr, &fl.daddr, 0,
			     ip6_dst_hoplimit(dst), 0, fl.fl6_sport,
			     fl.fl6_dport, udp_get_no_check6_tx(sk));
	return 0;
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
		ret = -EAFNOSUPPORT;
		break;
	}

	return ret;
}

/* Called after encrypt to write IP packet to UDP port.
 * This method is expected to manage/free skb.
 */
void ovpn_udp_send_skb(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
		       struct sk_buff *skb)
{
	struct ovpn_bind *bind;
	struct socket *sock;
	int ret = -1;

	skb->dev = ovpn->dev;
	/* no checksum performed at this layer */
	skb->ip_summed = CHECKSUM_NONE;

	/* get socket info */
	sock = peer->sock;
	if (unlikely(!sock))
		goto out;

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

	ovpn_udp_send_skb(ovpn, peer, skb);
out:
	ovpn_peer_put(peer);
	return ret;
}
