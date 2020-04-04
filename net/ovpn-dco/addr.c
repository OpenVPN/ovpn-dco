/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

/*
 * Random secret to be used in hash computations to prevent
 * hash collision attacks.
 */

#include "main.h"
#include "addr.h"

#include <linux/once.h> // for get_random_once()
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <net/ipv6.h>
#include <net/ip.h>

__u32 ovpn_hashrnd __read_mostly;

void ovpn_hash_secret_init(void)
{
	get_random_once(&ovpn_hashrnd, sizeof(ovpn_hashrnd));
}

/*
 * Construct an ovpn_sockaddr_pair object from src/dest addr/port
 * addresses in an skb.
 */
int ovpn_sockaddr_pair_from_skb(struct ovpn_sockaddr_pair *sapair,
				struct sk_buff *skb)
{
	memset(sapair, 0, sizeof(*sapair));
	switch (skb->protocol) {
	case htons(ETH_P_IP):
	{
		if (unlikely(ip_hdr(skb)->protocol != IPPROTO_UDP))
			return -OVPN_ERR_ADDR4_MUST_BE_UDP;

		sapair->skb_hash = skb_get_hash(skb);
		sapair->skb_hash_defined = true;
		sapair->local.family = AF_INET;
		sapair->local.u.in4.sin_addr.s_addr = ip_hdr(skb)->daddr;
		sapair->local.u.in4.sin_port = udp_hdr(skb)->dest;
		sapair->remote.family = AF_INET;
		sapair->remote.u.in4.sin_addr.s_addr = ip_hdr(skb)->saddr;
		sapair->remote.u.in4.sin_port = udp_hdr(skb)->source;

		if (unlikely(!sapair->local.u.in4.sin_addr.s_addr &&
			     !sapair->local.u.in4.sin_port &&
			     !sapair->remote.u.in4.sin_addr.s_addr &&
			     !sapair->remote.u.in4.sin_port))
			return -OVPN_ERR_ADDR4_ZERO;

		return 0;
	}
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
		if (unlikely(ipv6_hdr(skb)->nexthdr != IPPROTO_UDP))
			return -OVPN_ERR_ADDR6_MUST_BE_UDP;

		sapair->skb_hash = skb_get_hash(skb);
		sapair->skb_hash_defined = true;
		sapair->local.family = AF_INET6;
		sapair->local.u.in6.sin6_addr = ipv6_hdr(skb)->daddr;
		sapair->local.u.in6.sin6_port = udp_hdr(skb)->dest;
		sapair->remote.family = AF_INET6;
		sapair->remote.u.in6.sin6_addr = ipv6_hdr(skb)->saddr;
		sapair->remote.u.in6.sin6_port = udp_hdr(skb)->source;
		sapair->remote.u.in6.sin6_flowinfo = ip6_flowinfo(ipv6_hdr(skb));

		return 0;
#endif
	}
	return -OVPN_ERR_IPVER_NOTIMP;
}

/*
 * Construct an ovpn_sockaddr_pair object from src/dest addr/port
 * addresses in a connected TCP/UDP socket.
 * For non-connected sockets, only touch sapair->local.
 * sapair is guaranteed not to be modified on error returns < 0.
 */
int ovpn_sockaddr_pair_from_sock(struct ovpn_sockaddr_pair *sapair,
				 struct sock *sk,
				 const bool tcp)
{
	struct inet_sock *inet;

	/* verify socket type */
	if (tcp) {
		if (!sk || sk->sk_protocol != IPPROTO_TCP)
			return -OVPN_ERR_SOCK_MUST_BE_TCP;
	} else {
		if (!sk || sk->sk_protocol != IPPROTO_UDP)
			return -OVPN_ERR_SOCK_MUST_BE_UDP;
	}

	inet = inet_sk(sk);

	switch (sk->sk_family)
	{
	case PF_INET:
	{
		sapair->local.family = AF_INET;
		sapair->local.u.in4.sin_addr.s_addr = inet->inet_saddr;
		sapair->local.u.in4.sin_port = inet->inet_sport;
		sapair->skb_hash = 0;
		sapair->skb_hash_defined = false;
		return 0;
	}
#if IS_ENABLED(CONFIG_IPV6)
	case PF_INET6:
	{
		/* loosely modeled on inet6_getname */
		sapair->local.family = AF_INET6;
		if (ipv6_addr_any(&sk->sk_v6_rcv_saddr))
			sapair->local.u.in6.sin6_addr = inet6_sk(sk)->saddr;
		else
			sapair->local.u.in6.sin6_addr = sk->sk_v6_rcv_saddr;
		sapair->local.u.in6.sin6_port = inet->inet_sport;

		sapair->skb_hash = 0;
		sapair->skb_hash_defined = false;
		return 0;
	}
#endif
	default:
		return -OVPN_ERR_IPVER_NOTIMP;
	}
}
