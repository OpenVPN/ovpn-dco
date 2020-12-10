/* SPDX-License-Identifier: GPL-2.0-only */
/*  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNADDR_H_
#define _NET_OVPN_DCO_OVPNADDR_H_

#include "crypto.h"

#include <linux/jhash.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/ipv6.h>

/* our basic transport layer address */
struct ovpn_sockaddr {
	unsigned short int family;
	union {
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	} u;
};

/* our basic association between remote and local address */
struct ovpn_sockaddr_pair {
	bool skb_hash_defined; /* true if skb_hash is defined */
	u32 skb_hash; /* skb hash (L4) */
	struct ovpn_sockaddr local; /* local ingress address */
	struct ovpn_sockaddr remote; /* peer source address */
};

/* mask out the non-prefix bits in an IPv4 address */
static inline __be32 ovpn_ipv4_network_addr(const __be32 addr,
					    const unsigned int prefix_len)
{
	if (!prefix_len)
		return 0;

	return addr & htonl(~((1 << (32 - prefix_len)) - 1));
}

/* Compare two ovpn_sockaddr_pair objects for equality,
 * considering family, addr, and port.
 * Note: we assume that the local/remote family values
 * within the same ovpn_sockaddr_pair are equal
 * (use ovpn_sockaddr_pair_validate below to validate this).
 */
static inline bool ovpn_sockaddr_pair_eq(const struct ovpn_sockaddr_pair *p1,
					 const struct ovpn_sockaddr_pair *p2)
{
	if (p1->skb_hash_defined != p2->skb_hash_defined)
		return false;

	if (p1->skb_hash_defined && p1->skb_hash != p2->skb_hash)
		return false;

	if (p1->local.family != p2->local.family)
		return false;

	switch (p1->local.family) {
	case AF_INET:
		if (p1->local.u.in4.sin_addr.s_addr !=
		    p2->local.u.in4.sin_addr.s_addr)
			return false;

		if (p1->local.u.in4.sin_port != p2->local.u.in4.sin_port)
			return false;

		if (p1->remote.u.in4.sin_addr.s_addr !=
		    p2->remote.u.in4.sin_addr.s_addr)
			return false;

		if (p1->remote.u.in4.sin_port != p2->remote.u.in4.sin_port)
			return false;
		break;
	case AF_INET6:
		if (!ipv6_addr_equal(&p1->local.u.in6.sin6_addr,
				     &p2->local.u.in6.sin6_addr))
			return false;

		if (p1->local.u.in6.sin6_port != p2->local.u.in6.sin6_port)
			return false;

		if (!ipv6_addr_equal(&p1->remote.u.in6.sin6_addr,
				     &p2->remote.u.in6.sin6_addr))
			return false;

		if (p1->remote.u.in6.sin6_port != p2->remote.u.in6.sin6_port)
			return false;
		break;
	default:
		return false;
	}

	return true;
}

/* Validate a struct ovpn_sockaddr_pair:
 * 1. family must be AF_INET or AF_INET6
 * 2. family must be consistent
 */
static inline int
ovpn_sockaddr_pair_validate(const struct ovpn_sockaddr_pair *p)
{
	if (p->local.family != p->remote.family)
		return -EINVAL;

	switch (p->local.family) {
	case AF_INET:
	case AF_INET6:
		return 0;
	default:
		return -EAFNOSUPPORT;
	}
}

/* Translate skb->protocol value to AF_INET or AF_INET6 */
static inline unsigned short skb_protocol_to_family(const struct sk_buff *skb)
{
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		return AF_INET;
	case htons(ETH_P_IPV6):
		return AF_INET6;
	default:
		return 0;
	}
}

/* Translate skb->protocol value to AF_INET or AF_INET6 */
static inline int skb_protocol_to_ip_ver(const struct sk_buff *skb)
{
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		return 4;
	case htons(ETH_P_IPV6):
		return 6;
	default:
		return 0;
	}
}

#endif /* _NET_OVPN_DCO_OVPNADDR_H_ */
