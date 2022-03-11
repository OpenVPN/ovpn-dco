/* SPDX-License-Identifier: GPL-2.0-only */
/*  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2021 OpenVPN Technologies, Inc.
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
	union {
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	};
};

/* mask out the non-prefix bits in an IPv4 address */
static inline __be32 ovpn_ipv4_network_addr(const __be32 addr,
					    const unsigned int prefix_len)
{
	if (!prefix_len)
		return 0;

	return addr & htonl(~((1 << (32 - prefix_len)) - 1));
}

/* Validate a struct ovpn_sockaddr:
 * 1. family must be AF_INET or AF_INET6
 * 2. family must be consistent
 */
static inline int
ovpn_sockaddr_validate(const struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
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
