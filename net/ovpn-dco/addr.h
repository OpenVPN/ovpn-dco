/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
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

extern __u32 ovpn_hashrnd __read_mostly;

struct ovpn_addr {
       bool v6;
       union {
               struct in_addr a4;
               struct in6_addr a6;
       } u;
};

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
	bool skb_hash_defined;       /* true if skb_hash is defined */
	u32 skb_hash;              /* skb hash (L4) */
	struct ovpn_sockaddr local;   /* local ingress address */
	struct ovpn_sockaddr remote;  /* peer source address */
};

/* assumes that ovpn_hash_secret_init has been called */
static __always_inline __u32 ovpn_hash_3words(const __u32 a, const __u32 b,
					      const __u32 c)
{
	return jhash_3words(a, b, c, ovpn_hashrnd);
}

/* mask out the non-prefix bits in an IPv4 address */
static inline __be32 ovpn_ipv4_network_addr(const __be32 addr,
					    const unsigned int prefix_len)
{
	if (prefix_len)
		return addr & htonl(~((1 << (32 - prefix_len)) - 1));
	else
		return 0;
}

/* return an IPv4 address / prefix_len hash */
static inline __u32 ovpn_ipv4_hash(const __be32 addr,
				   const unsigned int prefix_len) {
	return ovpn_hash_3words(AF_INET, addr, prefix_len);
}

#if IS_ENABLED(CONFIG_IPV6)
/* return an IPv6 address / prefix_len hash */
static inline __u32 ovpn_ipv6_hash(const struct in6_addr *addr,
				   const unsigned int prefix_len) {
	return jhash_2words(AF_INET6,
			    prefix_len,
			    __ipv6_addr_jhash(addr, ovpn_hashrnd));
}
#endif

/*
 * Compare two ovpn_sockaddr_pair objects for equality,
 * considering family, addr, and port.
 * Note: we assume that the local/remote family values
 * within the same ovpn_sockaddr_pair are equal
 * (use ovpn_sockaddr_pair_validate below to validate this).
 */
static inline bool ovpn_sockaddr_pair_eq(const struct ovpn_sockaddr_pair *p1,
					 const struct ovpn_sockaddr_pair *p2)
{
	const bool d1 = p1->skb_hash_defined;
	if (d1 != p2->skb_hash_defined)
		return false;
	if (d1 && p1->skb_hash != p2->skb_hash)
		return false;
	if (p1->local.family != p2->local.family)
		return false;
	switch (p1->local.family) {
	case AF_INET:
		return  p1->local.u.in4.sin_addr.s_addr == p2->local.u.in4.sin_addr.s_addr &&
			p1->local.u.in4.sin_port == p2->local.u.in4.sin_port &&
			p1->remote.u.in4.sin_addr.s_addr == p2->remote.u.in4.sin_addr.s_addr &&
			p1->remote.u.in4.sin_port == p2->remote.u.in4.sin_port;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		return  ipv6_addr_equal(&p1->local.u.in6.sin6_addr, &p2->local.u.in6.sin6_addr) &&
			p1->local.u.in6.sin6_port == p2->local.u.in6.sin6_port &&
			ipv6_addr_equal(&p1->remote.u.in6.sin6_addr, &p2->remote.u.in6.sin6_addr) &&
			p1->remote.u.in6.sin6_port == p2->remote.u.in6.sin6_port;
#endif
	}
	return false;
}

/*
 * Validate a struct ovpn_sockaddr_pair:
 * 1. family must be AF_INET or AF_INET6
 * 2. family must be consistent
 */
static inline int ovpn_sockaddr_pair_validate(const struct ovpn_sockaddr_pair *p)
{
	if (p->local.family != p->remote.family)
		return -OVPN_ERR_IPVER_INCONSISTENT;

	switch (p->local.family) {
	case AF_INET:
#if IS_ENABLED(CONFIG_IPV6)
        case AF_INET6:
#endif
		return 0;
        default:
		return -OVPN_ERR_IPVER_NOTIMP;
	}
}

/*
 * Translate skb->protocol value to AF_INET or AF_INET6.
 */
static inline unsigned short skb_protocol_to_family(const struct sk_buff *skb)
{
	switch (skb->protocol)
	{
	case htons(ETH_P_IP):
		return AF_INET;
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
		return AF_INET6;
#endif
	default:
		return 0;
	}
}

/*
 * Translate skb->protocol value to AF_INET or AF_INET6.
 */
static inline int skb_protocol_to_ip_ver(const struct sk_buff *skb)
{
	switch (skb->protocol)
	{
	case htons(ETH_P_IP):
		return 4;
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
		return 6;
#endif
	default:
		return 0;
	}
}

int ovpn_sockaddr_pair_from_skb(struct ovpn_sockaddr_pair *sapair,
				struct sk_buff *skb);

int ovpn_sockaddr_pair_from_sock(struct ovpn_sockaddr_pair *sapair,
				 struct sock *sk,
				 const bool tcp);

void ovpn_hash_secret_init(void);

#endif /* _NET_OVPN_DCO_OVPNADDR_H_ */
