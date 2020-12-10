/* SPDX-License-Identifier: GPL-2.0-only */
/*  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2021 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNBIND_H_
#define _NET_OVPN_DCO_OVPNBIND_H_

#include "addr.h"
#include "rcu.h"

#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

struct ovpn_peer;

struct ovpn_bind {
	struct ovpn_sockaddr_pair sapair;  /* local/remote sockaddrs */
	struct rcu_head rcu;
};

static inline bool ovpn_bind_skb_match(const struct ovpn_bind *bind,
				       struct sk_buff *skb)
{
	const unsigned short family = skb_protocol_to_family(skb);
	const struct ovpn_sockaddr_pair *sap = &bind->sapair;
	const u32 hash_key = skb_get_hash(skb);

	if (unlikely(!bind))
		return false;

	if (unlikely(bind->sapair.skb_hash_defined &&
		     bind->sapair.skb_hash != hash_key))
		return false;

	if (unlikely(bind->sapair.local.family != family))
		return false;

	switch (family) {
	case AF_INET:
		if (unlikely(sap->local.u.in4.sin_addr.s_addr !=
			     ip_hdr(skb)->daddr))
			return false;

		if (unlikely(sap->local.u.in4.sin_port != udp_hdr(skb)->dest))
			return false;

		if (unlikely(sap->remote.u.in4.sin_addr.s_addr !=
			     ip_hdr(skb)->saddr))
			return false;

		if (unlikely(sap->remote.u.in4.sin_port !=
			     udp_hdr(skb)->source))
			return false;
		break;
	case AF_INET6:
		if (unlikely(!ipv6_addr_equal(&sap->local.u.in6.sin6_addr,
					      &ipv6_hdr(skb)->daddr)))
			return false;

		if (unlikely(sap->local.u.in6.sin6_port != udp_hdr(skb)->dest))
			return false;

		if (unlikely(!ipv6_addr_equal(&sap->remote.u.in6.sin6_addr,
					      &ipv6_hdr(skb)->saddr)))
			return false;

		if (unlikely(sap->remote.u.in6.sin6_port !=
			     udp_hdr(skb)->source))
			return false;
		break;
	default:
		return false;
	}

	return true;
}

/* Return true if sockaddr (src/dest addr/port) of incoming packet
 * is different from previously saved value.
 * rcu_read_lock must be held.
 * Called in softirq context.
 */
static inline bool ovpn_bind_test_peer(const struct ovpn_bind *bind,
				       struct sk_buff *skb)
{
	ovpn_rcu_lockdep_assert_held();

	/* no-op if skb src/dest addr/port is equal to what
	 * we previously saved
	 */
	if (likely(ovpn_bind_skb_match(bind, skb)))
		return false;

	/* peer src/dest addr/port has changed */
	return true;
}

bool ovpn_bind_get_sockaddr_pair(const struct ovpn_peer *peer,
				 struct ovpn_sockaddr_pair *sapair);

struct ovpn_bind *
ovpn_bind_from_sockaddr_pair(const struct ovpn_sockaddr_pair *pair);
void ovpn_bind_reset(struct ovpn_peer *peer, struct ovpn_bind *bind);

#endif /* _NET_OVPN_DCO_OVPNBIND_H_ */
