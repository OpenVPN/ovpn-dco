/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020-2021 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_SKB_H_
#define _NET_OVPN_DCO_SKB_H_

#include <linux/types.h>
#include <net/ip_tunnels.h>

#define OVPN_SKB_CB(skb) ((struct ovpn_skb_cb *)&((skb)->cb))

struct ovpn_skb_cb {
	/* original recv packet size for stats accounting */
	unsigned int rx_stats_size;

};

/* READ_ONCE version of skb_queue_len()
 */
static inline u32 ovpn_skb_queue_len(const struct sk_buff_head *list)
{
	return READ_ONCE(list->qlen);
}

/* Return IP protocol version from skb header.
 * Return 0 if protocol is not IPv4/IPv6 or cannot be read.
 */
static inline __be16 ovpn_ip_check_protocol(struct sk_buff *skb)
{
	__be16 proto = 0;

	/* skb could be non-linear,
	 * make sure IP header is in non-fragmented part
	 */
	if (!pskb_network_may_pull(skb, sizeof(struct iphdr)))
		return 0;

	if (ip_hdr(skb)->version == 4)
		proto = htons(ETH_P_IP);
	else if (ip_hdr(skb)->version == 6)
		proto = htons(ETH_P_IPV6);

	return proto;
}

#endif /* _NET_OVPN_DCO_SKB_H_ */
