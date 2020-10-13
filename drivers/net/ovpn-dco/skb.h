/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
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

	/* OpenVPN packet ID */
	u32 pktid;
};

/* READ_ONCE version of skb_queue_len()
 */
static inline u32 ovpn_skb_queue_len(const struct sk_buff_head *list)
{
	return READ_ONCE(list->qlen);
}

static inline int ovpn_ip_check_protocol(struct sk_buff *skb)
{
	__be16 proto = ip_tunnel_parse_protocol(skb);

	if (unlikely(!proto))
		return -EPROTONOSUPPORT;

	if (unlikely(skb->protocol != proto))
		return -EINVAL;

	return 0;
}

static inline int ovpn_ip_header_probe(struct sk_buff *skb)
{
	__be16 proto = ip_tunnel_parse_protocol(skb);

	if (!proto)
		return -EPROTONOSUPPORT;

	skb->protocol = proto;
	return 0;
}

#endif /* _NET_OVPN_DCO_SKB_H_ */
