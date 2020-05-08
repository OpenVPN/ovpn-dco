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

/* READ_ONCE version of skb_queue_len()
 */
static inline u32 ovpn_skb_queue_len(const struct sk_buff_head *list)
{
	return READ_ONCE(list->qlen);
}

/* Probe IP header and do basic sanity checking on
 * IP packet in skb.
 */
static inline __be16 ovpn_ip_get_protocol(struct sk_buff *skb)
{
	const struct iphdr *iph;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		return 0;

	iph = ip_hdr(skb);
	switch (iph->version) {
	case 4:
		/* make sure that IPv4 packet doesn't have a bogus length */
		if (unlikely((iph->ihl << 2) < sizeof(struct iphdr)))
			return 0;
		return htons(ETH_P_IP);
	case 6:
		/* for IPv6, check for larger header size */
		if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
			return 0;
		return htons(ETH_P_IPV6);
	default:
		return 0;
	}
}


static inline int ovpn_ip_check_protocol(struct sk_buff *skb)
{
	__be16 proto = ovpn_ip_get_protocol(skb);

	if (unlikely(!proto))
		return -EPROTONOSUPPORT;

	if (unlikely(skb->protocol != proto))
		return -EINVAL;

	return 0;
}

static inline int ovpn_ip_header_probe(struct sk_buff *skb)
{
	__be16 proto = ovpn_ip_get_protocol(skb);

	if (!proto)
		return -EPROTONOSUPPORT;

	skb->protocol = proto;
	return 0;
}

#endif /* _NET_OVPN_DCO_SKB_H_ */
