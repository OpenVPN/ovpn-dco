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

/* flags */
#define OVPN_PROBE_SET_SKB BIT(0) /* set skb parms and possibly stash shim */

/* mask/flags in return value */
#define OVPN_PROBE_IPVER_MASK (0xF)

static inline int ovpn_ip_header_probe(struct sk_buff *skb,
				       unsigned int flags) /* OVPN_PROBE_x */
{
	const struct iphdr *iph;

	/* make sure that encapsulated packet is large enough to at least
	 * contain an IPv4 header
	 */
	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		return -EINVAL;

	/* verify specific IP version */
	iph = (struct iphdr *)skb->data;
	switch (iph->version) {
	case 4:
		/* make sure that IPv4 packet doesn't have a bogus length */
		if (unlikely((iph->ihl << 2) < sizeof(struct iphdr)))
			return -EINVAL;
		if (flags & OVPN_PROBE_SET_SKB) {
			skb->protocol = htons(ETH_P_IP);
			skb_reset_network_header(skb);
		}
		return 4;
#if IS_ENABLED(CONFIG_IPV6)
	case 6:
		/* for IPv6, check for larger header size */
		if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
			return -EINVAL;
		if (flags & OVPN_PROBE_SET_SKB) {
			skb->protocol = htons(ETH_P_IPV6);
			skb_reset_network_header(skb);
		}
		return 6;
#endif
	default:
		return -EOPNOTSUPP;
	}
}

#endif /* _NET_OVPN_DCO_SKB_H_ */
