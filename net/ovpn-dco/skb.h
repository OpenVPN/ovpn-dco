/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

/*
 * READ_ONCE version of skb_queue_len()
 */
static inline u32 ovpn_skb_queue_len(const struct sk_buff_head *list)
{
	return READ_ONCE(list->qlen);
}


/*
 * Scrub the skb when encapsulating/decapsulating
 */
static inline void ovpn_skb_scrub(struct sk_buff *skb)
{
	skb_scrub_packet(skb, true);
	skb_clear_hash(skb);
	skb_set_queue_mapping(skb, 0);
	skb->dev = NULL;
	skb->protocol = 0;


	/* skb->priority is intentionally passed through */
}

/*
 * Probe IP header and do basic sanity checking on
 * IP packet in skb.
 */

/* flags */
#define OVPN_PROBE_SET_SKB      (1<<0)  /* set skb parms and possibly stash shim */

/* mask/flags in return value */
#define OVPN_PROBE_IPVER_MASK   (0xF)

static inline int ovpn_ip_header_probe(struct sk_buff *skb,
				       unsigned int flags) /* OVPN_PROBE_x */
{
	const struct iphdr *iph;

	/* make sure that encapsulated packet is large enough
	   to at least contain an IPv4 header */
	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		return -OVPN_ERR_IP_HEADER_LEN;

	/* verify specific IP version */
	iph = (struct iphdr *)skb->data;
	switch (iph->version) {
	case 4:
		/* make sure that IPv4 packet doesn't have a bogus length */
		if (unlikely((iph->ihl<<2) < sizeof(struct iphdr)))
			return -OVPN_ERR_BOGUS_PKT_LEN;
		if (flags & OVPN_PROBE_SET_SKB) {
			skb->protocol = htons(ETH_P_IP);
			skb_reset_network_header(skb);
		}
		return 4;
#if IS_ENABLED(CONFIG_IPV6)
	case 6:
		/* for IPv6, check for larger header size */
		if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
			return -OVPN_ERR_IP_HEADER_LEN;
		if (flags & OVPN_PROBE_SET_SKB) {
			skb->protocol = htons(ETH_P_IPV6);
			skb_reset_network_header(skb);
		}
		return 6;
#endif
	default:
		return -OVPN_ERR_IPVER_NOTIMP;
	}
}
