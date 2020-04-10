/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNDEBUG_H_
#define _NET_OVPN_DCO_OVPNDEBUG_H_

#include <net/ip.h>
#include <linux/ipv6.h>

#define ovpn_debug_netdev(level, ovpn, fmt, args...)			\
	do {								\
		netdev_printk(level,					\
			      ovpn->dev,				\
			      fmt,					\
			      ##args);					\
	} while (0)

#define ovpn_debug(level, fmt, args...)					\
	do {								\
		printk(level fmt, ##args);				\
	} while (0)

struct ovpn_debug_nf_pre
{
	char srcaddr[64];
	char destaddr[64];
};

static inline void ovpn_skb_head_print(const char *prefix,
				       const struct sk_buff *skb)
{
	ovpn_debug(KERN_INFO,
		   "%s h=%pK[%u] d=%pK[%u] tnm=0x%x/0x%x/0x%x[%u] s=%u/%u gso=%u/%u/%u p=0x%x hh=%u/%u hash=%u/%d/%d\n",
		   prefix,
		   skb->head, skb->hdr_len,
		   skb->data, skb->data_len,
		   skb->transport_header,
		   skb->network_header,
		   skb->mac_header, skb->mac_len,
		   skb->len,
		   skb->truesize,
		   skb_shinfo(skb)->gso_size, skb_shinfo(skb)->gso_segs, skb_shinfo(skb)->gso_type,
		   ntohs(skb->protocol),
		   skb_headroom(skb),
		   skb_headlen(skb),
		   skb->hash,
		   !!skb->l4_hash,
		   !!skb->sw_hash);
}

static inline void ovpn_skb_dump(const char *title,
				 const struct sk_buff *skb)
{
	const unsigned int maxbytes = 64;
	const unsigned int len = skb_headlen(skb);

	ovpn_skb_head_print(title, skb);
	if (len <= maxbytes) {
		print_hex_dump(KERN_INFO, "  ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, 0);
	} else {
		const unsigned int mb = maxbytes / 2;
		print_hex_dump(KERN_INFO, "  ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, mb, 0);
		print_hex_dump(KERN_INFO, "  ", DUMP_PREFIX_OFFSET, 16, 1, skb->data + (len - mb), mb, 0);
	}
}

static inline void ovpn_skb_addr_print(const char *prefix,
				       const struct sk_buff *skb)
{
	const struct iphdr *iph;

	iph = ip_hdr(skb);
        switch (iph->version) {
	case 4:
		ovpn_debug(KERN_INFO, "%s %pI4 -> %pI4\n", prefix, &iph->saddr, &iph->daddr);
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case 6:
	{
		struct ipv6hdr *ip6 = ipv6_hdr(skb);
		ovpn_debug(KERN_INFO, "%s %pI6 -> %pI6\n", prefix, &ip6->saddr, &ip6->daddr);
		break;
	}
#endif
	default:
		ovpn_debug(KERN_INFO, "%s unknown IP version\n", prefix);
		break;
	}
}

static inline void ovpn_sg_dump(const char *prefix, struct scatterlist *sgsrc,
				unsigned int len, bool dump_data)
{
	unsigned int i;
	for (i = 0; i < len; ++i) {
		struct scatterlist *sg = &sgsrc[i];
		ovpn_debug(KERN_INFO, "%s[%d] flags=%s%s len=%u\n",
			   prefix,
			   i,
			   sg_is_chain(sg) ? "C" : "",
			   sg_is_last(sg) ? "L" : "", sg->length);
		if (dump_data)
			print_hex_dump(KERN_INFO, "  ", DUMP_PREFIX_OFFSET,
				       16, 1, sg_virt(sg), sg->length, 0);
	}
}

#endif /* _NET_OVPN_DCO_OVPNDEBUG_H_ */
