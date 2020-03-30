/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

#include "ovpn.h"
#include "peer.h"

#include <net/ip.h>
#include <linux/types.h>

static inline const char *ovpn_pt_str(const unsigned int pkt_type)
{
	return "NONE";
}

static inline void ovpn_fmt_proto(const __u8 proto,
				  char *outbuf,
				  const size_t size)
{
	switch (proto) {
	case IPPROTO_TCP:
		snprintf(outbuf, size, "TCP");
		break;
	case IPPROTO_UDP:
		snprintf(outbuf, size, "UDP");
		break;
	case IPPROTO_ICMP:
		snprintf(outbuf, size, "ICMP");
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case IPPROTO_ICMPV6:
		snprintf(outbuf, size, "ICMPv6");
		break;
#endif
	default:
		snprintf(outbuf, size, "PROTO-%d", (int)proto);
		break;
	}
}

static inline void ovpn_fmt_proto_port(const struct ovpn_proto_port *pp,
				       char *outbuf,
				       const size_t size)
{
	char protoname[16];

	ovpn_fmt_proto(pp->proto, protoname, sizeof(protoname));

	switch (pp->proto) {
	default:
		snprintf(outbuf, size, "%s:%d",
			 protoname,
			 (int)ntohs(pp->port));
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case IPPROTO_ICMPV6:
#endif
	case IPPROTO_ICMP: {
		const int type = (ntohs(pp->port) >> 8) & 0xFF;
		const int code = ntohs(pp->port) & 0xFF;
		if (pp->id_defined) {
			const int id = ntohs(pp->id);
			snprintf(outbuf, size, "ICMP:%d/%d%%%d", type, code, id);
		} else
			snprintf(outbuf, size, "ICMP:%d/%d", type, code);
		break;
	}}
}

/* 1.2.3.4/TCP:443 */
static inline void ovpn_skb_fmt_addr(const struct sk_buff *skb,
				     const bool src,
				     char *outbuf,
				     const size_t size)
{
	const struct iphdr *iph;
	struct ovpn_proto_port pp = {0};
	char protoport[16];

	iph = ip_hdr(skb);
        switch (iph->version) {
	case 4:
		ovpn_get_ip4_port(skb, src, &pp);
		ovpn_fmt_proto_port(&pp, protoport, sizeof(protoport));
		snprintf(outbuf, size, "%pI4/%s",
			 src ? &iph->saddr : &iph->daddr,
			 protoport);
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case 6:
	{
		struct ipv6hdr *ip6 = ipv6_hdr(skb);
		ovpn_get_ip6_port(skb, src, &pp);
		ovpn_fmt_proto_port(&pp, protoport, sizeof(protoport));
		snprintf(outbuf, size, "%pI6/%s",
			 src ? &ip6->saddr : &ip6->daddr,
			 protoport);
		break;
	}
#endif
	default:
		snprintf(outbuf, size, "UNKNOWN-IP-VER-%d", (int)iph->version);
		break;
	}
}


static inline void ovpn_dbg_kovpn_in(const struct sk_buff *skb,
				     const struct ovpn_peer* peer)
{
	char srcbuf[64];
	char destbuf[64];
	ovpn_skb_fmt_addr(skb, true, srcbuf, sizeof(srcbuf));
	ovpn_skb_fmt_addr(skb, false, destbuf, sizeof(destbuf));
	printk("OVPN_DCO IN %s -> %s\n", srcbuf, destbuf);
}

static inline void ovpn_dbg_ping_received(const struct sk_buff *skb,
					  const struct ovpn_struct *ovpn,
					  const struct ovpn_peer* peer)
{
	printk("PING RECEIVED\n");
}

static inline void ovpn_dbg_ping_xmit(const struct ovpn_peer* peer)
{
	struct ovpn_struct *ovpn = NULL;
	struct ovpn_file *ofile;
	rcu_read_lock();
	ofile = rcu_dereference(peer->ofile);
	if (ofile)
		ovpn = rcu_dereference(ofile->ovpn);
	printk("PING XMIT\n");
	rcu_read_unlock();
}

#if DEBUG_DTAB

static inline void ovpn_dbg_dtab_lookup(const struct ovpn_dtab_key *dkey,
					const struct ovpn_dtab_entry *de)
{
	if (ovpn_dtab_addr_v4(&dkey->addr)) {
		printk("DTAB LOOKUP rid=%d swid=%d v4=%pI4\n", (int)dkey->route_id, (int)dkey->switch_id, &dkey->addr.a4.s_addr);
		if (de)
			printk("DTAB SUCCEED goto=%d target=%pI4\n", (int)de->goto_delta, &de->target.a4.s_addr);
	} else if (ovpn_dtab_addr_v6_defined(&dkey->addr)) {
		printk("DTAB LOOKUP rid=%d swid=%d v6=%pI6\n", (int)dkey->route_id, (int)dkey->switch_id, &dkey->addr.a6);
		if (de)
			printk("DTAB SUCCEED goto=%d target=%pI6\n", (int)de->goto_delta, &de->target.a6);
	}
}

#endif
