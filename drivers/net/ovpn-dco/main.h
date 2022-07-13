/* SPDX-License-Identifier: GPL-2.0 */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2022 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_MAIN_H_
#define _NET_OVPN_DCO_MAIN_H_

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/printk.h>
#include <linux/udp.h>

#ifndef OVPN_DCO_VERSION
#define OVPN_DCO_VERSION "2.0.0"
#endif

/* Our UDP encapsulation types, must be unique
 * (other values in include/uapi/linux/udp.h)
 */
#define UDP_ENCAP_OVPNINUDP 100  /* transport layer */

struct net_device;
bool ovpn_dev_is_valid(const struct net_device *dev);

#define SKB_HEADER_LEN                                       \
	(max(sizeof(struct iphdr), sizeof(struct ipv6hdr)) + \
	 sizeof(struct udphdr) + NET_SKB_PAD)

#define OVPN_HEAD_ROOM ALIGN(16 + SKB_HEADER_LEN, 4)
#define OVPN_MAX_PADDING 16
#define OVPN_QUEUE_LEN 1024
#define OVPN_MAX_TUN_QUEUE_LEN 0x10000

#ifdef CONFIG_OVPN_DCO_DEBUG
#define ovpn_print_hex_debug(_buf, _len)				\
{									\
	print_hex_dump(KERN_DEBUG, "data: ", DUMP_PREFIX_NONE, 32, 1,	\
		       _buf, _len, true);				\
}
#else
#define ovpn_print_hex_debug(_buf, _len)				\
{									\
	if (0)								\
		print_hex_dump(KERN_DEBUG, "data: ", DUMP_PREFIX_NONE,	\
			       32, 1, _buf, _len, true);		\
									\
}
#endif

#endif /* _NET_OVPN_DCO_OVPN_DCO_H_ */
