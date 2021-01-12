/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2021 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_MAIN_H_
#define _NET_OVPN_DCO_MAIN_H_

#ifndef OVPN_DCO_VERSION
#define OVPN_DCO_VERSION "2.0.0"
#endif

#define DEBUG_FREE		0
#define DEBUG_CRYPTO		0
#define DEBUG_PEER_BY_ID	0
#define DEBUG_CPU_SWITCH	0
#define DEBUG_PING		0
#define DEBUG_IN		0
#define DEBUG_DTAB		0
#define DEBUG_MTU		0
#define DEBUG_ERR_VERBOSE	0

/* Our UDP encapsulation types, must be unique
 * (other values in include/uapi/linux/udp.h)
 */
#define UDP_ENCAP_OVPNINUDP 100  /* transport layer */

/* If 1, filter replay packets */
#define ENABLE_REPLAY_PROTECTION 1

#include <linux/cache.h>
#include <linux/kref.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <net/ip.h>

static __cacheline_aligned_in_smp DEFINE_MUTEX(ovpn_config_mutex);

struct net_device;
bool ovpn_dev_is_valid(const struct net_device *dev);

void ovpn_release_lock(struct kref *kref);

#define SKB_HEADER_LEN                                       \
	(max(sizeof(struct iphdr), sizeof(struct ipv6hdr)) + \
	 sizeof(struct udphdr) + NET_SKB_PAD)

#define OVPN_HEAD_ROOM ALIGN(16 + SKB_HEADER_LEN, 4)
#define OVPN_MAX_PADDING 16

#define OVPN_QUEUE_LEN 1024

/* max allowed parameter values */
#define OVPN_MAX_PEERS                1000000
#define OVPN_MAX_DEV_QUEUES           0x1000
#define OVPN_MAX_DEV_TX_QUEUE_LEN     0x10000
#define OVPN_MAX_TUN_QUEUE_LEN        0x10000
#define OVPN_MAX_TCP_SEND_QUEUE_LEN   0x10000
#define OVPN_MAX_THROTTLE_PERIOD_MS   10000

#ifdef DEBUG
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
