/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2020 OpenVPN, Inc.
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

static __cacheline_aligned_in_smp DEFINE_MUTEX(ovpn_config_mutex);

struct net_device;
bool ovpn_dev_is_valid(const struct net_device *dev);

static const unsigned char ovpn_keepalive_message[] = {
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

static const unsigned char ovpn_explicit_exit_notify_message[] = {
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
	6 // OCC_EXIT
};

void ovpn_release_lock(struct kref *kref);

#define SKB_HEADER_LEN                                       \
	(max(sizeof(struct iphdr), sizeof(struct ipv6hdr)) + \
	 sizeof(struct udphdr) + NET_SKB_PAD)

#define OVPN_HEAD_ROOM ALIGN(16 + SKB_HEADER_LEN, 4)
#define OVPN_MAX_PADDING 16

/* max allowed parameter values */
#define OVPN_MAX_PEERS                1000000
#define OVPN_MAX_DEV_QUEUES           0x1000
#define OVPN_MAX_DEV_TX_QUEUE_LEN     0x10000
#define OVPN_MAX_TUN_QUEUE_LEN        0x10000
#define OVPN_MAX_TCP_SEND_QUEUE_LEN   0x10000
#define OVPN_MAX_THROTTLE_PERIOD_MS   10000

#endif /* _NET_OVPN_DCO_OVPN_DCO_H_ */
