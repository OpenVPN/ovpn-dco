/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNSTRUCT_H_
#define _NET_OVPN_DCO_OVPNSTRUCT_H_

#include "peer.h"

#include <uapi/linux/ovpn_dco.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

/* Our state per ovpn interface */
struct ovpn_struct {
	/* read-mostly objects in this section */
	struct net_device *dev;

	/* protect writing to the ovpn_struct object */
	spinlock_t lock;

	/* workqueue used to schedule crypto work that may sleep */
	struct workqueue_struct *crypto_wq;
	/* workqueue used to schedule generic event that may sleep or that need
	 * to be performed out of softirq context
	 */
	struct workqueue_struct *events_wq;

	/* associated peer. in client mode we need only one peer. will be
	 * extended with a table later
	 */
	struct ovpn_peer __rcu *peer;
	struct socket *sock;
	enum ovpn_mode mode;
	enum ovpn_proto proto;

	unsigned int max_tun_queue_len;

	netdev_features_t set_features;

	void *security;

#ifdef CONFIG_OVPN_DCO_DEBUG
	int debug;
#endif

	u32 registered_nl_portid;
	bool registered_nl_portid_set;
};

#endif /* _NET_OVPN_DCO_OVPNSTRUCT_H_ */
