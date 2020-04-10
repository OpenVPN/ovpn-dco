// SPDX-License-Identifier: GPL-2.0-only
/*
 *  OpenVPN data channel accelerator
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

/*
 * Our state per ovpn interface, shared across all queues.
 */
struct ovpn_struct {
	/* read-mostly objects in this section */
	struct net_device *dev;

	spinlock_t lock;
	/* associated peer. in client mode we need only one peer. will be
	 * extended with a table later
	 */
	struct ovpn_peer __rcu *peer;
	struct socket *sock;
	enum ovpn_mode mode;
	enum ovpn_proto proto;

	struct ovpn_stats_percpu __percpu *stats;  /* per-CPU dev stats */

	unsigned int max_tun_queue_len;

	netdev_features_t set_features;

	void *security;

	/* Don't calculate checksum on outgoing tunnel packets */
	u8 omit_csum:1;

#ifdef CONFIG_OVPN_DCO_DEBUG
	int debug;
#endif

	uint32_t registered_nl_portid;
	bool registered_nl_portid_set;
};

#endif /* _NET_OVPN_DCO_OVPNSTRUCT_H_ */
