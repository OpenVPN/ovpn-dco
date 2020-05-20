/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNWORK_H_
#define _NET_OVPN_DCO_OVPNWORK_H_

#include <linux/types.h>

#define OVPN_SKB_CB(skb) ((struct ovpn_skb_cb *)&((skb)->cb))

struct ovpn_work {
	/* object must have +1 refcount during async op */
	struct ovpn_crypto_key_slot *ks;
};

struct ovpn_skb_cb {
	/* must be first member */
	struct ovpn_work *work;

	/* original recv packet size for stats accounting */
	unsigned int rx_stats_size;

	/* OpenVPN packet ID */
	u32 pktid;
};

#endif /* _NET_OVPN_DCO_OVPNWORK_H_ */
