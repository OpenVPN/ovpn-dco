/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPN_H_
#define _NET_OVPN_DCO_OVPN_H_

#include "main.h"
#include "peer.h"
#include "sock.h"
#include "ovpnstruct.h"

#include <net/sock.h>

struct ovpn_struct;

static inline bool ovpn_hold(struct ovpn_struct *ovpn)
{
	return kref_get_unless_zero(&ovpn->refcount);
}

static inline void ovpn_put(struct ovpn_struct *ovpn)
{
	int removed;

	removed = kref_put(&ovpn->refcount, ovpn_release_lock);
#if DEBUG_FREE >= 1
	ovpn_debug(OVPN_KERN_INFO, "ovpn_put removed=%d refs=%d\n",
		   removed,
		   removed ? 0 : atomic_read(&ovpn->refcount.refcount));
#endif
}

static inline struct ovpn_struct *ovpn_struct_from_peer(struct ovpn_peer *peer)
	__must_hold(ovpn_config_mutex)
{
	return peer->ovpn;
}

u16 ovpn_select_queue(struct net_device *dev, struct sk_buff *skb,
		      struct net_device *sb_dev);

void ovpn_xmit_special(struct ovpn_peer *peer, const void *data,
			const unsigned int len);

netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev);

int ovpn_udp_encap_recv(struct sock *sk, struct sk_buff *skb);

#endif /* _NET_OVPN_DCO_OVPN_H_ */
