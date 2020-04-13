// SPDX-License-Identifier: GPL-2.0-only
/*
 *  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */


#ifndef _NET_OVPN_DCO_OVPN_H_
#define _NET_OVPN_DCO_OVPN_H_

#include "main.h"
#include "peer.h"
#include "sock.h"
#include "ovpnstruct.h"

#include <net/sock.h>

struct ovpn_struct;
struct net_device;

int ovpn_struct_init(struct net_device *dev);

u16 ovpn_select_queue(struct net_device *dev, struct sk_buff *skb,
		      struct net_device *sb_dev);

void ovpn_xmit_special(struct ovpn_peer *peer, const void *data,
			const unsigned int len);

netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev);

int ovpn_udp_encap_recv(struct sock *sk, struct sk_buff *skb);

#endif /* _NET_OVPN_DCO_OVPN_H_ */
