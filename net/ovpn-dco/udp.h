/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_UDP_H_
#define _NET_OVPN_DCO_UDP_H_

#include "main.h"
#include "peer.h"
#include "ovpnstruct.h"

#include <linux/skbuff.h>
#include <linux/types.h>
#include <net/sock.h>

int ovpn_udp_encap_recv(struct sock *sk, struct sk_buff *skb);
void ovpn_udp_send_skb(struct ovpn_struct *ovpn, struct ovpn_peer *peer,
		       struct sk_buff *skb);
int ovpn_udp_send_data(struct ovpn_struct *ovpn, const u8 *data, size_t len);

#endif /* _NET_OVPN_DCO_UDP_H_ */
