/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020-2021 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_NETLINK_H_
#define _NET_OVPN_DCO_NETLINK_H_

int ovpn_netlink_init(struct ovpn_struct *ovpn);
int ovpn_netlink_register(void);
void ovpn_netlink_unregister(void);
int ovpn_netlink_send_packet(struct ovpn_struct *ovpn, const uint8_t *buf,
			     size_t len);
int ovpn_netlink_notify_del_peer(struct ovpn_peer *peer);

#endif /* _NET_OVPN_DCO_NETLINK_H_ */
