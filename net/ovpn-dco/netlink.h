/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_NETLINK_H_
#define _NET_OVPN_DCO_NETLINK_H_

int ovpn_netlink_register(void);
void ovpn_netlink_unregister(void);
int ovpn_netlink_send_packet(struct ovpn_struct *ovpn, const uint8_t *buf,
			     size_t len);

#endif /* _NET_OVPN_DCO_NETLINK_H_ */
