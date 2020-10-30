/* SPDX-License-Identifier: GPL-2.0 */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_TCP_H_
#define _NET_OVPN_DCO_TCP_H_

#include <linux/workqueue.h>

void ovpn_tcp_tx_work(struct work_struct *work);
void ovpn_tcp_rx_work(struct work_struct *work);

void ovpn_queue_tcp_skb(struct ovpn_peer *peer, struct sk_buff *skb);

int ovpn_tcp_sock_attach(struct socket *sock, struct ovpn_peer *peer);
void ovpn_tcp_sock_detach(struct socket *sock);

#endif /* _NET_OVPN_DCO_TCP_H_ */
