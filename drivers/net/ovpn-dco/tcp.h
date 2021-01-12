/* SPDX-License-Identifier: GPL-2.0 */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2021 OpenVPN, Inc.
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

/* Prepare skb and enqueue it for sending to peer.
 *
 * Preparation consist in prepending the skb payload with its size.
 * Required by the OpenVPN protocol in order to extract packets from
 * the TCP stream on the receiver side.
 */
static inline void ovpn_tcp_send_skb(struct ovpn_peer *peer, struct sk_buff *skb)
{
	u16 len = skb->len;

	*(__be16 *)__skb_push(skb, sizeof(u16)) = htons(len);
	ovpn_queue_tcp_skb(peer, skb);
}

#endif /* _NET_OVPN_DCO_TCP_H_ */
