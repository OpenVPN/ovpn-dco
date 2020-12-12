/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNPROTO_H_
#define _NET_OVPN_DCO_OVPNPROTO_H_

#include "main.h"

#include <linux/skbuff.h>

/* Methods for operating on the initial command
 * byte of the OpenVPN protocol.
 */

enum {
	/* packet opcode (high 5 bits) and key-id (low 3 bits) are combined in
	 * one byte
	 */
	OVPN_KEY_ID_MASK = 0x07,
	OVPN_OPCODE_SHIFT = 3,
	OVPN_OPCODE_MASK = 0x1F,

	/* upper bounds on opcode and key ID */
	OVPN_KEY_ID_MAX = (OVPN_KEY_ID_MASK + 1),
	OVPN_OPCODE_MAX = (OVPN_OPCODE_MASK + 1),

	/* packet opcodes of interest to us */
	OVPN_DATA_V1 = 6, /* data channel V1 packet */
	OVPN_DATA_V2 = 9, /* data channel V2 packet */

	/* size of initial packet opcode */
	OVPN_OP_SIZE_V1 = 1,
	OVPN_OP_SIZE_V2 = 4,

	/* indicates that Peer ID is undefined */
	OVPN_OP_PEER_ID_UNDEF = 0x00FFFFFF,

	/* mask for high Peer IDs, used by relays that also accept ordinary
	 * clients
	 */
	OVPN_OP_PEER_ID_HIGH_MASK = 0x00800000,

	/* first byte of keepalive message */
	OVPN_KEEPALIVE_FIRST_BYTE = 0x2a,

	/* first byte of exit message */
	OVPN_EXPLICIT_EXIT_NOTIFY_FIRST_BYTE = 0x28,
};

/**
 * Extract the OP code from the skb head.
 *
 * Note: this function assumes that the skb head was pulled enough
 * to access the first byte after the provided offset.
 *
 * Return the OP code
 */
static inline u8 ovpn_opcode_from_skb(const struct sk_buff *skb, u16 offset)
{
	return *(skb->data + offset) >> OVPN_OPCODE_SHIFT;
}

/**
 * Extract the key ID code from the skb head.
 *
 * Note: this function assumes that the skb head was pulled enough
 * to access the first at the beginning of the data buffer.
 *
 * Return the key ID
 */

static inline u8 ovpn_key_id_from_skb(const struct sk_buff *skb)
{
	return *skb->data & OVPN_KEY_ID_MASK;
}

static inline u32 ovpn_opcode_compose(u8 opcode, u8 key_id, u32 peer_id)
{
	const u8 op = (opcode << OVPN_OPCODE_SHIFT) | (key_id & OVPN_KEY_ID_MASK);

	return (op << 24) | (peer_id & 0x00FFFFFF);
}

#endif /* _NET_OVPN_DCO_OVPNPROTO_H_ */
