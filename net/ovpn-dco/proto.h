/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

/*
 * Methods for operating on the initial command
 * byte of the OpenVPN protocol.
 */

#ifndef _NET_OVPN_DCO_OVPNPROTO_H_
#define _NET_OVPN_DCO_OVPNPROTO_H_

#include "main.h"

#include <linux/skbuff.h>

enum {
	/* packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte */
	OVPN_KEY_ID_MASK =   0x07,
	OVPN_OPCODE_SHIFT =     3,
	OVPN_OPCODE_MASK =   0x1F,

	/* upper bounds on opcode and key ID */
	OVPN_KEY_ID_MAX =    (OVPN_KEY_ID_MASK+1),
	OVPN_OPCODE_MAX =    (OVPN_OPCODE_MASK+1),

	/* packet opcodes of interest to us */
	OVPN_DATA_V1 =          6,   /* data channel V1 packet */
	OVPN_DATA_V2 =          9,   /* data channel V2 packet */

        /* size of initial packet opcode */
	OVPN_OP_SIZE_V1 =       1,
	OVPN_OP_SIZE_V2 =       4,

	/* indicates that Peer ID is undefined */
	OVPN_OP_PEER_ID_UNDEF = 0x00FFFFFF,

	/* mask for high Peer IDs, used by relays that also accept ordinary clients */
	OVPN_OP_PEER_ID_HIGH_MASK = 0x00800000,

	/* first byte of keepalive message */
	OVPN_KEEPALIVE_FIRST_BYTE = 0x2a,

	/* first byte of exit message */
	OVPN_EXPLICIT_EXIT_NOTIFY_FIRST_BYTE = 0x28,
};

/* 8 bit opcodes */

static inline unsigned int ovpn_opcode_extract(const unsigned int op)
{
	return op >> OVPN_OPCODE_SHIFT;
}

static inline unsigned int ovpn_key_id_extract(const unsigned int op)
{
	return op & OVPN_KEY_ID_MASK;
}

static inline unsigned int ovpn_op_compose(const unsigned int opcode,
					   const unsigned int key_id)
{
	return (opcode << OVPN_OPCODE_SHIFT) | key_id;
}

static inline bool ovpn_opcode_is_data(const unsigned int op)
{
	const unsigned int opcode = ovpn_opcode_extract(op);
	return opcode == OVPN_DATA_V2 || opcode == OVPN_DATA_V1;
}

/* 32 bit opcodes */

static inline unsigned int ovpn_op32_compose(const unsigned int opcode,
					     const unsigned int key_id,
					     const int op_peer_id)
{
	const unsigned int op8 = ovpn_op_compose(opcode, key_id);
	if (opcode == OVPN_DATA_V2)
		return (op8 << 24) | (op_peer_id & 0x00FFFFFF);
	else
		return op8;
}

static inline unsigned int ovpn_op32_from_skb(const struct sk_buff *skb,
					      int *op_peer_id)
{
	unsigned char op_buf[OVPN_OP_SIZE_V2];
	const void *p = skb_header_pointer(skb, 0, OVPN_OP_SIZE_V2, op_buf);
	u32 op;

	if (unlikely(!p))
		return 0;

	op = ntohl(*(const __be32 *)p);
	if (op_peer_id && ovpn_opcode_extract(op >> 24) == OVPN_DATA_V2) {
		const int opi = op & 0x00FFFFFF;
		if (opi != OVPN_OP_PEER_ID_UNDEF)
			*op_peer_id = opi;
		else
			*op_peer_id = -1;
	}
	return op >> 24;
}

/*
 * Is keepalive message?
 * Assumes that single byte at skb->data is defined.
 */
static inline bool ovpn_is_keepalive(struct sk_buff *skb)
{
	return *skb->data == OVPN_KEEPALIVE_FIRST_BYTE
		&& pskb_may_pull(skb, sizeof(ovpn_keepalive_message))
		&& !memcmp(skb->data, ovpn_keepalive_message,
			   sizeof(ovpn_keepalive_message));
}

/*
 * Is explicit exit notify message?
 * Assumes that single byte at skb->data is defined.
 */
static inline bool ovpn_is_explicit_exit_notify(struct sk_buff *skb)
{
	return *skb->data == OVPN_EXPLICIT_EXIT_NOTIFY_FIRST_BYTE
		&& pskb_may_pull(skb, sizeof(ovpn_explicit_exit_notify_message))
		&& !memcmp(skb->data, ovpn_explicit_exit_notify_message,
			   sizeof(ovpn_explicit_exit_notify_message));
}

#endif /* _NET_OVPN_DCO_OVPNPROTO_H_ */
