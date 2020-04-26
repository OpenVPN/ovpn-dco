/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNPKTID_H_
#define _NET_OVPN_DCO_OVPNPKTID_H_

#include "main.h"

#include <linux/spinlock.h>

/* When the OpenVPN protocol is run in AEAD mode, use
 * the OpenVPN packet ID as the AEAD nonce:
 *
 *    00000005 521c3b01 4308c041 83ba3099
 *    [seq # ] [nonce_tail              ]
 *    [               16-byte full IV   ] -> NONCE_SIZE
 *    [4-bytes                            -> NONCE_WIRE_SIZE
 *    on wire]
 */

/* AEAD nonce size -- this is the full AEAD IV size */
#define NONCE_SIZE 16

/* AEAD nonce size reduced by 4-byte nonce tail -- this is the
 * size of the AEAD Associated Data (AD) sent over the wire
 * and is normally the head of the IV
 */
#define NONCE_WIRE_SIZE (NONCE_SIZE - sizeof(struct ovpn_nonce_tail))

/* AEAD expected IV size */
#ifndef EXPECTED_IV_SIZE
#define EXPECTED_IV_SIZE 12
#endif

/* If no packets received for this length of time, set a backtrack floor
 * at highest received packet ID thus far.
 */
#define PKTID_RECV_EXPIRE (30 * HZ)

/* Warn userspace with OVPN_TH_NOTIFY_PKTID_WRAP_WARN
 * message when packet ID crosses this threshold.
 */
#ifndef PKTID_WRAP_WARN
#define PKTID_WRAP_WARN 0xf0000000ULL
#endif

/* Last 12 bytes of AEAD nonce.
 * Normally is negotiated implicitly rather than
 * being sent explicitly over the wire.
 */
struct ovpn_nonce_tail {
	u8 u8[12];
};

/* Packet-ID state for transmitter */
struct ovpn_pktid_xmit {
	atomic64_t seq_num;
	struct ovpn_tcp_linear *tcp_linear;
};

/* replay window sizing in bytes = 2^REPLAY_WINDOW_ORDER */
#define REPLAY_WINDOW_ORDER 8

#define REPLAY_WINDOW_BYTES BIT(REPLAY_WINDOW_ORDER)
#define REPLAY_WINDOW_SIZE  (REPLAY_WINDOW_BYTES * 8)
#define REPLAY_INDEX(base, i) (((base) + (i)) & (REPLAY_WINDOW_SIZE - 1))

/* Packet-ID state for receiver.
 * Other than lock member, can be zeroed to initialize.
 */
struct ovpn_pktid_recv {
	/* "sliding window" bitmask of recent packet IDs received */
	u8 history[REPLAY_WINDOW_BYTES];
	/* bit position of deque base in history */
	unsigned int base;
	/* extent (in bits) of deque in history */
	unsigned int extent;
	/* expiration of history in jiffies */
	unsigned long expire;
	/* highest sequence number received */
	u32 id;
	/* highest time stamp received */
	u32 time;
	/* we will only accept backtrack IDs > id_floor */
	u32 id_floor;
	unsigned int max_backtrack;
	/* protects entire pktd ID state */
	spinlock_t lock;
};

/* Get the next packet ID for xmit */
static inline int ovpn_pktid_xmit_next(struct ovpn_pktid_xmit *pid, u32 *pktid)
{
	const u64 seq_num = atomic64_inc_return(&pid->seq_num);

	BUILD_BUG_ON(PKTID_WRAP_WARN >= 0x100000000ULL);
	*pktid = (u32)seq_num;
	if (unlikely(seq_num >= PKTID_WRAP_WARN)) {
		if (seq_num >= 0x100000000ULL)
			return -E2BIG;
		if (seq_num == PKTID_WRAP_WARN)
			return -1;
	}
	return 0;
}

/* Write the full 16-byte AEAD IV to dest */
static inline void ovpn_pktid_aead_write(const u32 pktid,
					 const struct ovpn_nonce_tail *nt,
					 unsigned char *dest)
{
	*(__be32 *)(dest) = htonl(pktid);
	BUILD_BUG_ON(4 + sizeof(struct ovpn_nonce_tail) != NONCE_SIZE);
	memcpy(dest + 4, nt->u8, sizeof(struct ovpn_nonce_tail));
}

/* Write a short-form CBC/HMAC packet ID to dest (4 bytes) */
static inline void ovpn_pktid_chm_write(const u32 pktid, unsigned char *dest)
{
	*(u32 *)dest = htonl(pktid);
}

void ovpn_pktid_xmit_init(struct ovpn_pktid_xmit *pid);
void ovpn_pktid_recv_init(struct ovpn_pktid_recv *pr);

int ovpn_pktid_recv(struct ovpn_pktid_recv *pr, u32 pkt_id, u32 pkt_time);

#endif /* _NET_OVPN_DCO_OVPNPKTID_H_ */
