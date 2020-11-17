// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include "crypto_none.h"
#include "crypto.h"
#include "pktid.h"
#include "proto.h"
#include "skb.h"

#include <linux/skbuff.h>
#include <linux/printk.h>

const struct ovpn_crypto_ops ovpn_none_ops;

static int ovpn_none_encap_overhead(const struct ovpn_crypto_key_slot *ks)
{
	return  OVPN_OP_SIZE_V2 +			/* OP header size */
		sizeof(u32);				/* Packet ID */
}

static int ovpn_none_encrypt(struct ovpn_crypto_key_slot *ks, struct sk_buff *skb)
{
	const u32 head_size = ovpn_none_encap_overhead(ks);
	u32 pktid, op;
	int ret;

	/* Sample NONE head:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	 * [ OP32 ] [seq # ] [             payload...                     ]
	 */

	/* check that there's enough headroom in the skb for packet
	 * encapsulation, after adding network header and encryption overhead
	 */
	if (unlikely(skb_cow_head(skb, OVPN_HEAD_ROOM + head_size)))
		return -ENOBUFS;

	/* Prepend packet ID */
	ret = ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid);
	if (unlikely(ret < 0)) {
		if (ret != -1)
			return ret;
		//ovpn_notify_pktid_wrap_pc(ks->peer, ks->key_id);
	}

	/* place seq # at the beginning of the packet */
	__skb_push(skb, sizeof(pktid));
	*((__force __be32 *)skb->data) = htonl(pktid);

	/* add packet op as head of additional data */
	op = ovpn_op32_compose(OVPN_DATA_V2, ks->key_id, ks->remote_peer_id);
	__skb_push(skb, OVPN_OP_SIZE_V2);
	BUILD_BUG_ON(sizeof(op) != OVPN_OP_SIZE_V2);
	*((__force __be32 *)skb->data) = htonl(op);

	return 0;
}

static int ovpn_none_decrypt(struct ovpn_crypto_key_slot *ks, struct sk_buff *skb, unsigned int op)
{
	const u32 payload_offset = ovpn_none_encap_overhead(ks);
	const u32 opcode = ovpn_opcode_extract(op);
	const u32 opsize = OVPN_OP_SIZE_V2;
	__be32 *pid;
	int ret;

	if (unlikely(opcode != OVPN_DATA_V2))
		return -EOPNOTSUPP;

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(skb->len - payload_offset < 0 || !pskb_may_pull(skb, payload_offset)))
		return -EINVAL;

	/* PID sits after the op */
	pid = (__force __be32 *)(skb->data + opsize);
	ret = ovpn_pktid_recv(&ks->pid_recv, ntohl(*pid), 0);
	if (unlikely(ret < 0))
		return ret;

	/* point to encapsulated IP packet */
	__skb_pull(skb, payload_offset);

	return 0;
}

static void ovpn_none_crypto_key_slot_destroy(struct ovpn_crypto_key_slot *ks)
{
	if (!ks)
		return;

	kfree(ks);
}

static struct ovpn_crypto_key_slot *ovpn_none_crypto_key_slot_new(const struct ovpn_key_config *kc)
{
	struct ovpn_crypto_key_slot *ks;

	/* validate crypto alg */
	if (kc->cipher_alg != OVPN_CIPHER_ALG_NONE)
		return ERR_PTR(-EOPNOTSUPP);

	/* build the key slot */
	ks = kmalloc(sizeof(*ks), GFP_KERNEL);
	if (!ks)
		return ERR_PTR(-ENOMEM);

	ks->ops = &ovpn_none_ops;
	kref_init(&ks->refcount);
	ks->key_id = kc->key_id;

	/* init packet ID generation/validation */
	ovpn_pktid_xmit_init(&ks->pid_xmit);
	ovpn_pktid_recv_init(&ks->pid_recv);

	return ks;
}

const struct ovpn_crypto_ops ovpn_none_ops = {
	.encrypt     = ovpn_none_encrypt,
	.decrypt     = ovpn_none_decrypt,
	.new         = ovpn_none_crypto_key_slot_new,
	.destroy     = ovpn_none_crypto_key_slot_destroy,
	.encap_overhead = ovpn_none_encap_overhead,
};
