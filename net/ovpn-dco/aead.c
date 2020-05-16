// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include "aead.h"
#include "peer.h"
#include "work.h"
#include "crypto.h"
#include "pktid.h"
#include "proto.h"

#include <crypto/aead.h>
#include <linux/skbuff.h>
#include <linux/printk.h>

#define OVPN_AEAD_WORK_SKB_CB(skb) \
	((struct ovpn_aead_work **)&OVPN_SKB_CB(skb)->work)

const struct ovpn_crypto_ops ovpn_aead_ops;

struct ovpn_aead_work {
	struct ovpn_work w; /* must be first member */

	/* user's callback */
	void (*callback)(struct sk_buff *skb, int err);

	/* encrypt/decrypt specific data */
	union {
		/* encrypt */
		struct {
		} e;

		/* decrypt */
		struct {
			unsigned int payload_offset;
			unsigned int pktid_offset;
		} d;
	} u;

	/* initialized by ovpn_aead_work_alloc */
	unsigned int sg_offset;
	int totfrags;
	unsigned int req_offset;
	unsigned char data[0] __aligned(sizeof(void *));
};

/* ovpn_aead_work accessors for the variable length components */

static unsigned char *wa_iv(struct ovpn_aead_work *work)
{
	return work->data;
}

static struct aead_request *wa_req(struct ovpn_aead_work *work)
{
	return (struct aead_request *)(work->data + work->req_offset);
}

static struct scatterlist *wa_sg(struct ovpn_aead_work *work)
{
	return (struct scatterlist *)(work->data + work->sg_offset);
}

/* allocate variable length object ovpn_aead_work */
static struct ovpn_aead_work *ovpn_aead_work_alloc(struct crypto_aead *aead,
						   unsigned int totfrags)
{
	struct ovpn_aead_work *work;
	unsigned int scatterlist_offset;
	unsigned int aead_request_offset;
	unsigned int len;

	len = offsetof(struct ovpn_aead_work, data);

	/* IV */
	len += NONCE_SIZE;

	/* struct scatterlist[] */
	len = ALIGN(len, __alignof__(struct scatterlist));
	scatterlist_offset = len;
	len += sizeof(struct scatterlist) * totfrags;

	/* struct aead_request */
	len += crypto_aead_alignmask(aead) & ~(crypto_tfm_ctx_alignment() - 1);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	aead_request_offset = len;
	len += sizeof(struct aead_request) + crypto_aead_reqsize(aead);

	/* alloc variable-length object */
	work = kmalloc(sizeof(*work) + len, GFP_ATOMIC);
	if (unlikely(!work))
		return NULL;

	/* set object offsets into data[] */
	work->totfrags = totfrags;
	work->sg_offset = scatterlist_offset - offsetof(struct ovpn_aead_work,
							data);
	work->req_offset = aead_request_offset - offsetof(struct ovpn_aead_work,
							  data);

	return work;
}

static struct ovpn_aead_work *ovpn_aead_encrypt_done2(struct sk_buff *skb,
						      int *err)
{
	struct ovpn_aead_work *work = *OVPN_AEAD_WORK_SKB_CB(skb);

	if (unlikely(*err))
		return work;

	return work;
}

static void ovpn_aead_encrypt_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;
	struct ovpn_aead_work *work = ovpn_aead_encrypt_done2(skb, &err);

	work->callback(skb, err);
}

static int ovpn_aead_encap_overhead(const struct ovpn_crypto_key_slot *ks)
{
	return  OVPN_OP_SIZE_V2 +			/* OP header size */
		4 +					/* Packet ID */
		crypto_aead_authsize(ks->u.ae.encrypt);	/* Auth Tag */
}

static int ovpn_aead_encrypt(struct ovpn_crypto_key_slot *ks,
			     struct sk_buff *skb,
			     void (*callback)(struct sk_buff *, int err))
{
	const unsigned int tag_size = crypto_aead_authsize(ks->u.ae.encrypt);
	const unsigned int head_size = ovpn_aead_encap_overhead(ks);
	unsigned int nfrags, nfrags_check;
	struct ovpn_aead_work *work;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	u32 pktid;
	int err;

	/* Sample AES-GCM head:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	 * [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	 *          [4-byte
	 *          IV head]
	 */

	/* check that there's enough headroom in the skb for packet
	 * encapsulation, after adding network header and encryption overhead
	 */
	if (unlikely(skb_cow_head(skb, OVPN_HEAD_ROOM + head_size))) {
		err = -ENOBUFS;
		goto error;
	}

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0)) {
		err = nfrags;
		goto error;
	}

	/* allocate workspace */
	work = ovpn_aead_work_alloc(ks->u.ae.encrypt, nfrags + 2);
	if (unlikely(!work)) {
		err = -ENOMEM;
		goto error;
	}

	/* get newly allocated space for scatter/gather list */
	sg = wa_sg(work);

	/* sg table:
	 * 0: pkt_op, wire nonce (AD, len=OVPN_OP_SIZE_V2+NONCE_WIRE_SIZE),
	 * 1, 2, 3, ...: payload,
	 * n: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* build scatterlist to encrypt packet payload */
	nfrags_check = skb_to_sgvec_nomark(skb, sg + 1, 0, skb->len);
	if (unlikely(nfrags != nfrags_check)) {
		err = -EINVAL;
		goto error_free;
	}

	/* append auth_tag onto scatterlist */
	__skb_push(skb, tag_size);
	sg_set_buf(sg + nfrags + 1, skb->data, tag_size);

	/* Prepend packet ID.
	 * Nonce containing OpenVPN packet ID is both our IV (NONCE_SIZE)
	 * and tail of our additional data (NONCE_WIRE_SIZE)
	 */
	__skb_push(skb, NONCE_WIRE_SIZE);
	err = ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid);
	if (unlikely(err < 0)) {
		if (err != -1)
			goto error_free;
		//ovpn_notify_pktid_wrap_pc(ks->peer, ks->key_id);
	}
	ovpn_pktid_aead_write(pktid, &ks->u.ae.nonce_tail_xmit,
			      wa_iv(work));
	memcpy(skb->data, wa_iv(work), NONCE_WIRE_SIZE);

	/* add packet op as head of additional data */
	{
		const u32 pkt_op = ovpn_op32_compose(OVPN_DATA_V2, ks->key_id,
						     ks->remote_peer_id);
		__skb_push(skb, OVPN_OP_SIZE_V2);
		BUILD_BUG_ON(sizeof(pkt_op) != OVPN_OP_SIZE_V2);
		*((__be32 *)skb->data) = htonl(pkt_op);
	}

	/* AEAD Additional data */
	sg_set_buf(sg, skb->data, OVPN_OP_SIZE_V2 + NONCE_WIRE_SIZE);

	/* finish workspace initialization and set pointer
	 * in private skb control buffer
	 */
	work->w.ks = ks;
	work->callback = callback;
	*OVPN_AEAD_WORK_SKB_CB(skb) = work;

	/* setup async crypto operation */
	aead_request_set_tfm(wa_req(work), ks->u.ae.encrypt);
	aead_request_set_callback(wa_req(work), 0, ovpn_aead_encrypt_done, skb);
	aead_request_set_crypt(wa_req(work), sg, sg, skb->len - head_size,
			       wa_iv(work));
	aead_request_set_ad(wa_req(work), OVPN_OP_SIZE_V2 + NONCE_WIRE_SIZE);

	/* encrypt it */
	err = crypto_aead_encrypt(wa_req(work));

	if (likely(err != -EINPROGRESS))
		ovpn_aead_encrypt_done2(skb, &err); /* synchronous */

	return err;

error_free:
	kfree(work);
error:
	*OVPN_AEAD_WORK_SKB_CB(skb) = NULL;
	return err;
}

static struct ovpn_aead_work *ovpn_aead_decrypt_done2(struct sk_buff *skb,
						      int *err)
{
	struct ovpn_crypto_key_slot *ks;
	struct ovpn_aead_work *work;

	work = *OVPN_AEAD_WORK_SKB_CB(skb);
	if (unlikely(*err))
		return work;

	/* get key slot  */
	ks = work->w.ks;
	if (unlikely(!ks)) {
		*err = -ENOENT;
		return work;
	}

	/* verify packet ID */
	{
		const __be32 *pid = (const __be32 *)(skb->data +
						     work->u.d.pktid_offset);
		const int status = ovpn_pktid_recv(&ks->pid_recv,
						   ntohl(*pid), 0);
		if (unlikely(status < 0)) {
			/* bad packet ID, drop packet */
			*err = status;
			return work;
		}
	}

	/* point to encapsulated IP packet */
	__skb_pull(skb, work->u.d.payload_offset);

	return work;
}

static void ovpn_aead_decrypt_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;
	struct ovpn_aead_work *work = ovpn_aead_decrypt_done2(skb, &err);

	work->callback(skb, err);
}

static int ovpn_aead_decrypt(struct ovpn_crypto_key_slot *ks,
			     struct sk_buff *skb, unsigned int op,
			     void (*callback)(struct sk_buff *, int err))
{
	unsigned int nfrags, nfrags_check, payload_offset, opsize, ad_start;
	const unsigned int tag_size = crypto_aead_authsize(ks->u.ae.decrypt);
	const unsigned int opcode = ovpn_opcode_extract(op);
	struct ovpn_aead_work *work;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	unsigned char *sg_data;
	int ret, payload_len;
	unsigned int sg_len;

	if (likely(opcode == OVPN_DATA_V2)) {
		opsize = OVPN_OP_SIZE_V2;
	} else if (opcode == OVPN_DATA_V1) {
		opsize = OVPN_OP_SIZE_V1;
	} else {
		ret = -EINVAL;
		goto error;
	}

	payload_offset = opsize + NONCE_WIRE_SIZE + tag_size;
	payload_len = skb->len - payload_offset;

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < 0 || !pskb_may_pull(skb, payload_offset))) {
		ret = -EINVAL;
		goto error;
	}

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0)) {
		ret = nfrags;
		goto error;
	}

	/* allocate workspace */
	work = ovpn_aead_work_alloc(ks->u.ae.decrypt, nfrags + 2);
	if (unlikely(!work)) {
		ret = -ENOMEM;
		goto error;
	}

	/* get newly allocated space for scatter/gather list */
	sg = wa_sg(work);

	/* sg table:
	 * 0: pkt_op, wire nonce (AD, len=OVPN_OP_SIZE_V2+NONCE_WIRE_SIZE),
	 * 1, 2, 3, ...: payload,
	 * n: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* packet op is head of additional data */
	sg_data = skb->data;
	sg_len = OVPN_OP_SIZE_V2 + NONCE_WIRE_SIZE;
	if (unlikely(opcode == OVPN_DATA_V1)) {
		sg_data = skb->data + OVPN_OP_SIZE_V1;
		sg_len = NONCE_WIRE_SIZE;
	}
	sg_set_buf(sg, sg_data, sg_len);

	/* build scatterlist to decrypt packet payload */
	nfrags_check = skb_to_sgvec_nomark(skb, sg + 1, payload_offset,
					   payload_len);
	if (unlikely(nfrags != nfrags_check)) {
		ret = -EINVAL;
		goto error_free;
	}

	/* append auth_tag onto scatterlist */
	sg_set_buf(sg + nfrags + 1, skb->data + opsize + NONCE_WIRE_SIZE,
		   tag_size);

	/* copy nonce into IV buffer */
	memcpy(wa_iv(work), skb->data + opsize, NONCE_WIRE_SIZE);
	memcpy(wa_iv(work) + NONCE_WIRE_SIZE, ks->u.ae.nonce_tail_recv.u8,
	       sizeof(struct ovpn_nonce_tail));

	/* finish workspace initialization and set pointer
	 * in private skb control buffer
	 */
	work->w.ks = ks;
	work->callback = callback;
	work->u.d.pktid_offset = opsize;
	work->u.d.payload_offset = payload_offset;
	*OVPN_AEAD_WORK_SKB_CB(skb) = work;

	/* setup async crypto operation */
	aead_request_set_tfm(wa_req(work), ks->u.ae.decrypt);
	aead_request_set_callback(wa_req(work), 0, ovpn_aead_decrypt_done, skb);
	aead_request_set_crypt(wa_req(work), sg, sg, payload_len + tag_size,
			       wa_iv(work));

	ad_start = NONCE_WIRE_SIZE;
	if (likely(opcode == OVPN_DATA_V2))
		ad_start += OVPN_OP_SIZE_V2;
	aead_request_set_ad(wa_req(work), ad_start);

	/* decrypt it */
	ret = crypto_aead_decrypt(wa_req(work));
	if (likely(ret != -EINPROGRESS))
		ovpn_aead_decrypt_done2(skb, &ret); /* synchronous */

	return ret;

error_free:
	kfree(work);
error:
	*OVPN_AEAD_WORK_SKB_CB(skb) = NULL;
	return ret;
}

/* Initialize a struct crypto_aead object */
static struct crypto_aead *ovpn_aead_init(const char *title,
					  const char *alg_name,
					  const unsigned char *key,
					  unsigned int keylen)
{
	const unsigned int auth_tag_size = 16;
	struct crypto_aead *aead;
	int ret;

	aead = crypto_alloc_aead(alg_name, 0, 0);
	if (IS_ERR(aead)) {
		ret = PTR_ERR(aead);
		pr_err("%s crypto_alloc_aead failed, err=%d\n", title, ret);
		aead = NULL;
		goto error;
	}

	ret = crypto_aead_setkey(aead, key, keylen);
	if (ret) {
		pr_err("%s crypto_aead_setkey size=%u failed, err=%d\n", title,
		       keylen, ret);
		goto error;
	}

	ret = crypto_aead_setauthsize(aead, auth_tag_size);
	if (ret) {
		pr_err("%s crypto_aead_setauthsize failed, err=%d\n", title,
		       ret);
		goto error;
	}

	/* basic AEAD assumption */
	if (crypto_aead_ivsize(aead) != EXPECTED_IV_SIZE) {
		pr_err("%s IV size must be %d\n", title, EXPECTED_IV_SIZE);
		ret = -EINVAL;
		goto error;
	}

	pr_debug("********* Cipher %s (%s)\n", alg_name, title);
	pr_debug("*** IV size=%u\n", crypto_aead_ivsize(aead));
	pr_debug("*** req size=%u\n", crypto_aead_reqsize(aead));
	pr_debug("*** block size=%u\n", crypto_aead_blocksize(aead));
	pr_debug("*** auth size=%u\n", crypto_aead_authsize(aead));
	pr_debug("*** alignmask=0x%x\n", crypto_aead_alignmask(aead));

	return aead;

error:
	crypto_free_aead(aead);
	return ERR_PTR(ret);
}

static void ovpn_aead_crypto_key_slot_destroy(struct ovpn_crypto_key_slot *ks)
{
	if (!ks)
		return;

	crypto_free_aead(ks->u.ae.encrypt);
	crypto_free_aead(ks->u.ae.decrypt);
	ovpn_peer_put(ks->peer);
	kfree(ks);
}

static struct ovpn_crypto_key_slot *
ovpn_aead_crypto_key_slot_init(enum ovpn_cipher_alg alg,
			       const unsigned char *encrypt_key,
			       unsigned int encrypt_keylen,
			       const unsigned char *decrypt_key,
			       unsigned int decrypt_keylen,
			       const unsigned char *encrypt_nonce_tail,
			       unsigned int encrypt_nonce_tail_len,
			       const unsigned char *decrypt_nonce_tail,
			       unsigned int decrypt_nonce_tail_len,
			       u16 key_id, struct ovpn_peer *peer)
{
	struct ovpn_crypto_key_slot *ks = NULL;
	const char *alg_name;
	int ret;

	/* validate crypto alg */
	switch (alg) {
	case OVPN_CIPHER_ALG_AES_GCM:
		alg_name = "gcm(aes)";
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	/* build the key slot */
	ks = kmalloc(sizeof(*ks), GFP_KERNEL);
	if (!ks)
		return ERR_PTR(-ENOMEM);

	ks->peer = NULL;
	ks->ops = &ovpn_aead_ops;
	ks->u.ae.encrypt = NULL;
	ks->u.ae.decrypt = NULL;
	kref_init(&ks->refcount);
	ks->key_id = key_id;

	/* grab a reference to peer */
	if (!ovpn_peer_hold(peer)) {
		ret = -ENOENT;
		goto destroy_ks;
	}

	ks->peer = peer;

	ks->u.ae.encrypt = ovpn_aead_init("encrypt", alg_name, encrypt_key,
					  encrypt_keylen);
	if (IS_ERR(ks->u.ae.encrypt)) {
		ret = PTR_ERR(ks->u.ae.encrypt);
		ks->u.ae.encrypt = NULL;
		goto destroy_ks;
	}

	ks->u.ae.decrypt = ovpn_aead_init("decrypt", alg_name, decrypt_key,
					  decrypt_keylen);
	if (IS_ERR(ks->u.ae.decrypt)) {
		ret = PTR_ERR(ks->u.ae.decrypt);
		ks->u.ae.decrypt = NULL;
		goto destroy_ks;
	}

	if (sizeof(struct ovpn_nonce_tail) != encrypt_nonce_tail_len ||
	    sizeof(struct ovpn_nonce_tail) != decrypt_nonce_tail_len) {
		ret = -EINVAL;
		goto destroy_ks;
	}

	memcpy(ks->u.ae.nonce_tail_xmit.u8, encrypt_nonce_tail,
	       sizeof(struct ovpn_nonce_tail));
	memcpy(ks->u.ae.nonce_tail_recv.u8, decrypt_nonce_tail,
	       sizeof(struct ovpn_nonce_tail));

	/* init packet ID generation/validation */
	ovpn_pktid_xmit_init(&ks->pid_xmit);
	ovpn_pktid_recv_init(&ks->pid_recv);

	return ks;

destroy_ks:
	ovpn_aead_crypto_key_slot_destroy(ks);
	return ERR_PTR(ret);
}

static struct ovpn_crypto_key_slot *
ovpn_aead_crypto_key_slot_new(const struct ovpn_key_config *kc,
			      struct ovpn_peer *peer)
{
	return ovpn_aead_crypto_key_slot_init(kc->cipher_alg,
					      kc->encrypt.cipher_key,
					      kc->encrypt.cipher_key_size,
					      kc->decrypt.cipher_key,
					      kc->decrypt.cipher_key_size,
					      kc->encrypt.nonce_tail,
					      kc->encrypt.nonce_tail_size,
					      kc->decrypt.nonce_tail,
					      kc->decrypt.nonce_tail_size,
					      kc->key_id, peer);
}

const struct ovpn_crypto_ops ovpn_aead_ops = {
	.encrypt     = ovpn_aead_encrypt,
	.decrypt     = ovpn_aead_decrypt,
	.new         = ovpn_aead_crypto_key_slot_new,
	.destroy     = ovpn_aead_crypto_key_slot_destroy,
	.encap_overhead = ovpn_aead_encap_overhead,
	.use_hmac    = false,
};
