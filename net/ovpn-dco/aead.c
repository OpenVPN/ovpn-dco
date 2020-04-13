// SPDX-License-Identifier: GPL-2.0-only
/*
 *  OpenVPN data channel accelerator
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
#include "debug.h"
#include "pktid.h"
#include "proto.h"

#include <crypto/aead.h>
#include <linux/skbuff.h>

#define OVPN_AEAD_WORK_SKB_CB(skb) ((struct ovpn_aead_work **) &OVPN_SKB_CB(skb)->work)

const struct ovpn_crypto_ops ovpn_aead_ops;

struct ovpn_aead_work {
	struct ovpn_work w; /* must be first member */

	/* user's callback */
	void (*callback)(struct sk_buff *, int err);

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

/*
 * ovpn_aead_work accessors for the variable length components
 */

static inline unsigned char *wa_iv(struct ovpn_aead_work *work)
{
	return work->data;
}

static inline struct aead_request *wa_req(struct ovpn_aead_work *work)
{
	return (struct aead_request *)(work->data + work->req_offset);
}

static inline struct scatterlist *wa_sg(struct ovpn_aead_work *work)
{
	return (struct scatterlist *)(work->data + work->sg_offset);
}

/*
 * allocate variable length object ovpn_aead_work
 */

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
	work = kmalloc(sizeof(struct ovpn_aead_work) + len, GFP_ATOMIC);
	if (unlikely(!work))
		return NULL;

	/* set object offsets into data[] */
	work->totfrags = totfrags;
	work->sg_offset = scatterlist_offset - offsetof(struct ovpn_aead_work, data);
	work->req_offset = aead_request_offset - offsetof(struct ovpn_aead_work, data);

	return work;
}

static inline struct ovpn_aead_work *ovpn_aead_encrypt_done2(struct sk_buff *skb,
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

/*
 * Encrypt skb.
 */
static int ovpn_aead_encrypt(struct ovpn_crypto_context *cc,
			     struct sk_buff *skb,
			     unsigned int net_headroom,
			     unsigned int key_id,
			     void (*callback)(struct sk_buff *, int err))
{
	struct sk_buff *trailer;
	unsigned int nfrags;
	struct ovpn_aead_work *work;
	struct scatterlist *sg;
	int err;

	const unsigned int auth_tag_size = crypto_aead_authsize(cc->u.ae.encrypt);

	/*
	 * Sample AES-GCM head:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	 * [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	 *          [4-byte
	 *          IV head]
	 */

	/* check that there's enough headroom in the skb for packet encapsulation,
	   after adding network header and encryption overhead */
	if (unlikely(skb_cow_head(skb, net_headroom +
				  OVPN_OP_SIZE_V2 +
				  NONCE_WIRE_SIZE +
				  auth_tag_size +
				  OVPN_COMPRESS_V2_MAX_HEAD))) {
		err = -OVPN_ERR_ENCRYPT_COW_HEAD;
		goto error;
	}

	/* get number of skb fragments and ensure that packet data is writable */
	{
		err = skb_cow_data(skb, 0, &trailer);
		if (unlikely(err < 0)) {
			err = -OVPN_ERR_ENCRYPT_COW_DATA;
			goto error;
		}
		nfrags = err;
	}

	/* allocate workspace */
	work = ovpn_aead_work_alloc(cc->u.ae.encrypt, nfrags + 2);
	if (unlikely(!work)) {
		err = -ENOMEM;
		goto error;
	}

	/* get newly allocated space for scatter/gather list */
	sg = wa_sg(work);

	/*
	 * sg table:
	 * 0: pkt_op, wire nonce (AD, len=OVPN_OP_SIZE_V2+NONCE_WIRE_SIZE),
	 * 1, 2, 3, ...: payload,
	 * n: auth_tag (len=auth_tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* build scatterlist to encrypt packet payload */
	{
		unsigned int nfrags_check;
		nfrags_check = skb_to_sgvec_nomark(skb, sg + 1, 0, skb->len);
		if (unlikely(nfrags != nfrags_check)) {
			err = -OVPN_ERR_NFRAGS;
			goto error_free;
		}
	}

	/* append auth_tag onto scatterlist */
	__skb_push(skb, auth_tag_size);
	sg_set_buf(sg + nfrags + 1, skb->data, auth_tag_size);

	/* Prepend packet ID.
	   Nonce containing OpenVPN packet ID is both our IV (NONCE_SIZE)
	   and tail of our additional data (NONCE_WIRE_SIZE). */
	{
		u32 pktid;

		__skb_push(skb, NONCE_WIRE_SIZE);
		err = ovpn_pktid_xmit_next(&cc->pid_xmit, &pktid);
		if (unlikely(err < 0)) {
			if (err != -OVPN_ERR_PKTID_WRAP_WARN)
				goto error_free;
			//ovpn_notify_pktid_wrap_pc(cc->peer, key_id);
		}
		ovpn_pktid_aead_write(pktid, &cc->u.ae.nonce_tail_xmit,
				      wa_iv(work));
		memcpy(skb->data, wa_iv(work), NONCE_WIRE_SIZE);
	}

	/* add packet op as head of additional data */
	{
		const u32 pkt_op = ovpn_op32_compose(OVPN_DATA_V2, key_id,
						     cc->remote_peer_id);
		__skb_push(skb, OVPN_OP_SIZE_V2);
		BUILD_BUG_ON(OVPN_OP_SIZE_V2 != sizeof(pkt_op));
		*((__be32 *)skb->data) = htonl(pkt_op);
	}

	/* AEAD Additional data */
	sg_set_buf(sg, skb->data, OVPN_OP_SIZE_V2 + NONCE_WIRE_SIZE);

#if DEBUG_CRYPTO >= 1
	ovpn_sg_dump("AEAD-E ", sg, nfrags + 2, true);
#endif

	/* finish workspace initialization and set pointer
	   in private skb control buffer */
	work->w.cc = cc;
	work->callback = callback;
	*OVPN_AEAD_WORK_SKB_CB(skb) = work;

	/* setup async crypto operation */
	aead_request_set_tfm(wa_req(work), cc->u.ae.encrypt);
	aead_request_set_callback(wa_req(work), 0, ovpn_aead_encrypt_done, skb);
	aead_request_set_crypt(wa_req(work), sg, sg,
			       skb->len - (OVPN_OP_SIZE_V2 + NONCE_WIRE_SIZE + auth_tag_size),
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

static struct ovpn_aead_work *ovpn_aead_decrypt_done2(struct sk_buff *skb, int *err)
{
	struct ovpn_aead_work *work;
	struct ovpn_crypto_context *cc;

	work = *OVPN_AEAD_WORK_SKB_CB(skb);
	if (unlikely(*err))
		return work;

	/* get crypto context */
	cc = work->w.cc;
	if (unlikely(!cc)) {
		*err = -OVPN_ERR_NO_CRYPTO_CONTEXT;
		return work;
	}

	/* verify packet ID */
	{
		const __be32 *pid = (const __be32 *)(skb->data +
						     work->u.d.pktid_offset);
		const int status = ovpn_pktid_recv(&cc->pid_recv,
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

/*
 * Decrypt skb.
 */
static int ovpn_aead_decrypt(struct ovpn_crypto_context *cc,
			     struct sk_buff *skb,
			     unsigned int key_id,
			     unsigned int op,
			     void (*callback)(struct sk_buff *, int err))
{
	struct sk_buff *trailer;
	unsigned int nfrags;
	struct ovpn_aead_work *work;
	struct scatterlist *sg;
	int err;

	const unsigned int auth_tag_size = crypto_aead_authsize(cc->u.ae.decrypt);
	const unsigned int opcode = ovpn_opcode_extract(op);
	unsigned int opsize;
	unsigned int payload_offset;
	int payload_len;

	if (likely(opcode == OVPN_DATA_V2))
		opsize = OVPN_OP_SIZE_V2;
	else if (opcode == OVPN_DATA_V1)
		opsize = OVPN_OP_SIZE_V1;
	else {
		err = -OVPN_ERR_DATA_V1_V2_REQUIRED;
		goto error;
	}

	payload_offset = opsize + NONCE_WIRE_SIZE + auth_tag_size;
	payload_len = skb->len - payload_offset;

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < 0 || !pskb_may_pull(skb, payload_offset))) {
		err = -OVPN_ERR_DECRYPT_PKT_SIZE;
		goto error;
	}

	/* get number of skb fragments and ensure that packet data is writable */
	{
		err = skb_cow_data(skb, 0, &trailer);
		if (unlikely(err < 0)) {
			err = -OVPN_ERR_DECRYPT_COW_DATA;
			goto error;
		}
		nfrags = err;
	}

	/* allocate workspace */
	work = ovpn_aead_work_alloc(cc->u.ae.decrypt, nfrags + 2);
	if (unlikely(!work)) {
		err = -ENOMEM;
		goto error;
	}

	/* get newly allocated space for scatter/gather list */
	sg = wa_sg(work);

	/*
	 * sg table:
	 * 0: pkt_op, wire nonce (AD, len=OVPN_OP_SIZE_V2+NONCE_WIRE_SIZE),
	 * 1, 2, 3, ...: payload,
	 * n: auth_tag (len=auth_tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* packet op is head of additional data */
	if (opcode == OVPN_DATA_V2)
		sg_set_buf(sg, skb->data, OVPN_OP_SIZE_V2 + NONCE_WIRE_SIZE);
	else
		sg_set_buf(sg, skb->data + OVPN_OP_SIZE_V1, NONCE_WIRE_SIZE);

	/* build scatterlist to decrypt packet payload */
	{
		unsigned int nfrags_check;
		nfrags_check = skb_to_sgvec_nomark(skb, sg + 1, payload_offset, payload_len);
		if (unlikely(nfrags != nfrags_check)) {
			err = -OVPN_ERR_NFRAGS;
			goto error_free;
		}
	}

	/* append auth_tag onto scatterlist */
	sg_set_buf(sg + nfrags + 1, skb->data + opsize + NONCE_WIRE_SIZE, auth_tag_size);

	/* copy nonce into IV buffer */
	memcpy(wa_iv(work), skb->data + opsize, NONCE_WIRE_SIZE);
	memcpy(wa_iv(work) + NONCE_WIRE_SIZE,
	       cc->u.ae.nonce_tail_recv.u8,
	       sizeof(struct ovpn_nonce_tail));

#if DEBUG_CRYPTO >= 1
	ovpn_sg_dump("AEAD-D ", sg, nfrags + 2, true);
#endif

	/* finish workspace initialization and set pointer
	   in private skb control buffer */
	work->w.cc = cc;
	work->callback = callback;
	work->u.d.pktid_offset = opsize;
	work->u.d.payload_offset = payload_offset;
	*OVPN_AEAD_WORK_SKB_CB(skb) = work;

	/* setup async crypto operation */
	aead_request_set_tfm(wa_req(work), cc->u.ae.decrypt);
	aead_request_set_callback(wa_req(work), 0, ovpn_aead_decrypt_done, skb);
	aead_request_set_crypt(wa_req(work), sg, sg,
			       payload_len + auth_tag_size, wa_iv(work));
	aead_request_set_ad(wa_req(work), (opcode == OVPN_DATA_V2 ? OVPN_OP_SIZE_V2 : 0) + NONCE_WIRE_SIZE);

	/* decrypt it */
	err = crypto_aead_decrypt(wa_req(work));

	if (likely(err != -EINPROGRESS))
		ovpn_aead_decrypt_done2(skb, &err); /* synchronous */

	return err;

error_free:
	kfree(work);
error:
	*OVPN_AEAD_WORK_SKB_CB(skb) = NULL;
	return err;
}

/*
 * All methods below this point, unless otherwise indicated, are called
 * from process context with config_mutex held.
 */

/*
 * Initialize a struct crypto_aead object
 */
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
		ovpn_debug(KERN_ERR, "%s crypto_alloc_aead failed, err=%d\n",
			   title, ret);
		aead = NULL;
		goto error;
	}

	ret = crypto_aead_setkey(aead, key, keylen);
	if (ret) {
		ovpn_debug(KERN_ERR,
			   "%s crypto_aead_setkey size=%u failed, err=%d\n",
			   title, keylen, ret);
		goto error;
	}

	ret = crypto_aead_setauthsize(aead, auth_tag_size);
	if (ret) {
		ovpn_debug(KERN_ERR,
			   "%s crypto_aead_setauthsize failed, err=%d\n", title,
			   ret);
		goto error;
	}

	/* basic AEAD assumption */
	if (EXPECTED_IV_SIZE != crypto_aead_ivsize(aead)) {
		ovpn_debug(KERN_INFO, "%s IV size must be %d\n", title, EXPECTED_IV_SIZE);
		ret = -OVPN_ERR_IV_SIZE;
		goto error;
	}

#if DEBUG_CRYPTO >= 1
	ovpn_debug(KERN_INFO, "********* Cipher %s (%s)\n", alg_name, title);
	ovpn_debug(KERN_INFO, "*** IV size=%u\n", crypto_aead_ivsize(aead));
	ovpn_debug(KERN_INFO, "*** req size=%u\n", crypto_aead_reqsize(aead));
	ovpn_debug(KERN_INFO, "*** block size=%u\n", crypto_aead_blocksize(aead));
	ovpn_debug(KERN_INFO, "*** auth size=%u\n", crypto_aead_authsize(aead));
	ovpn_debug(KERN_INFO, "*** alignmask=0x%x\n", crypto_aead_alignmask(aead));
#endif

	return aead;

error:
	crypto_free_aead(aead);
	return ERR_PTR(ret);
}

static void ovpn_aead_crypto_context_destroy(struct ovpn_crypto_context *cc)
{
	if (!cc)
		return;

	crypto_free_aead(cc->u.ae.encrypt);
	crypto_free_aead(cc->u.ae.decrypt);
	ovpn_peer_put(cc->peer);
	kfree(cc);
}

static struct ovpn_crypto_context *
ovpn_aead_crypto_context_init(enum ovpn_cipher_alg alg,
			      const unsigned char *encrypt_key,
			      unsigned int encrypt_keylen,
			      const unsigned char *decrypt_key,
			      unsigned int decrypt_keylen,
			      const unsigned char *encrypt_nonce_tail, /* 4 bytes */
			      unsigned int encrypt_nonce_tail_len,
			      const unsigned char *decrypt_nonce_tail, /* 4 bytes */
			      unsigned int decrypt_nonce_tail_len,
			      struct ovpn_peer *peer)
{
	struct ovpn_crypto_context *cc = NULL;
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

	/* build the crypto context */
	cc = kmalloc(sizeof(*cc), GFP_KERNEL);
	if (!cc)
		return ERR_PTR(-ENOMEM);

	cc->peer = NULL;
	cc->ops = &ovpn_aead_ops;
	cc->u.ae.encrypt = NULL;
	cc->u.ae.decrypt = NULL;
	kref_init(&cc->refcount);

	/* grab a reference to peer */
	if (!ovpn_peer_hold(peer)) {
		ret = -ENOENT;
		goto destroy_cc;
	}

	cc->peer = peer;

	cc->u.ae.encrypt = ovpn_aead_init("encrypt", alg_name, encrypt_key,
					  encrypt_keylen);
	if (IS_ERR(cc->u.ae.encrypt)) {
		ret = PTR_ERR(cc->u.ae.encrypt);
		cc->u.ae.encrypt = NULL;
		goto destroy_cc;
	}
	cc->u.ae.decrypt = ovpn_aead_init("decrypt", alg_name, decrypt_key,
					  decrypt_keylen);
	if (IS_ERR(cc->u.ae.decrypt)) {
		ret = PTR_ERR(cc->u.ae.decrypt);
		cc->u.ae.decrypt = NULL;
		goto destroy_cc;
	}

	if (sizeof(struct ovpn_nonce_tail) != encrypt_nonce_tail_len ||
	    sizeof(struct ovpn_nonce_tail) != decrypt_nonce_tail_len) {
		ret = -EINVAL;
		goto destroy_cc;
	}

	memcpy(cc->u.ae.nonce_tail_xmit.u8, encrypt_nonce_tail,
	       sizeof(struct ovpn_nonce_tail));
	memcpy(cc->u.ae.nonce_tail_recv.u8, decrypt_nonce_tail,
	       sizeof(struct ovpn_nonce_tail));

	/* init packet ID generation/validation */
	ovpn_pktid_xmit_init(&cc->pid_xmit);
	ovpn_pktid_recv_init(&cc->pid_recv);

	return cc;

destroy_cc:
	ovpn_aead_crypto_context_destroy(cc);
	return ERR_PTR(ret);
}

static struct ovpn_crypto_context *
ovpn_aead_crypto_context_new(const struct ovpn_key_config *kc, int *key_id,
			     struct ovpn_peer *peer)
{
	struct ovpn_crypto_context *cc;

	/* sometimes caller wants to wipe context */
	if (!kc) {
		*key_id = -1;
		return NULL;
	}

	cc = ovpn_aead_crypto_context_init(kc->cipher_alg,
					   kc->encrypt.cipher_key,
					   kc->encrypt.cipher_key_size,
					   kc->decrypt.cipher_key,
					   kc->decrypt.cipher_key_size,
					   kc->encrypt.nonce_tail,
					   kc->encrypt.nonce_tail_size,
					   kc->decrypt.nonce_tail,
					   kc->decrypt.nonce_tail_size, peer);
	if (!IS_ERR(cc))
		*key_id = kc->key_id;

	return cc;
}

static int ovpn_aead_encap_overhead(const struct ovpn_crypto_context *cc)
{
	return  OVPN_OP_SIZE_V2 +                        /* OP header size */
		4 +                                      /* Packet ID */
		crypto_aead_authsize(cc->u.ae.encrypt) + /* Auth Tag */
		OVPN_COMPRESS_V2_MAX_HEAD;               /* Compression V2 header */
}

const struct ovpn_crypto_ops ovpn_aead_ops = {
	.encrypt     = ovpn_aead_encrypt,
	.decrypt     = ovpn_aead_decrypt,
	.new         = ovpn_aead_crypto_context_new,
	.destroy     = ovpn_aead_crypto_context_destroy,
	.encap_overhead = ovpn_aead_encap_overhead,
	.use_hmac    = false,
};
