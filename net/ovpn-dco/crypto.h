// SPDX-License-Identifier: GPL-2.0-only
/*
 *  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */


#ifndef _NET_OVPN_DCO_OVPNCRYPTO_H_
#define _NET_OVPN_DCO_OVPNCRYPTO_H_

#include "main.h"
#include "pktid.h"

#include <uapi/linux/ovpn_dco.h>
#include <linux/skbuff.h>


struct ovpn_peer;
struct ovpn_crypto_context;

/* info needed for both encrypt and decrypt directions */
struct ovpn_key_direction {
	const unsigned char *cipher_key;
	unsigned int cipher_key_size;
	const unsigned char *hmac_key;  /* not used for GCM modes */
	unsigned int hmac_key_size;     /* not used for GCM modes */
	unsigned char nonce_tail[12];   /* only needed for GCM modes */
	__u64 data_limit;               /* per-key bytes limit if >0, not used for GCM modes */
};

/* all info for a particular symmetric key (primary or secondary) */
struct ovpn_key_config {
	enum ovpn_cipher_alg cipher_alg;
	enum ovpn_hmac_alg hmac_alg;          /* not used for GCM modes */
	u16 key_id;
	struct ovpn_key_direction encrypt;
	struct ovpn_key_direction decrypt;
};

struct ovpn_crypto_ops {
	int (*encrypt)(struct ovpn_crypto_context *cc,
		       struct sk_buff *skb,
		       unsigned int net_headroom,
		       unsigned int key_id,
		       void (*callback)(struct sk_buff *, int err));

	int (*decrypt)(struct ovpn_crypto_context *cc,
		       struct sk_buff *skb,
		       unsigned int key_id,
		       unsigned int op,
		       void (*callback)(struct sk_buff *, int err));

	struct ovpn_crypto_context *(*new)(const struct ovpn_key_config *kc,
					   int *key_id,
					   struct ovpn_peer *peer,
					   int *err);

	void (*destroy)(struct ovpn_crypto_context *cc);

	int (*encap_overhead)(const struct ovpn_crypto_context *cc);

	bool use_hmac;
};

struct ovpn_crypto_context {
	const struct ovpn_crypto_ops *ops;
	struct ovpn_peer *peer;          /* backref to peer */
	int remote_peer_id;              /* remote peer ID used to reference us (-1 to disable) */

	union {
		/* aead mode */
		struct {
			struct crypto_aead *encrypt;
			struct crypto_aead *decrypt;
			struct ovpn_nonce_tail nonce_tail_xmit;
			struct ovpn_nonce_tail nonce_tail_recv;
		} ae;

		/* cbc/hmac mode */
		struct {
			struct crypto_skcipher *cipher_encrypt;
			struct crypto_skcipher *cipher_decrypt;
			struct crypto_ahash *hmac_encrypt;
			struct crypto_ahash *hmac_decrypt;
			struct ovpn_crypto_data_limit* data_limit;
		} chm;
	} u;

	struct ovpn_pktid_recv pid_recv ____cacheline_aligned_in_smp;
	struct ovpn_pktid_xmit pid_xmit ____cacheline_aligned_in_smp;
	struct kref refcount;
	struct rcu_head rcu;
};

struct ovpn_crypto_context_pair {
	int primary_key_id;
	int secondary_key_id;
	struct ovpn_crypto_context *primary;
	struct ovpn_crypto_context *secondary;
	struct rcu_head rcu;
};

struct ovpn_crypto_state {
	struct ovpn_crypto_context_pair __rcu *ccp;
	const struct ovpn_crypto_ops *ops;
};

static inline void ovpn_crypto_state_init(struct ovpn_crypto_state *cs)
{
	RCU_INIT_POINTER(cs->ccp, NULL);
	cs->ops = NULL;
}

static inline bool ovpn_crypto_state_defined(const struct ovpn_crypto_state *cs)
{
	return rcu_access_pointer(cs->ccp) != NULL;
}

static inline struct ovpn_crypto_context *
ovpn_crypto_context_from_key_id(const struct ovpn_crypto_context_pair *ccp,
				const int key_id)
{
	if (ccp) {
		if (key_id == ccp->primary_key_id)
			return ccp->primary;
		else if (key_id == ccp->secondary_key_id)
			return ccp->secondary;
	}
	return NULL;
}

/* rcu_read_lock must be held */
static inline struct ovpn_crypto_context *
ovpn_crypto_context_from_state(const struct ovpn_crypto_state *cs,
			       const int key_id)
{
	const struct ovpn_crypto_context_pair *ccp = rcu_dereference(cs->ccp);
	return ovpn_crypto_context_from_key_id(ccp, key_id);
}

/* rcu_read_lock must be held */
static inline struct ovpn_crypto_context *
ovpn_crypto_context_primary(const struct ovpn_crypto_state *cs,
			    int *key_id)
{
	const struct ovpn_crypto_context_pair *ccp = rcu_dereference(cs->ccp);
	if (ccp) {
		*key_id = ccp->primary_key_id;
		return ccp->primary;
	} else
		return NULL;
}

/*
 * Return true if this crypto error should be considered fatal
 * for TCP transport sessions.
 */
static inline bool ovpn_crypto_err_fatal_for_tcp(const int err)
{
	switch (-err) {
	case OVPN_ERR_DECRYPTION_FAILED:
	case OVPN_ERR_HMAC:
	case OVPN_ERR_PKCS7_PADDING:
	case OVPN_ERR_PKTID_WRAP:
		return true;
	default:
		return false;
	}
}

void ovpn_crypto_context_release(struct kref *kref);

static inline bool ovpn_crypto_context_hold(struct ovpn_crypto_context *cc)
{
	return kref_get_unless_zero(&cc->refcount);
}

static inline void ovpn_crypto_context_put(struct ovpn_crypto_context *cc)
{
	kref_put(&cc->refcount, ovpn_crypto_context_release);
}

const struct ovpn_crypto_ops *
ovpn_crypto_state_select_family(struct ovpn_peer *peer,
				const struct ovpn_peer_keys_reset *pkr,
				int *err);

int ovpn_crypto_state_reset(struct ovpn_crypto_state *cs,
			    const struct ovpn_peer_keys_reset *pkr,
			    struct ovpn_peer *peer);

int ovpn_crypto_encap_overhead(const struct ovpn_crypto_state *cs);

void ovpn_crypto_state_release(struct ovpn_peer *peer);

void ovpn_peer_keys_reset_free(struct ovpn_peer_keys_reset *pkr);
void ovpn_key_config_free(struct ovpn_key_config *kc);

#endif /* _NET_OVPN_DCO_OVPNCRYPTO_H_ */
