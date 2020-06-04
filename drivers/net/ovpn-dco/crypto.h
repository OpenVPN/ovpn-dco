/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
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
struct ovpn_crypto_key_slot;

enum ovpn_crypto_families {
	OVPN_CRYPTO_FAMILY_UNDEF = 0,
	OVPN_CRYPTO_FAMILY_AEAD,
	OVPN_CRYPTO_FAMILY_CBC_HMAC,
};

/* info needed for both encrypt and decrypt directions */
struct ovpn_key_direction {
	const u8 *cipher_key;
	size_t cipher_key_size;
	const u8 *hmac_key; /* not used for GCM modes */
	size_t hmac_key_size; /* not used for GCM modes */
	const u8 *nonce_tail; /* only needed for GCM modes */
	size_t nonce_tail_size; /* only needed for GCM modes */
	u64 data_limit; /* per-key bytes limit if >0, not used for GCM modes */
};

/* all info for a particular symmetric key (primary or secondary) */
struct ovpn_key_config {
	enum ovpn_cipher_alg cipher_alg;
	enum ovpn_hmac_alg hmac_alg;          /* not used for GCM modes */
	u16 key_id;
	struct ovpn_key_direction encrypt;
	struct ovpn_key_direction decrypt;
};

/* used to pass settings from netlink to the crypto engine */
struct ovpn_peer_key_reset {
	u32 remote_peer_id;
	enum ovpn_key_slot slot;
	enum ovpn_crypto_families crypto_family;
	struct ovpn_key_config key;
};

struct ovpn_crypto_ops {
	int (*encrypt)(struct ovpn_crypto_key_slot *ks,
		       struct sk_buff *skb);

	int (*decrypt)(struct ovpn_crypto_key_slot *ks,
		       struct sk_buff *skb,
		       unsigned int op);

	struct ovpn_crypto_key_slot *(*new)(const struct ovpn_key_config *kc);

	void (*destroy)(struct ovpn_crypto_key_slot *ks);

	int (*encap_overhead)(const struct ovpn_crypto_key_slot *ks);

	bool use_hmac;
};

struct ovpn_crypto_key_slot {
	const struct ovpn_crypto_ops *ops;
	int remote_peer_id;
	int key_id;

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
			struct ovpn_crypto_data_limit *data_limit;
		} chm;
	} u;

	struct ovpn_pktid_recv pid_recv ____cacheline_aligned_in_smp;
	struct ovpn_pktid_xmit pid_xmit ____cacheline_aligned_in_smp;
	struct kref refcount;
	struct rcu_head rcu;
};

struct ovpn_crypto_state {
	struct ovpn_crypto_key_slot __rcu *primary;
	struct ovpn_crypto_key_slot __rcu *secondary;
	const struct ovpn_crypto_ops *ops;

	/* protects primary, secondary slots and ops */
	struct mutex mutex;
};

static inline bool ovpn_crypto_key_slot_hold(struct ovpn_crypto_key_slot *ks)
{
	return kref_get_unless_zero(&ks->refcount);
}

static inline void ovpn_crypto_state_init(struct ovpn_crypto_state *cs)
{
	RCU_INIT_POINTER(cs->primary, NULL);
	RCU_INIT_POINTER(cs->secondary, NULL);
	cs->ops = NULL;
	mutex_init(&cs->mutex);
}

static inline struct ovpn_crypto_key_slot *
ovpn_crypto_key_id_to_slot(const struct ovpn_crypto_state *cs, int key_id)
{
	struct ovpn_crypto_key_slot *ks;

	if (unlikely(!cs))
		return NULL;

	rcu_read_lock();
	ks = rcu_dereference(cs->primary);
	if (ks && ks->key_id == key_id) {
		if (unlikely(!ovpn_crypto_key_slot_hold(ks)))
			ks = NULL;
		goto out;
	}

	ks = rcu_dereference(cs->secondary);
	if (ks && ks->key_id == key_id) {
		if (unlikely(!ovpn_crypto_key_slot_hold(ks)))
			ks = NULL;
		goto out;
	}
out:
	rcu_read_unlock();

	return ks;
}

static inline struct ovpn_crypto_key_slot *
ovpn_crypto_key_slot_primary(const struct ovpn_crypto_state *cs)
{
	struct ovpn_crypto_key_slot *ks;

	rcu_read_lock();
	ks = rcu_dereference(cs->primary);
	if (unlikely(ks && !ovpn_crypto_key_slot_hold(ks)))
		ks = NULL;
	rcu_read_unlock();

	return ks;
}

void ovpn_crypto_key_slot_release(struct kref *kref);

static inline void ovpn_crypto_key_slot_put(struct ovpn_crypto_key_slot *ks)
{
	kref_put(&ks->refcount, ovpn_crypto_key_slot_release);
}

int ovpn_crypto_state_select_family(struct ovpn_crypto_state *cs,
				    const struct ovpn_peer_key_reset *pkr);

int ovpn_crypto_state_reset(struct ovpn_crypto_state *cs,
			    const struct ovpn_peer_key_reset *pkr);

void ovpn_crypto_key_slot_delete(struct ovpn_crypto_state *cs,
				 enum ovpn_key_slot slot);

int ovpn_crypto_encap_overhead(const struct ovpn_crypto_state *cs);

void ovpn_crypto_state_release(struct ovpn_crypto_state *cs);

void ovpn_key_config_free(struct ovpn_key_config *kc);

enum ovpn_crypto_families
ovpn_keys_familiy_get(const struct ovpn_key_config *kc);

void ovpn_crypto_key_slots_swap(struct ovpn_crypto_state *cs);

#endif /* _NET_OVPN_DCO_OVPNCRYPTO_H_ */
