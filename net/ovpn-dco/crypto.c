// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include "main.h"
#include "aead.h"
#include "crypto.h"
#include "peer.h"

#include <uapi/linux/ovpn_dco.h>

static struct ovpn_crypto_key_slot *
ovpn_ks_new(const struct ovpn_crypto_ops *ops, const struct ovpn_key_config *kc,
	    struct ovpn_peer *peer)
{
	return ops->new(kc, peer);
}

static void ovpn_ks_destroy_rcu(struct rcu_head *head)
{
	struct ovpn_crypto_key_slot *ks;

	ks = container_of(head, struct ovpn_crypto_key_slot, rcu);
	ks->ops->destroy(ks);
}

void ovpn_crypto_key_slot_release(struct kref *kref)
{
	struct ovpn_crypto_key_slot *ks;

	ks = container_of(kref, struct ovpn_crypto_key_slot, refcount);
	call_rcu(&ks->rcu, ovpn_ks_destroy_rcu);
}

void ovpn_crypto_state_release(struct ovpn_peer *peer)
{
	struct ovpn_crypto_key_slot *ks;

	mutex_lock(&peer->mutex);
	ks = rcu_dereference_protected(peer->crypto.primary,
				       lockdep_is_held(&peer->mutex));
	if (ks) {
		RCU_INIT_POINTER(peer->crypto.primary, NULL);
		ovpn_crypto_key_slot_put(ks);
	}

	ks = rcu_dereference_protected(peer->crypto.secondary,
				       lockdep_is_held(&peer->mutex));
	if (ks) {
		RCU_INIT_POINTER(peer->crypto.secondary, NULL);
		ovpn_crypto_key_slot_put(ks);
	}
	mutex_unlock(&peer->mutex);
}

int ovpn_crypto_encap_overhead(const struct ovpn_crypto_state *cs)
{
	const struct ovpn_crypto_key_slot *ks;
	int ret;

	rcu_read_lock();
	ks = rcu_dereference(cs->primary);
	if (!ks) {
		rcu_read_unlock();
		return -ENOENT;
	}
	ret = ks->ops->encap_overhead(ks);
	rcu_read_unlock();

	return ret;
}

/* Reset the ovpn_crypto_state object in a way that is atomic
 * to RCU readers.
 */
int ovpn_crypto_state_reset(struct ovpn_crypto_state *cs,
			    const struct ovpn_peer_key_reset *pkr,
			    struct ovpn_peer *peer)
	__must_hold(peer->mutex)
{
	struct ovpn_crypto_key_slot *old = NULL;
	struct ovpn_crypto_key_slot *new;

	lockdep_assert_held(&peer->mutex);

	new = ovpn_ks_new(cs->ops, &pkr->key, peer);
	if (IS_ERR(new))
		return PTR_ERR(new);

	new->remote_peer_id = pkr->remote_peer_id;

	switch (pkr->slot) {
	case OVPN_KEY_SLOT_PRIMARY:
		old = rcu_dereference_protected(cs->primary,
						lockdep_is_held(&peer->lock));
		rcu_assign_pointer(cs->primary, new);
		break;
	case OVPN_KEY_SLOT_SECONDARY:
		old = rcu_dereference_protected(cs->secondary,
						lockdep_is_held(&peer->lock));
		rcu_assign_pointer(cs->secondary, new);
		break;
	default:
		goto free_key;
	}

	pr_debug("*** NEW KEY INSTALLED id=%u remote_pid=%u\n",
		 new->key_id, new->remote_peer_id);

	if (old) {
		ovpn_crypto_key_slot_put(old);
	}

	return 0;
free_key:
	ovpn_crypto_key_slot_put(new);
	return -EINVAL;
}

void ovpn_crypto_key_slot_delete(struct ovpn_peer *peer,
				 enum ovpn_key_slot slot)
{
	struct ovpn_crypto_key_slot *ks = NULL;

	mutex_lock(&peer->mutex);
	switch (slot) {
	case OVPN_KEY_SLOT_PRIMARY:
		ks = rcu_dereference_protected(peer->crypto.primary,
					       lockdep_is_held(&peer->lock));
		RCU_INIT_POINTER(peer->crypto.primary, NULL);
		break;
	case OVPN_KEY_SLOT_SECONDARY:
		ks = rcu_dereference_protected(peer->crypto.secondary,
					       lockdep_is_held(&peer->lock));
		RCU_INIT_POINTER(peer->crypto.secondary, NULL);
		break;
	default:
		pr_warn("Invalid slot to release: %u\n", slot);
		break;
	}
	mutex_unlock(&peer->mutex);

	if (!ks) {
		pr_debug("Key slot already released: %u\n", slot);
		return;
	}

	ovpn_crypto_key_slot_put(ks);
}


static const struct ovpn_crypto_ops *
ovpn_crypto_select_family(const struct ovpn_peer_key_reset *pkr)
{
	switch (pkr->crypto_family) {
	case OVPN_CRYPTO_FAMILY_UNDEF:
		return NULL;
	case OVPN_CRYPTO_FAMILY_AEAD:
		return &ovpn_aead_ops;
//	case OVPN_CRYPTO_FAMILY_CBC_HMAC:
//		return &ovpn_chm_ops;
	default:
		return NULL;
	}
}

int ovpn_crypto_state_select_family(struct ovpn_peer *peer,
				    const struct ovpn_peer_key_reset *pkr)
	__must_hold(peer->lock)
{
	const struct ovpn_crypto_ops *new_ops;
	const struct ovpn_crypto_ops *ops;

	lockdep_assert_held(&peer->lock);

	new_ops = ovpn_crypto_select_family(pkr);
	if (!new_ops)
		return -EOPNOTSUPP;

	ops = peer->crypto.ops;
	if (ops && ops != new_ops) /* family changed? */
		return -EINVAL;

	peer->crypto.ops = new_ops;

	return 0;
}

enum ovpn_crypto_families
ovpn_keys_familiy_get(const struct ovpn_key_config *kc)
{
	switch (kc->cipher_alg) {
	case OVPN_CIPHER_ALG_AES_GCM:
		return OVPN_CRYPTO_FAMILY_AEAD;
	case OVPN_CIPHER_ALG_AES_CBC:
		return OVPN_CRYPTO_FAMILY_CBC_HMAC;
	default:
		return OVPN_CRYPTO_FAMILY_UNDEF;
	}
}
