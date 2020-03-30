// SPDX-License-Identifier: GPL-2.0-only
/*
 *  OpenVPN data channel accelerator
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

/*
 * Helper method for ovpn_crypto_state_reset to create a new
 * ovpn_crypto_context.
 */
static struct ovpn_crypto_context *
ovpn_cc_new(const struct ovpn_crypto_ops *ops, const struct ovpn_key_config *kc,
	    int *key_id, struct ovpn_peer *peer)
{
	struct ovpn_crypto_context *cc;
	int err = 0;

	cc = ops->new(kc, key_id, peer, &err);
	if (!cc)
		return NULL;

	return cc;
}

/*
 * Destroy an ovpn_crypto_context.
 * If object has been visible to RCU readers, this method
 * should only be called one RCU grace period after
 * visibility has been removed.
 */
static void __ovpn_cc_destroy_rcu(struct rcu_head *head)
{
	struct ovpn_crypto_context *cc = container_of(head, struct ovpn_crypto_context, rcu);
	struct ovpn_peer *peer = cc->peer;

	ovpn_peer_put(peer);

	cc->ops->destroy(cc);
}

void ovpn_crypto_context_release(struct kref *kref)
{
	struct ovpn_crypto_context *cc = container_of(kref,
						      struct ovpn_crypto_context,
						      refcount);
	call_rcu(&cc->rcu, __ovpn_cc_destroy_rcu);
}

static void
ovpn_crypto_context_pair_release(struct ovpn_crypto_context_pair *ccp)
{
	if (ccp->primary)
		ovpn_crypto_context_put(ccp->primary);
	if (ccp->secondary)
		ovpn_crypto_context_put(ccp->secondary);
	kfree_rcu(ccp, rcu);
}

void ovpn_crypto_state_release(struct ovpn_peer *peer)
{
	struct ovpn_crypto_context_pair *ccp;

	mutex_lock(&peer->mutex);
	ccp = rcu_dereference_protected(peer->crypto.ccp,
					lockdep_is_held(&peer->mutex));
	if (ccp) {
		RCU_INIT_POINTER(peer->crypto.ccp, NULL);
		ovpn_crypto_context_pair_release(ccp);
	}
	mutex_unlock(&peer->mutex);
}

int ovpn_crypto_encap_overhead(const struct ovpn_crypto_state *cs)
{
	const struct ovpn_crypto_context *cc;
	struct ovpn_crypto_context_pair *ccp;
	int ret;

	rcu_read_lock();

	ccp = rcu_dereference(cs->ccp);
	if (!ccp) {
		rcu_read_unlock();
		return -OVPN_ERR_NO_CRYPTO_CONTEXT;
	}
	cc = ccp->primary;
	if (!cc) {
		rcu_read_unlock();
		return -OVPN_ERR_NO_CRYPTO_CONTEXT;
	}
	ret = cc->ops->encap_overhead(cc);

	rcu_read_unlock();
	return ret;
}

void ovpn_key_config_free(struct ovpn_key_config *kc)
{
	if (!kc)
		return;

	kfree(kc->encrypt.cipher_key);
	kfree(kc->decrypt.cipher_key);
	kfree(kc->encrypt.hmac_key);
	kfree(kc->decrypt.hmac_key);
	kfree(kc);
}

void ovpn_peer_keys_reset_free(struct ovpn_peer_keys_reset *pkr)
{
	ovpn_key_config_free(pkr->primary);
	ovpn_key_config_free(pkr->secondary);
}

/*
 * Reset the ovpn_crypto_state object in a way that is atomic
 * to RCU readers.  Should be called from user context
 * with peer->mutex held.
 */
int ovpn_crypto_state_reset(struct ovpn_crypto_state *cs,
			    const struct ovpn_peer_keys_reset *pkr,
			    struct ovpn_peer *peer)
	__must_hold(peer->mutex)
{
	struct ovpn_crypto_context_pair *oldc;
	struct ovpn_crypto_context_pair *newc;

	lockdep_assert_held(&peer->mutex);

	newc = kzalloc(sizeof(struct ovpn_crypto_context_pair), GFP_KERNEL);
	if (unlikely(!newc))
		return -ENOMEM;

	newc->primary_key_id = newc->secondary_key_id = -1;
	oldc = rcu_dereference_protected(cs->ccp, lockdep_is_held(&peer->mutex));

	newc->primary = ovpn_cc_new(cs->ops, pkr->primary,
				    &newc->primary_key_id, peer);
	if (!newc->primary)
		goto free_cc;

	newc->secondary = ovpn_cc_new(cs->ops, pkr->secondary,
				      &newc->secondary_key_id, peer);
	if (!newc->secondary)
		goto free_cc;

	printk("*** NEW CRYPTO CONTEXT pri=%d sec=%d\n",
	       newc->primary_key_id, newc->secondary_key_id);

	rcu_assign_pointer(cs->ccp, newc);
	if (oldc)
		ovpn_crypto_context_pair_release(oldc);

	return 0;
free_cc:
	ovpn_crypto_context_pair_release(newc);
	return -ENOMEM;
}

static const struct ovpn_crypto_ops *
ovpn_crypto_select_family(const struct ovpn_peer_keys_reset *pkr,
			  int *err)
{
	switch (pkr->crypto_family) {
	case OVPN_CRYPTO_FAMILY_UNDEF:
		return NULL;
	case OVPN_CRYPTO_FAMILY_AEAD:
		return &ovpn_aead_ops;
//	case OVPN_CRYPTO_FAMILY_CBC_HMAC:
//		return &ovpn_chm_ops;
	default:
		*err = -OVPN_ERR_BAD_CRYPTO_FAMILY;
		return NULL;
	}
}

const struct ovpn_crypto_ops *
ovpn_crypto_state_select_family(struct ovpn_peer *peer,
				const struct ovpn_peer_keys_reset *pkr,
				int *err)
	__must_hold(peer->mutex)
{
	const struct ovpn_crypto_ops *ops;
	const struct ovpn_crypto_ops *new_ops;

	lockdep_assert_held(&peer->mutex);

	new_ops = ovpn_crypto_select_family(pkr, err);
	if (!new_ops)
		return NULL;

	ops = peer->crypto.ops;
	if (ops && ops != new_ops) { /* family changed? */
		*err = -OVPN_ERR_BAD_CRYPTO_FAMILY;
		return NULL;
	}
	peer->crypto.ops = new_ops;

	return new_ops;
}
