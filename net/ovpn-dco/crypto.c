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

/* Helper method for ovpn_crypto_state_reset to create a new
 * ovpn_crypto_context.
 */
static struct ovpn_crypto_context *
ovpn_cc_new(const struct ovpn_crypto_ops *ops, const struct ovpn_key_config *kc,
	    int *key_id, struct ovpn_peer *peer)
{
	return ops->new(kc, key_id, peer);
}

/* Destroy an ovpn_crypto_context.
 * If object has been visible to RCU readers, this method
 * should only be called one RCU grace period after
 * visibility has been removed.
 */
static void __ovpn_cc_destroy_rcu(struct rcu_head *head)
{
	struct ovpn_crypto_context *cc;

	cc = container_of(head, struct ovpn_crypto_context, rcu);
	cc->ops->destroy(cc);
}

void ovpn_crypto_context_release(struct kref *kref)
{
	struct ovpn_crypto_context *cc;

	cc = container_of(kref, struct ovpn_crypto_context, refcount);
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

	spin_lock(&peer->lock);
	ccp = rcu_dereference_protected(peer->crypto.ccp,
					lockdep_is_held(&peer->lock));
	if (ccp) {
		RCU_INIT_POINTER(peer->crypto.ccp, NULL);
		ovpn_crypto_context_pair_release(ccp);
	}
	spin_unlock(&peer->lock);
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
		return -ENOENT;
	}
	cc = ccp->primary;
	if (!cc) {
		rcu_read_unlock();
		return -ENOENT;
	}
	ret = cc->ops->encap_overhead(cc);

	rcu_read_unlock();
	return ret;
}

/* Reset the ovpn_crypto_state object in a way that is atomic
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
	int ret;

	lockdep_assert_held(&peer->mutex);

	newc = kzalloc(sizeof(*newc), GFP_KERNEL);
	if (unlikely(!newc))
		return -ENOMEM;

	newc->primary_key_id = -1;
	newc->secondary_key_id = -1;
	oldc = rcu_dereference_protected(cs->ccp,
					 lockdep_is_held(&peer->mutex));

	if (pkr->primary_key_set) {
		newc->primary = ovpn_cc_new(cs->ops, &pkr->primary,
					    &newc->primary_key_id, peer);
		if (IS_ERR(newc->primary)) {
			ret = PTR_ERR(newc->primary);
			newc->primary = NULL;
			goto free_cc;
		}
		newc->primary->remote_peer_id = pkr->remote_peer_id;
	}

	if (pkr->secondary_key_set) {
		newc->secondary = ovpn_cc_new(cs->ops, &pkr->secondary,
					      &newc->secondary_key_id, peer);
		if (IS_ERR(newc->secondary)) {
			ret = PTR_ERR(newc->secondary);
			newc->secondary = NULL;
			goto free_cc;
		}
		newc->secondary->remote_peer_id = pkr->remote_peer_id;
	}

	pr_debug("*** NEW CRYPTO CONTEXT pri=%d sec=%d remote_pid=%u\n",
		 newc->primary_key_id, newc->secondary_key_id,
		 pkr->remote_peer_id);

	rcu_assign_pointer(cs->ccp, newc);
	if (oldc)
		ovpn_crypto_context_pair_release(oldc);

	return 0;
free_cc:
	ovpn_crypto_context_pair_release(newc);
	return ret;
}

static const struct ovpn_crypto_ops *
ovpn_crypto_select_family(const struct ovpn_peer_keys_reset *pkr)
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
				    const struct ovpn_peer_keys_reset *pkr)
	__must_hold(peer->mutex)
{
	const struct ovpn_crypto_ops *ops;
	const struct ovpn_crypto_ops *new_ops;

	lockdep_assert_held(&peer->mutex);

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
