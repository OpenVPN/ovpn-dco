/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

#include "ovpn.h"
#include "addr.h"
#include "bind.h"

#include <linux/types.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <net/sock.h>

/*
 * Given a remote/local sockaddr pair, compute the skb hash
 * and get a dst_entry so we can send packets to the remote.
 * Called from process context or softirq (must be indicated with
 * process_context bool).
 */
struct ovpn_bind *
ovpn_bind_from_sockaddr_pair(const struct ovpn_sockaddr_pair *pair)
{
	struct ovpn_bind *bind;
	int err;

	err = ovpn_sockaddr_pair_validate(pair);
	if (err < 0)
		return ERR_PTR(err);

	bind = kmalloc(sizeof(struct ovpn_bind), GFP_KERNEL);
	if (unlikely(!bind))
		return ERR_PTR(-ENOMEM);

	bind->sapair = *pair;

	return bind;
}

static void ovpn_bind_release(struct ovpn_bind *bind)
{
	kfree(bind);
}

static void ovpn_bind_release_rcu(struct rcu_head *head)
{
	struct ovpn_bind *bind = container_of(head, struct ovpn_bind, rcu);
	ovpn_bind_release(bind);
}

void ovpn_bind_state_init(struct ovpn_bind_state *obs)
{
	RCU_INIT_POINTER(obs->ob, NULL);
}

void ovpn_bind_state_reset(struct ovpn_bind_state *obs, spinlock_t *lock,
			   struct ovpn_bind *bind)
{
	struct ovpn_bind *old;

	spin_lock(lock);
	old = rcu_dereference_protected(obs->ob, lockdep_is_held(lock));
	rcu_assign_pointer(obs->ob, bind);
	spin_unlock(lock);
	if (old)
		call_rcu(&old->rcu, ovpn_bind_release_rcu);
}

/*
 * Save sockaddr of incoming packet.
 * rcu_read_lock must be held on entry but
 * will be released prior to exit.
 * Called in softirq context.
 */
void ovpn_bind_record_peer(struct ovpn_struct *ovpn,
			   struct ovpn_peer *peer, struct sk_buff *skb,
			   spinlock_t *lock)
{
	struct ovpn_sockaddr_pair sapair;
	struct ovpn_bind *bind;
	struct socket *sock;
	int err;

	ovpn_rcu_lockdep_assert_held();

	err = ovpn_sockaddr_pair_from_skb(&sapair, skb);
	if (unlikely(err < 0))
		goto error_unlock;

	sock = rcu_dereference(peer->sock);
	if (unlikely(!sock)) {
		err = -OVPN_ERR_NO_TRANSPORT_SOCK;
		goto error_unlock;
	}

	bind = ovpn_bind_from_sockaddr_pair(&sapair);
	if (unlikely(IS_ERR(bind))) {
		err = PTR_ERR(bind);
		goto error_unlock;
	}

	rcu_read_unlock();

	ovpn_bind_state_reset(&peer->bind, lock, bind);

	return;

error_unlock:
	rcu_read_unlock();
}

/*
 * Get the the ovpn_sockaddr_pair of the current binding and
 * save in sapair.  If binding is undefined, zero sapair.
 * Return true on success or false if binding is undefined.
 */
bool ovpn_bind_get_sockaddr_pair(const struct ovpn_bind_state *bs,
				 struct ovpn_sockaddr_pair *sapair)
{
	struct ovpn_bind *bind;
	bool ret;

	rcu_read_lock();
	bind = rcu_dereference(bs->ob);
	if (bind) {
		*sapair = bind->sapair;
		ret = true;
	} else {
		memset(sapair, 0, sizeof(*sapair));
		ret = false;
	}
	rcu_read_unlock();
	return ret;
}
