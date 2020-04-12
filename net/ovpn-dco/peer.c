// SPDX-License-Identifier: GPL-2.0-only
/*
 *  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include "ovpn.h"
#include "bind.h"
#include "crypto.h"
//#include "ovpnerrcat.h"
//#include "ovpnmisc.h"
//#include "ovpnnotify.h"
//#include "ovpnpeerid.h"
//#include "ovpnrhash.h"
//#include "route.h"
//#include "ovpntcp.h"

static void __ovpn_peer_timer_delete_all(struct ovpn_peer *peer);
static void __ovpn_peer_keepalive_xmit_handler(struct timer_list *arg);
static void __ovpn_peer_keepalive_expire_handler(struct timer_list *arg);

struct ovpn_peer *ovpn_peer_get(struct ovpn_struct *ovpn)
{
	struct ovpn_peer *peer;

	rcu_read_lock();
	peer = rcu_dereference(ovpn->peer);
	if (peer && !ovpn_peer_hold(peer))
		peer = NULL;
	rcu_read_unlock();

	return peer;
}

/*
 * Construct a new peer.
 */
static struct ovpn_peer *ovpn_peer_new(struct ovpn_struct *ovpn)
{
	struct ovpn_peer *peer = NULL;

	/* alloc and init peer object */
        peer = (struct ovpn_peer *)kmalloc(sizeof(struct ovpn_peer), GFP_KERNEL);
	if (!peer)
		return ERR_PTR(-ENOMEM);

	peer->status = OVPN_STATUS_ACTIVE;
	peer->halt = false;
	RCU_INIT_POINTER(peer->bind, NULL);
	ovpn_crypto_state_init(&peer->crypto);
	spin_lock_init(&peer->lock);
	mutex_init(&peer->mutex);
	kref_init(&peer->refcount);
	ovpn_peer_stats_init(&peer->stats);

	peer->ovpn = ovpn;
	dev_hold(ovpn->dev);

	/* init keepalive timers */
	ovpn_timer_init(&peer->keepalive_xmit,
			__ovpn_peer_keepalive_xmit_handler);
	ovpn_timer_init(&peer->keepalive_expire,
			__ovpn_peer_keepalive_expire_handler);

	return peer;
}

/*
 * Reset the ovpn_sockaddr_pair associated with a peer.
 */
int ovpn_peer_reset_sockaddr(struct ovpn_peer *peer,
			     const struct ovpn_sockaddr_pair *sapair)
{
	struct ovpn_bind *bind;

	/* create new ovpn_bind object */
	bind = ovpn_bind_from_sockaddr_pair(sapair);
	if (unlikely(IS_ERR(bind)))
		return PTR_ERR(bind);

	/* set binding */
	ovpn_bind_reset(peer, bind);

	return 0;
}

void ovpn_peer_release(struct ovpn_peer *peer)
{
	ovpn_bind_reset(peer, NULL);
	__ovpn_peer_timer_delete_all(peer);
	ovpn_crypto_state_release(peer);

	dev_put(peer->ovpn->dev);

	mutex_destroy(&peer->mutex);
	kfree(peer);
}

static void ovpn_peer_release_rcu(struct rcu_head *head)
{
	struct ovpn_peer *peer = container_of(head, struct ovpn_peer, rcu);
	ovpn_peer_release(peer);
}

/*
 * Use with kref_put calls, when releasing refcount
 * on ovpn_peer objects.  This method should only
 * be called from process context with config_mutex held.
 */
void ovpn_peer_release_kref(struct kref *kref)
{
	struct ovpn_peer *peer = container_of(kref, struct ovpn_peer, refcount);
	call_rcu(&peer->rcu, ovpn_peer_release_rcu);
}

/*
 * Delete a peer, consuming the original +1 refcount that
 * the object was created with.  Deletion may be deferred
 * if other objects hold references to the peer.
 */
void ovpn_peer_delete(struct ovpn_peer *peer)
{
	if (!peer->halt) {
		peer->halt = true;
		ovpn_peer_put(peer);
	}
}


struct ovpn_peer *
ovpn_peer_new_with_sockaddr(struct ovpn_struct *ovpn,
			    const struct ovpn_sockaddr_pair *sapair)
{
	struct ovpn_peer *peer;
	int ret;

	/* create new peer */
	peer = ovpn_peer_new(ovpn);
	if (IS_ERR(peer))
		return peer;

	/* set peer sockaddr */
	ret = ovpn_peer_reset_sockaddr(peer, sapair);
	if (ret < 0) {
		ovpn_peer_release(peer);
		return ERR_PTR(ret);
	}

	return peer;
}

/*
 * Keepalive timer delete/schedule.
 */

static void __ovpn_peer_timer_delete(struct ovpn_peer *peer,
				     struct ovpn_timer *t)
{
	if (ovpn_timer_delete(t, &peer->lock))
		ovpn_peer_put(peer);
}

static void __ovpn_peer_timer_delete_all(struct ovpn_peer *peer)
{
	__ovpn_peer_timer_delete(peer, &peer->keepalive_xmit);
	__ovpn_peer_timer_delete(peer, &peer->keepalive_expire);
}

static void __ovpn_peer_timer_schedule(struct ovpn_peer *peer,
				       struct ovpn_timer *t,
				       int rcdelta)
{
	if (!ovpn_timer_schedule(t, &peer->lock))
		++rcdelta;
	switch (rcdelta) {
	case 0:
		break;
	case 1:
		if (!ovpn_peer_hold(peer))
			ovpn_timer_delete(t, &peer->lock);
		break;
	case -1:
		ovpn_peer_put(peer);
		break;
	default:
		WARN_ON(1);
	}
}

/*
 * keepalive timer callbacks.
 * A reference is held on peer which the functions
 * may release prior to return.
 */

static void __ovpn_peer_keepalive_xmit_handler(struct timer_list *t)
{
	struct ovpn_peer *peer = from_ovpn_timer(peer, t, keepalive_xmit);

#if DEBUG_PING
	ovpn_dbg_ping_xmit(peer);
#endif
	ovpn_xmit_special(peer, ovpn_keepalive_message,
			  sizeof(ovpn_keepalive_message));
	__ovpn_peer_timer_schedule(peer, &peer->keepalive_xmit, -1);
}

static void __ovpn_peer_keepalive_expire_handler(struct timer_list *t)
{
	struct ovpn_peer *peer = from_ovpn_timer(peer, t, keepalive_expire);
#if DEBUG_PING
	printk("KEEPALIVE EXPIRE\n");
#endif
	ovpn_peer_put(peer);
}

/*
 * Update keepalive timers.
 * Called from softirq context.
 */

void ovpn_peer_update_keepalive_xmit(struct ovpn_peer *peer)
{
// if DEBUG_PING >= 2, normal outgoing traffic doesn't reset xmit timer
#if DEBUG_PING < 2
	ovpn_timer_event(&peer->keepalive_xmit);
#endif
}

/*
 * Configure keepalive parameters.
 * Called from process context.
 * Peer is generally held by RCU lock.
 */
void ovpn_peer_set_keepalive(struct ovpn_peer *peer,
			     const unsigned keepalive_ping,
			     const unsigned keepalive_timeout)
{
	ovpn_timer_set_period(&peer->keepalive_xmit, keepalive_ping);
	__ovpn_peer_timer_schedule(peer, &peer->keepalive_xmit, 0);

	ovpn_timer_set_period(&peer->keepalive_expire, keepalive_timeout);
	__ovpn_peer_timer_schedule(peer, &peer->keepalive_expire, 0);
}

/*
 * Transmit explicit exit notification.
 * Called from process context.
 */
int ovpn_peer_xmit_explicit_exit_notify(struct ovpn_peer *peer)
	__must_hold(ovpn_config_mutex)
{
	lockdep_assert_held(&ovpn_config_mutex);
	local_bh_disable(); /* simulate softirq context for ovpn_xmit_special */
	preempt_disable();
	ovpn_xmit_special(peer, ovpn_explicit_exit_notify_message,
			  sizeof(ovpn_explicit_exit_notify_message));
	preempt_enable();
	local_bh_enable();
	return 0;
}
