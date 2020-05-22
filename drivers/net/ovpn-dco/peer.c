// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include "ovpn.h"
#include "bind.h"
#include "crypto.h"
#include "peer.h"

#include <linux/timer.h>
#include <linux/workqueue.h>

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

static void ovpn_peer_ping(struct timer_list *t)
{
	struct ovpn_peer *peer = from_timer(peer, t, keepalive_xmit);

	rcu_read_lock();
	pr_debug("sending ping to peer %pIScp\n",
		 &rcu_dereference(peer->bind)->sapair.remote.u);
	rcu_read_unlock();

	ovpn_keepalive_xmit(peer);
}

static void ovpn_peer_expire(struct timer_list *t)
{
	struct ovpn_peer *tmp, *peer = from_timer(peer, t, keepalive_recv);
	struct ovpn_struct *ovpn;

	rcu_read_lock();
	pr_debug("peer expired: %pIScp\n",
		 &rcu_dereference(peer->bind)->sapair.remote.u);
	rcu_read_unlock();

	ovpn = peer->ovpn;
	if (!ovpn)
		return;

	spin_lock_bh(&ovpn->lock);
	tmp = rcu_dereference_protected(ovpn->peer,
					lockdep_is_held(&ovpn->lock));
	if (tmp == peer) {
		rcu_assign_pointer(ovpn->peer, NULL);
		ovpn_peer_delete(peer);
	}
	spin_unlock_bh(&ovpn->lock);
}

/* Construct a new peer */
static struct ovpn_peer *ovpn_peer_new(struct ovpn_struct *ovpn)
{
	struct ovpn_peer *peer;
	int ret;

	/* alloc and init peer object */
	peer = kmalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer)
		return ERR_PTR(-ENOMEM);

	peer->halt = false;
	RCU_INIT_POINTER(peer->bind, NULL);
	ovpn_crypto_state_init(&peer->crypto);
	spin_lock_init(&peer->lock);
	kref_init(&peer->refcount);
	ovpn_peer_stats_init(&peer->stats);

	INIT_WORK(&peer->encrypt_work, ovpn_encrypt_work);
	INIT_WORK(&peer->decrypt_work, ovpn_decrypt_work);

	ret = ptr_ring_init(&peer->tx_ring, OVPN_QUEUE_LEN, GFP_KERNEL);
	if (ret < 0) {
		pr_err("cannot allocate TX ring\n");
		goto err;
	}

	ret = ptr_ring_init(&peer->rx_ring, OVPN_QUEUE_LEN, GFP_KERNEL);
	if (ret < 0) {
		pr_err("cannot allocate RX ring\n");
		goto err_tx_ring;
	}

	peer->ovpn = ovpn;
	dev_hold(ovpn->dev);

	timer_setup(&peer->keepalive_xmit, ovpn_peer_ping, 0);
	timer_setup(&peer->keepalive_recv, ovpn_peer_expire, 0);

	return peer;
err_tx_ring:
	ptr_ring_cleanup(&peer->tx_ring, NULL);
err:
	kfree(peer);
	return NULL;
}

/* Reset the ovpn_sockaddr_pair associated with a peer */
int ovpn_peer_reset_sockaddr(struct ovpn_peer *peer,
			     const struct ovpn_sockaddr_pair *sapair)
{
	struct ovpn_bind *bind;

	/* create new ovpn_bind object */
	bind = ovpn_bind_from_sockaddr_pair(sapair);
	if (IS_ERR(bind))
		return PTR_ERR(bind);

	/* set binding */
	ovpn_bind_reset(peer, bind);

	return 0;
}

static void ovpn_peer_timer_delete_all(struct ovpn_peer *peer)
{
	del_timer_sync(&peer->keepalive_xmit);
	del_timer_sync(&peer->keepalive_recv);
}

void ovpn_peer_release(struct ovpn_peer *peer)
{
	ovpn_bind_reset(peer, NULL);
	ovpn_peer_timer_delete_all(peer);

	WARN_ON(!__ptr_ring_empty(&peer->tx_ring));
	ptr_ring_cleanup(&peer->tx_ring, NULL);
	WARN_ON(!__ptr_ring_empty(&peer->rx_ring));
	ptr_ring_cleanup(&peer->rx_ring, NULL);

	dev_put(peer->ovpn->dev);

	kfree(peer);
}

static void ovpn_peer_release_rcu(struct rcu_head *head)
{
	struct ovpn_peer *peer = container_of(head, struct ovpn_peer, rcu);

	ovpn_crypto_state_release(&peer->crypto);
	ovpn_peer_release(peer);
}

/* Use with kref_put calls, when releasing refcount
 * on ovpn_peer objects.  This method should only
 * be called from process context with config_mutex held.
 */
void ovpn_peer_release_kref(struct kref *kref)
{
	struct ovpn_peer *peer = container_of(kref, struct ovpn_peer, refcount);

	call_rcu(&peer->rcu, ovpn_peer_release_rcu);
}

/* Delete a peer, consuming the original +1 refcount that
 * the object was created with.  Deletion may be deferred
 * if other objects hold references to the peer.
 */
void ovpn_peer_delete(struct ovpn_peer *peer)
{
	if (peer->halt)
		return;

	peer->halt = true;
	ovpn_peer_put(peer);
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

/* Configure keepalive parameters */
void ovpn_peer_keepalive_set(struct ovpn_peer *peer, u32 interval, u32 timeout)
{
	u32 delta;

	rcu_read_lock();
	pr_debug("scheduling keepalive for %pIScp: interval=%u timeout=%u\n",
		 &rcu_dereference(peer->bind)->sapair.remote.u, interval,
		 timeout);
	rcu_read_unlock();

	peer->keepalive_interval = interval;
	delta = msecs_to_jiffies(interval * MSEC_PER_SEC);
	mod_timer(&peer->keepalive_xmit, jiffies + delta);

	peer->keepalive_timeout = timeout;
	delta = msecs_to_jiffies(timeout * MSEC_PER_SEC);
	mod_timer(&peer->keepalive_recv, jiffies + delta);
}
