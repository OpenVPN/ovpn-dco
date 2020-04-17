/* SPDX-License-Identifier: GPL-2.0-only */
/* OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNPEER_H_
#define _NET_OVPN_DCO_OVPNPEER_H_

#include "addr.h"
#include "bind.h"
#include "sock.h"
#include "stats.h"
#include "timer.h"

struct ovpn_peer {
	struct ovpn_struct *ovpn;

	struct socket *sock;

	/* our crypto context, protected by mutex */
	struct ovpn_crypto_state crypto;

	/* our binding to peer */
	struct ovpn_bind __rcu *bind;

	/* time in future when we will transmit a keepalive
	 * (subject to continuous change)
	 */
	struct ovpn_timer keepalive_xmit;

	/* time in future when we must have received a packet from
	 * peer or we will timeout session
	 */
	struct ovpn_timer keepalive_expire;

	/* OVPN_STATUS_(ACTIVE|KEEPALIVE_TIMEOUT|EXPLICIT_EXIT) */
	unsigned char status;

	/* true if ovpn_peer_mark_delete was called */
	bool halt;

	/* per-peer rx/tx stats */
	struct ovpn_peer_stats stats;

	/* used for bind, keepalive_xmit, keepalive_expire */
	spinlock_t lock;

	/* used for crypto context */
	struct mutex mutex;

	/* needed because crypto methods can go async */
	struct kref refcount;

	/* needed to free a peer in an RCU safe way */
	struct rcu_head rcu;
};

int ovpn_update_peer_by_sockaddr_pc(struct ovpn_peer *peer);
void ovpn_peer_release_kref(struct kref *kref);
void ovpn_peer_release(struct ovpn_peer *peer);

struct ovpn_peer *ovpn_peer_get(struct ovpn_struct *ovpn);

static inline bool ovpn_peer_hold(struct ovpn_peer *peer)
{
	return kref_get_unless_zero(&peer->refcount);
}

static inline void ovpn_peer_put(struct ovpn_peer *peer)
{
	kref_put(&peer->refcount, ovpn_peer_release_kref);
}

static inline void ovpn_peer_update_keepalive_expire(struct ovpn_peer *peer)
{
	ovpn_timer_event(&peer->keepalive_expire);
}

void ovpn_peer_update_keepalive_xmit(struct ovpn_peer *peer);

struct ovpn_peer *
ovpn_peer_new_with_sockaddr(struct ovpn_struct *ovpn,
			    const struct ovpn_sockaddr_pair *sapair);

void ovpn_peer_delete(struct ovpn_peer *peer);

int ovpn_peer_reset_sockaddr(struct ovpn_peer *peer,
			     const struct ovpn_sockaddr_pair *sapair);

int ovpn_peer_xmit_explicit_exit_notify(struct ovpn_peer *peer)
	__must_hold(ovpn_config_mutex);

void ovpn_peer_set_keepalive(struct ovpn_peer *peer,
			     const unsigned int keepalive_ping,
			     const unsigned int keepalive_timeout);

#endif /* _NET_OVPN_DCO_OVPNPEER_H_ */
