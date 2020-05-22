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

#include <linux/timer.h>
#include <linux/ptr_ring.h>

struct ovpn_peer {
	struct ovpn_struct *ovpn;

	/* work objects to handle encryption/decryption of packets.
	 * these works are queued on the ovpn->crypt_wq workqueue.
	 */
	struct work_struct encrypt_work;
	struct work_struct decrypt_work;

	struct ptr_ring tx_ring;
	struct ptr_ring rx_ring;

	struct socket *sock;

	/* our crypto state */
	struct ovpn_crypto_state crypto;

	/* our binding to peer, protected by spinlock */
	struct ovpn_bind __rcu *bind;

	/* timer used to send periodic ping messages to the other peer, if no
	 * other data was sent within the past keepalive_interval seconds
	 */
	struct timer_list keepalive_xmit;
	/* keepalive interval in seconds */
	unsigned long keepalive_interval;

	/* timer used to mark a peer as expired when no data is received for
	 * keepalive_timeout seconds
	 */
	struct timer_list keepalive_recv;
	/* keepalive timeout in seconds */
	unsigned long keepalive_timeout;

	/* true if ovpn_peer_mark_delete was called */
	bool halt;

	/* per-peer rx/tx stats */
	struct ovpn_peer_stats stats;

	/* protects binding to peer (bind) and timers
	 * (keepalive_xmit, keepalive_expire)
	 */
	spinlock_t lock;

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

static inline void ovpn_peer_keepalive_recv_reset(struct ovpn_peer *peer)
{
	u32 delta = msecs_to_jiffies(peer->keepalive_timeout * MSEC_PER_SEC);

	if (unlikely(!delta))
		return;

	mod_timer(&peer->keepalive_recv, jiffies + delta);
}

static inline void ovpn_peer_keepalive_xmit_reset(struct ovpn_peer *peer)
{
	u32 delta = msecs_to_jiffies(peer->keepalive_interval * MSEC_PER_SEC);

	if (unlikely(!delta))
		return;

	mod_timer(&peer->keepalive_xmit, jiffies + delta);
}

struct ovpn_peer *
ovpn_peer_new_with_sockaddr(struct ovpn_struct *ovpn,
			    const struct ovpn_sockaddr_pair *sapair);

void ovpn_peer_delete(struct ovpn_peer *peer);

int ovpn_peer_reset_sockaddr(struct ovpn_peer *peer,
			     const struct ovpn_sockaddr_pair *sapair);

int ovpn_peer_xmit_explicit_exit_notify(struct ovpn_peer *peer)
	__must_hold(ovpn_config_mutex);

void ovpn_peer_keepalive_set(struct ovpn_peer *peer, u32 interval, u32 timeout);

#endif /* _NET_OVPN_DCO_OVPNPEER_H_ */
