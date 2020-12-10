// SPDX-License-Identifier: GPL-2.0-only
/*  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2021 OpenVPN Technologies, Inc.
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

/* Given a remote sockaddr, compute the skb hash
 * and get a dst_entry so we can send packets to the remote.
 * Called from process context or softirq (must be indicated with
 * process_context bool).
 */
struct ovpn_bind *ovpn_bind_from_sockaddr(const struct sockaddr *sa)
{
	struct ovpn_bind *bind;
	size_t sa_len;
	int err;

	if (sa->sa_family == AF_INET)
		sa_len = sizeof(struct sockaddr_in);
	else if (sa->sa_family == AF_INET6)
		sa_len = sizeof(struct sockaddr_in6);
	else
		return ERR_PTR(-EAFNOSUPPORT);

	err = ovpn_sockaddr_validate(sa);
	if (err < 0)
		return ERR_PTR(err);

	bind = kzalloc(sizeof(*bind), GFP_KERNEL);
	if (unlikely(!bind))
		return ERR_PTR(-ENOMEM);

	memcpy(&bind->sa, sa, sa_len);

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

void ovpn_bind_reset(struct ovpn_peer *peer, struct ovpn_bind *new)
{
	struct ovpn_bind *old;

	spin_lock_bh(&peer->lock);
	old = rcu_replace_pointer(peer->bind, new, true);
	spin_unlock_bh(&peer->lock);

	if (old)
		call_rcu(&old->rcu, ovpn_bind_release_rcu);
}
