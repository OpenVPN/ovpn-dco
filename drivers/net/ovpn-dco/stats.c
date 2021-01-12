// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020-2021 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include "main.h"
#include "stats.h"

void ovpn_peer_stats_init(struct ovpn_peer_stats *ps)
{
	atomic64_set(&ps->rx.bytes, 0);
	ps->rx.notify = 0;
	atomic64_set(&ps->tx.bytes, 0);
	ps->tx.notify = 0;
	ps->notify_per = 0;
	ps->period = 0 * HZ;
	ps->revisit = jiffies + ps->period;
	spin_lock_init(&ps->lock);
}
