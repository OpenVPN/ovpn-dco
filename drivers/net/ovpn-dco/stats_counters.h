/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020-2021 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNSTATS_COUNTERS_H_
#define _NET_OVPN_DCO_OVPNSTATS_COUNTERS_H_

#include "ovpn.h"

/* increment per-peer stats */
static inline bool ovpn_peer_stats_increment(struct ovpn_peer_stats *stats,
					     struct ovpn_peer_stat *stat,
					     const unsigned int n)
{
	const u64 newval = atomic64_add_return(n, &stat->bytes);
	bool notify_trigger = false;

	atomic_inc(&stat->packets);

	/* for performance, first check for trigger conditions
	 * before we grab spinlock
	 */
	if (!stats->notify_per && !stats->period)
		return false;

	if (likely(newval < READ_ONCE(stat->notify) &&
		   time_before(jiffies, READ_ONCE(stats->revisit))))
		return false;

	spin_lock_bh(&stats->lock);

	/* did stat cross notification threshold? */
	if (stats->notify_per && newval - n < stat->notify &&
	    stat->notify <= newval) {
		notify_trigger = true;
		stat->notify += stats->notify_per;

		if (stats->period)
			stats->revisit = jiffies + stats->period;
	}
	/* did notification time period elapse? */
	else if (stats->period && time_after_eq(jiffies, stats->revisit)) {
		notify_trigger = true;
		stats->revisit = jiffies + stats->period;
	}

	spin_unlock_bh(&stats->lock);

	return notify_trigger;
}

static inline void ovpn_peer_stats_increment_rx(struct ovpn_peer *peer,
						const unsigned int n)
{
	ovpn_peer_stats_increment(&peer->stats, &peer->stats.rx, n);
}

static inline void ovpn_peer_stats_increment_tx(struct ovpn_peer *peer,
						const unsigned int n)
{
	ovpn_peer_stats_increment(&peer->stats, &peer->stats.tx, n);
}

#endif /* _NET_OVPN_DCO_OVPNSTATS_COUNTERS_H_ */
