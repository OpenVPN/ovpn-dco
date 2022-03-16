/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020-2022 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNSTATS_COUNTERS_H_
#define _NET_OVPN_DCO_OVPNSTATS_COUNTERS_H_

#include "ovpn.h"

/* increment per-peer stats */
static inline void ovpn_peer_stats_increment(struct ovpn_peer_stat *stat, const unsigned int n)
{
	atomic64_add_return(n, &stat->bytes);
	atomic_inc(&stat->packets);
}

static inline void ovpn_peer_stats_increment_rx(struct ovpn_peer *peer, const unsigned int n)
{
	ovpn_peer_stats_increment(&peer->stats.rx, n);
}

static inline void ovpn_peer_stats_increment_tx(struct ovpn_peer *peer, const unsigned int n)
{
	ovpn_peer_stats_increment(&peer->stats.tx, n);
}

#endif /* _NET_OVPN_DCO_OVPNSTATS_COUNTERS_H_ */
