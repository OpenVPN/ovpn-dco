/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNSTATS_H_
#define _NET_OVPN_DCO_OVPNSTATS_H_

#include <linux/jiffies.h>
#include <linux/u64_stats_sync.h>

/* per-CPU stats */

struct ovpn_struct;

struct ovpn_stats {
	u64 rx_packets;
	u64 tx_packets;
	u64 rx_bytes;
	u64 tx_bytes;
};

struct ovpn_stats_percpu {
	struct ovpn_stats s;
	struct u64_stats_sync syncp;
};

/* per-peer stats, measured on transport layer */

/* one stat */
struct ovpn_peer_stat {
	atomic64_t bytes;
	/* notify userspace when bytes exceeds this value */
	u64 notify;
};

/* rx and tx stats, enabled by notify_per != 0 or period != 0 */
struct ovpn_peer_stats {
	struct ovpn_peer_stat rx;
	struct ovpn_peer_stat tx;
	/* configured bandwidth-triggered notification */
	u64 notify_per;
	/* configured time-triggered notification (relative jiffies) */
	unsigned long period;
	/* next timed notification (absolute jiffies) */
	unsigned long revisit;
	/* protects the ovpn_peer_stats object */
	spinlock_t lock;
};

/* struct for OVPN_ERR_STATS */

struct ovpn_err_stat {
	unsigned int category;
	int errcode;
	u64 count;
};

struct ovpn_err_stats {
	/* total stats, returned by kovpn */
	unsigned int total_stats;
	/* number of stats dimensioned below */
	unsigned int n_stats;
	struct ovpn_err_stat stats[];
};

/* struct for OVPN_PERCPU_STATS */

struct ovpn_percpu_stat {
	u64 rx_bytes;
	u64 tx_bytes;
};

struct ovpn_percpu_stats {
	/* total stats, returned by kovpn */
	unsigned int total_stats;
	/* number of stats dimensioned below */
	unsigned int n_stats;
	/* stats indexed by CPU number */
	struct ovpn_percpu_stat stats[];
};

void ovpn_stats_get(struct ovpn_struct *ovpn, struct ovpn_stats *ret);
void ovpn_percpu_snapshot(struct ovpn_struct *ovpn,
			  struct ovpn_percpu_stats *pcs);
void ovpn_peer_stats_init(struct ovpn_peer_stats *ps);
void debug_log_stats64(struct ovpn_struct *ovpn);

#endif /* _NET_OVPN_DCO_OVPNSTATS_H_ */
