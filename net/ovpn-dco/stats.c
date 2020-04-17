// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include "main.h"
#include "stats.h"
#include "ovpnstruct.h"

void ovpn_stats_get(struct ovpn_struct *ovpn, struct ovpn_stats *ret)
{
	int cpu;

	memset(ret, 0, sizeof(*ret));
	for_each_possible_cpu(cpu) {
		struct ovpn_stats_percpu *stats = per_cpu_ptr(ovpn->stats, cpu);
		u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin_irq(&stats->syncp);
			rx_packets = stats->s.rx_packets;
			tx_packets = stats->s.tx_packets;
			rx_bytes = stats->s.rx_bytes;
			tx_bytes = stats->s.tx_bytes;
		} while (u64_stats_fetch_retry_irq(&stats->syncp, start));

		ret->rx_packets += rx_packets;
		ret->tx_packets += tx_packets;
		ret->rx_bytes   += rx_bytes;
		ret->tx_bytes   += tx_bytes;
	}
}

void ovpn_percpu_snapshot(struct ovpn_struct *ovpn,
			  struct ovpn_percpu_stats *pcs)
{
	struct ovpn_stats_percpu *stats;
	struct ovpn_percpu_stat *ps;
	u64 rx_bytes, tx_bytes;
	unsigned int start;
	int cpu;

	pcs->total_stats = 0;
	memset(pcs->stats, 0, sizeof(pcs->stats[0]) * pcs->n_stats);

	/* collect rx/tx stats for each CPU */
	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(ovpn->stats, cpu);

		do {
			start = u64_stats_fetch_begin_irq(&stats->syncp);
			rx_bytes = stats->s.rx_bytes;
			tx_bytes = stats->s.tx_bytes;
		} while (u64_stats_fetch_retry_irq(&stats->syncp, start));

		if (cpu >= pcs->total_stats)
			pcs->total_stats = cpu + 1;

		if (cpu < pcs->n_stats) {
			ps = &pcs->stats[cpu];
			ps->rx_bytes = rx_bytes;
			ps->tx_bytes = tx_bytes;
		}
	}
}

void debug_log_stats64(struct ovpn_struct *ovpn)
{
	struct ovpn_stats_percpu *stats;
	u64 rx_bytes, tx_bytes;
	unsigned int start;
	int cpu;

	pr_info("--- kovpn PER-CPU STATS ---\n");
	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(ovpn->stats, cpu);

		do {
			start = u64_stats_fetch_begin_irq(&stats->syncp);
			rx_bytes = stats->s.rx_bytes;
			tx_bytes = stats->s.tx_bytes;
		} while (u64_stats_fetch_retry_irq(&stats->syncp, start));

		if (!rx_bytes && !tx_bytes)
			continue;

		pr_info("[%d] rx=%llu tx=%llu\n", cpu, rx_bytes, tx_bytes);
	}
}

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
