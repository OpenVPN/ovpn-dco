/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */


#include "main.h"
#include "debug.h"
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
	/* zero result set */
	{
		const struct ovpn_percpu_stat ps = {
			.rx_bytes = 0,
			.tx_bytes = 0,
		};
		size_t i;
		pcs->total_stats = 0;
		for (i = 0; i < pcs->n_stats; ++i)
			pcs->stats[i] = ps;
	}

	/* collect rx/tx stats for each CPU */
	{
		int cpu;
		for_each_possible_cpu(cpu) {
			struct ovpn_stats_percpu *stats = per_cpu_ptr(ovpn->stats, cpu);
			u64 rx_bytes, tx_bytes;
			unsigned int start;

			do {
				start = u64_stats_fetch_begin_irq(&stats->syncp);
				rx_bytes = stats->s.rx_bytes;
				tx_bytes = stats->s.tx_bytes;
			} while (u64_stats_fetch_retry_irq(&stats->syncp, start));

			if (cpu >= pcs->total_stats)
				pcs->total_stats = cpu + 1;
			if (cpu < pcs->n_stats) {
				struct ovpn_percpu_stat *ps = &pcs->stats[cpu];
				ps->rx_bytes = rx_bytes;
				ps->tx_bytes = tx_bytes;
			}
		}
	}
}

void debug_log_stats64(struct ovpn_struct *ovpn)
{
	int cpu;

	ovpn_debug(KERN_INFO, "--- kovpn PER-CPU STATS ---\n");
	for_each_possible_cpu(cpu) {
		struct ovpn_stats_percpu *stats = per_cpu_ptr(ovpn->stats, cpu);
		u64 rx_bytes, tx_bytes;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin_irq(&stats->syncp);
			rx_bytes = stats->s.rx_bytes;
			tx_bytes = stats->s.tx_bytes;
		} while (u64_stats_fetch_retry_irq(&stats->syncp, start));
		if (rx_bytes || tx_bytes)
			ovpn_debug(KERN_INFO, "[%d] rx=%llu tx=%llu\n", cpu, rx_bytes, tx_bytes);
	}
}

void ovpn_peer_stats_init(struct ovpn_peer_stats *ps)
{
	atomic64_set(&ps->rx.bytes, 0);
	ps->rx.notify = 0;
	atomic64_set(&ps->tx.bytes, 0);
	ps->tx.notify = 0;
	ps->notify_per = 0;
	ps->period = (unsigned long)0 * HZ;
	ps->revisit = jiffies + ps->period;
	spin_lock_init(&ps->lock);
}
