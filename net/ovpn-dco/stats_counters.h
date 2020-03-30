#ifndef _NET_OVPN_DCO_OVPNSTATS_COUNTERS_H_
#define _NET_OVPN_DCO_OVPNSTATS_COUNTERS_H_

#include "ovpn.h"
//#include "ovpnnotify.h"
#include "ovpnstruct.h"

/* increment per-ovpn_struct TX stats */

static inline void ovpn_increment_tx_stats(struct ovpn_struct *ovpn, unsigned int n)
{
	struct ovpn_stats_percpu *stats = this_cpu_ptr(ovpn->stats);
	u64_stats_update_begin(&stats->syncp);
	stats->s.tx_packets++;
	stats->s.tx_bytes += n;
	u64_stats_update_end(&stats->syncp);
}

static inline void ovpn_increment_tx_stats_by_peer(struct ovpn_peer *peer,
						   unsigned int n)
{
	struct ovpn_struct *ovpn = peer->ovpn;
	if (likely(ovpn))
		ovpn_increment_tx_stats(ovpn, n);
}

/* increment per-ovpn_struct RX stats */

static inline void ovpn_increment_rx_stats(struct ovpn_struct *ovpn,
					   unsigned int n)
{
	struct ovpn_stats_percpu *stats = this_cpu_ptr(ovpn->stats);
	u64_stats_update_begin(&stats->syncp);
	stats->s.rx_packets++;
	stats->s.rx_bytes += n;
	u64_stats_update_end(&stats->syncp);
}

/* increment per-peer stats */

static inline bool __ovpn_peer_stats_increment(struct ovpn_peer_stats *stats,
					       struct ovpn_peer_stat *stat,
					       const unsigned int n)
{
	bool notify_trigger = false;
	const u64 newval = atomic64_add_return(n, &stat->bytes);

	/* for performance, first check for trigger conditions
	   before we grab spinlock */
	if ((stats->notify_per && unlikely(newval >= READ_ONCE(stat->notify)))
	    || (stats->period && unlikely(time_after_eq(jiffies, READ_ONCE(stats->revisit))))) {
		spin_lock_bh(&stats->lock);

		/* did stat cross notification threshold? */
		if (stats->notify_per
		    && newval - n < stat->notify
		    && stat->notify <= newval) {
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
	}
	return notify_trigger;
}

static inline void ovpn_peer_stats_increment_rx(struct ovpn_peer *peer,
						const unsigned int n)
{
	__ovpn_peer_stats_increment(&peer->stats, &peer->stats.rx, n);
}

static inline void ovpn_peer_stats_increment_tx(struct ovpn_peer *peer,
						const unsigned int n)
{
	__ovpn_peer_stats_increment(&peer->stats, &peer->stats.tx, n);
}

static inline u64 ovpn_peer_stats_get_rx(struct ovpn_peer *peer)
{
	return atomic64_read(&peer->stats.rx.bytes);
}

static inline u64 ovpn_peer_stats_get_tx(struct ovpn_peer *peer)
{
	return atomic64_read(&peer->stats.tx.bytes);
}

#endif /* _NET_OVPN_DCO_OVPNSTATS_COUNTERS_H_ */
