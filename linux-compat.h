/* SPDX-License-Identifier: GPL-2.0-only */
/* OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020- OpenVPN, Inc.
 *
 *  Author:	Lev Stipakov <lev@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_LINUX_COMPAT_H_
#define _NET_OVPN_DCO_LINUX_COMPAT_H_

#include <linux/kconfig.h>
#include <linux/version.h>

/*
 *  Red Hat Enterprise Linux and SUSE Linux Enterprise kernels provide
 *  helper macros for detecting the distribution version.  This is needed
 *  here as Red Hat and SUSE backport features and changes from newer kernels
 *  into the older kernel baseline.  Therefore the RHEL and SLE kernel
 *  features may not be correctly identified by the Linux kernel
 *  version alone.
 *
 *  To be able to build ovpn-dco on non-RHEL/SLE kernels, we need
 *  these helper macros defined.  And we want the result to
 *  always be true, to not disable the other kernel version
 *  checks
 */
#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#endif
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(m, n) 1
#endif

#ifndef SUSE_PRODUCT_CODE
#define SUSE_PRODUCT_CODE 0
#endif
#ifndef SUSE_PRODUCT
#define SUSE_PRODUCT(pr, v, pl, aux) 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)

#ifndef UDP_ENCAP_OVPNINUDP
/* Our UDP encapsulation types, must be unique
 * (other values in include/uapi/linux/udp.h)
 */
#define UDP_ENCAP_OVPNINUDP 100  /* transport layer */
#endif

#define timer_container_of from_timer

enum ovpn_ifla_attrs {
	IFLA_OVPN_UNSPEC = 0,
	IFLA_OVPN_MODE,

	__IFLA_OVPN_AFTER_LAST,
	IFLA_OVPN_MAX = __IFLA_OVPN_AFTER_LAST - 1,
};

enum ovpn_mode {
	__OVPN_MODE_FIRST = 0,
	OVPN_MODE_P2P = __OVPN_MODE_FIRST,
	OVPN_MODE_MP,

	__OVPN_MODE_AFTER_LAST,
};

#else

#define __OVPN_MODE_FIRST 0
#define __OVPN_MODE_AFTER_LAST (OVPN_MODE_MP + 1)

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0)

#ifndef NLA_POLICY_MAX_LEN
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#define NLA_POLICY_MAX_LEN(_len) { .type = NLA_BINARY, .len = _len }
#else
#define NLA_POLICY_MAX_LEN(_len) NLA_POLICY_MAX(NLA_BINARY, _len)
#endif
#endif

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(9, 6)

#include <linux/netdev_features.h>
#undef NETIF_F_SG
#define NETIF_F_SG (__NETIF_F(SG) | NETIF_F_LLTX)

#define lltx needs_free_netdev

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(9, 3)

#define genl_split_ops genl_ops

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(9, 3) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0) && SUSE_PRODUCT_CODE < SUSE_PRODUCT(1, 15, 5, 0)

/**
 * commit 58caed3dacb4 renamed to netif_napi_add_tx_weight,
 * commit c3f760ef1287 removed netif_tx_napi_add
 */
#define netif_napi_add_tx_weight netif_tx_napi_add

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0) && SUSE_PRODUCT_CODE < SUSE_PRODUCT(1, 15, 5, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) && SUSE_PRODUCT_CODE < SUSE_PRODUCT(1, 15, 5, 0)

#define sock_is_readable stream_memory_read

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) && SUSE_PRODUCT_CODE < SUSE_PRODUCT(1, 15, 5, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0)

#define dev_get_tstats64 ip_tunnel_get_stats64

#include <linux/netdevice.h>

static inline void dev_sw_netstats_tx_add(struct net_device *dev,
					  unsigned int packets,
					  unsigned int len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->tx_bytes += len;
	tstats->tx_packets += packets;
	u64_stats_update_end(&tstats->syncp);
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0)

#define genl_small_ops genl_ops
#define small_ops ops
#define n_small_ops n_ops

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0)

#include <linux/netdevice.h>

static inline void dev_sw_netstats_rx_add(struct net_device *dev, unsigned int len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_bytes += len;
	tstats->rx_packets++;
	u64_stats_update_end(&tstats->syncp);
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)

/* Iterate through singly-linked GSO fragments of an skb. */
#define skb_list_walk_safe(first, skb, next_skb)				\
	for ((skb) = (first), (next_skb) = (skb) ? (skb)->next : NULL; (skb);	\
	     (skb) = (next_skb), (next_skb) = (skb) ? (skb)->next : NULL)

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
/**
 * rcu_replace_pointer() - replace an RCU pointer, returning its old value
 * @rcu_ptr: RCU pointer, whose old value is returned
 * @ptr: regular pointer
 * @c: the lockdep conditions under which the dereference will take place
 *
 * Perform a replacement, where @rcu_ptr is an RCU-annotated
 * pointer and @c is the lockdep argument that is passed to the
 * rcu_dereference_protected() call used to read that pointer.  The old
 * value of @rcu_ptr is returned, and @rcu_ptr is set to @ptr.
 */
#undef rcu_replace_pointer
#define rcu_replace_pointer(rcu_ptr, ptr, c)				\
({									\
	typeof(ptr) __tmp = rcu_dereference_protected((rcu_ptr), (c));	\
	rcu_assign_pointer((rcu_ptr), (ptr));				\
	__tmp;								\
})

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0) && SUSE_PRODUCT_CODE < SUSE_PRODUCT(1, 15, 3, 0)

/* commit 895b5c9f206e renamed nf_reset to nf_reset_ct */
#undef nf_reset_ct
#define nf_reset_ct nf_reset

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0) && SUSE_PRODUCT_CODE < SUSE_PRODUCT(1, 15, 3, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)

/* commit 1550c171935d introduced rt_gw4 and rt_gw6 for IPv6 gateways */
#define rt_gw4 rt_gateway

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) */

#endif /* _NET_OVPN_DCO_LINUX_COMPAT_H_ */
