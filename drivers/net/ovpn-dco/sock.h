/* SPDX-License-Identifier: GPL-2.0 */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020-2022 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_SOCK_H_
#define _NET_OVPN_DCO_SOCK_H_

#include <net/sock.h>

struct ovpn_struct;

/**
 * struct ovpn_socket - a kernel socket referenced in the ovpn-dco code
 */
struct ovpn_socket {
	union {
		/** @ovpn: the VPN session object owning this socket (UDP only) */
		struct ovpn_struct *ovpn;

		/** @peer: the unique peer transmitting over this socket (TCP only) */
		struct ovpn_peer *peer;
	};

	/** @sock: the kernel socket */
	struct socket *sock;

	/** @refcount: amount of contexts currently referencing this object */
	struct kref refcount;

	/** @rcu: member used to schedule RCU destructor callback */
	struct rcu_head rcu;
};

int ovpn_sock_holder_encap_overhead(struct socket *sock);
struct ovpn_struct *ovpn_from_udp_sock(struct sock *sk);

static inline int ovpn_sock_encap_overhead(const struct sock *sk)
{
	int ret;

	if (!sk)
		return -ENODEV;

	switch (sk->sk_protocol) {
	case IPPROTO_UDP:
		ret = sizeof(struct udphdr);
		break;
	default:
		return -EOPNOTSUPP;
	}

	switch (sk->sk_family) {
	case PF_INET:
		ret += sizeof(struct iphdr);
		break;
	case PF_INET6:
		ret += sizeof(struct ipv6hdr);
		break;
	default:
		return -EAFNOSUPPORT;
	}

	return ret;
}

void ovpn_socket_release_kref(struct kref *kref);

static inline void ovpn_socket_put(struct ovpn_socket *sock)
{
	kref_put(&sock->refcount, ovpn_socket_release_kref);
}

struct ovpn_socket *ovpn_socket_new(struct socket *sock, struct ovpn_peer *peer);

#endif /* _NET_OVPN_DCO_SOCK_H_ */
