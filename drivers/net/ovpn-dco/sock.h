/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_SOCK_H_
#define _NET_OVPN_DCO_SOCK_H_

#include <net/sock.h>

struct ovpn_struct;

int ovpn_sock_attach_udp(struct ovpn_struct *ovpn, struct socket *sock);
void ovpn_sock_detach(struct socket *sock);
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

#endif /* _NET_OVPN_DCO_SOCK_H_ */
