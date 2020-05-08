// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include "main.h"
#include "ovpn.h"
#include "peer.h"
#include "sock.h"
#include "rcu.h"
#include "udp.h"

#include <net/udp.h>
#include <net/udp_tunnel.h>

/* Detach socket from encapsulation handler and/or other callbacks */
static void ovpn_sock_unset_udp_cb(struct socket *sock)
{
	struct udp_tunnel_sock_cfg cfg = { };

	setup_udp_tunnel_sock(sock_net(sock->sk), sock, &cfg);
}

/* Finalize release of socket, called after RCU grace period */
void ovpn_sock_detach(struct socket *sock)
{
	if (!sock)
		return;

	ovpn_sock_unset_udp_cb(sock);

	sock_put(sock->sk);
	sockfd_put(sock);
}

/* Set UDP encapsulation callbacks */
static int ovpn_sock_set_udp_cb(struct socket *sock, void *user_data)
{
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = user_data,
		.encap_type = UDP_ENCAP_OVPNINUDP,
		.encap_rcv = ovpn_udp_encap_recv,
	};

	/* make sure no pre-existing encapsulation handler exists */
	if (rcu_dereference_sk_user_data(sock->sk)) {
		pr_err("provided socket already taken by other user\n");
		return -EBUSY;
	}

	/* verify UDP socket */
	if (sock->sk->sk_protocol != IPPROTO_UDP) {
		pr_err("expected UDP socket\n");
		return -EINVAL;
	}

	setup_udp_tunnel_sock(sock_net(sock->sk), sock, &cfg);

	return 0;
}

/* Return the encapsulation overhead of the socket */
int ovpn_sock_holder_encap_overhead(struct socket *sock)
{
	int ret;

	rcu_read_lock();
	ret = ovpn_sock_encap_overhead(sock->sk);
	rcu_read_unlock();
	return ret;
}

/* sock's refcounter is expected to be held by the caller already */
int ovpn_sock_attach_udp(struct ovpn_struct *ovpn, struct socket *sock)
{
	int ret;

	sock_hold(sock->sk);

	ret = ovpn_sock_set_udp_cb(sock, ovpn);
	if (ret < 0) {
		sock_put(sock->sk);
		return ret;
	}

	return 0;
}

struct ovpn_struct *ovpn_from_udp_sock(struct sock *sk)
{
	struct ovpn_struct *ovpn;
	struct ovpn_peer *peer;

	ovpn_rcu_lockdep_assert_held();

	if (unlikely(READ_ONCE(udp_sk(sk)->encap_type) != UDP_ENCAP_OVPNINUDP))
		return NULL;

	ovpn = rcu_dereference_sk_user_data(sk);
	if (unlikely(!ovpn))
		return NULL;

	peer = rcu_dereference(ovpn->peer);
	if (unlikely(!peer))
		return NULL;

	/* make sure that sk matches our stored transport socket */
	if (unlikely(!peer->sock || sk != peer->sock->sk))
		return NULL;

	return ovpn;
}
