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
#include "tcp.h"
#include "udp.h"

#include <net/udp.h>
#include <net/udp_tunnel.h>

/* Detach socket from encapsulation handler and/or other callbacks */
static void ovpn_sock_unset_udp_cb(struct socket *sock)
{
	struct udp_tunnel_sock_cfg cfg = { };

	setup_udp_tunnel_sock(sock_net(sock->sk), sock, &cfg);
	sockfd_put(sock);
}

/* Finalize release of socket, called after RCU grace period */
void ovpn_sock_detach(struct socket *sock)
{
	if (!sock)
		return;

	if (sock->sk->sk_protocol == IPPROTO_UDP)
		ovpn_sock_unset_udp_cb(sock);
	else if (sock->sk->sk_protocol == IPPROTO_TCP)
		ovpn_tcp_sock_detach(sock);
}

/* Set UDP encapsulation callbacks */
int ovpn_sock_attach_udp(struct socket *sock, struct ovpn_struct *ovpn)
{
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = ovpn,
		.encap_type = UDP_ENCAP_OVPNINUDP,
		.encap_rcv = ovpn_udp_encap_recv,
	};
	void *old_data;

	if (sock->sk->sk_protocol != IPPROTO_UDP) {
		pr_err("%s: expected UDP socket\n", __func__);
		return -EINVAL;
	}

	/* make sure no pre-existing encapsulation handler exists */
	rcu_read_lock();
	old_data = rcu_dereference_sk_user_data(sock->sk);
	rcu_read_unlock();
	if (old_data) {
		pr_err("provided socket already taken by other user\n");
		return -EBUSY;
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
