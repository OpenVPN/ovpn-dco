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
static void ovpn_sock_unset_udp_cb(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);

	udp_sk(sk)->encap_type = 0;
	udp_sk(sk)->encap_rcv = NULL;
	udp_sk(sk)->encap_destroy = NULL;
	rcu_assign_sk_user_data(sk, NULL);

	write_unlock_bh(&sk->sk_callback_lock);
}

/* Finalize release of socket, called after RCU grace period */
void ovpn_sock_detach(struct socket *sock)
{
	if (!sock)
		return;

	ovpn_sock_unset_udp_cb(sock->sk);

	sock_put(sock->sk);
	sockfd_put(sock);
}

/* Tunnel socket destroy hook for UDP encapsulation.
 * Is currently a no-op.
 * See net/ipv[46]/udp.c.
 */
static void ovpn_udp_encap_destroy(struct sock *sk)
{
}

/* Set UDP encapsulation callbacks */
static int ovpn_sock_set_udp_cb(struct sock *sk, void *user_data)
{
	int err = 0;

	write_lock_bh(&sk->sk_callback_lock);

	/* make sure no pre-existing encapsulation handler exists */
	if (READ_ONCE(sk->sk_user_data)) {
		pr_err("provided socket already taken by other user\n");
		err = -EBUSY;
		goto unlock;
	}

	/* verify UDP socket */
	if (sk->sk_protocol != IPPROTO_UDP) {
		pr_err("expected UDP socket\n");
		err = -EINVAL;
		goto unlock;
	}

	udp_sk(sk)->encap_type = UDP_ENCAP_OVPNINUDP;
	udp_sk(sk)->encap_rcv = ovpn_udp_encap_recv;
	udp_sk(sk)->encap_destroy = ovpn_udp_encap_destroy;

	rcu_assign_sk_user_data(sk, user_data);

unlock:
	write_unlock_bh(&sk->sk_callback_lock);
	return err;
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

	ret = ovpn_sock_set_udp_cb(sock->sk, ovpn);
	if (ret < 0) {
		sock_put(sock->sk);
		return ret;
	}

	/* Enable global kernel-wide UDP encapsulation callback */
	udp_tunnel_encap_enable(sock);

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
