// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include "main.h"
#include "ovpnstruct.h"
#include "ovpn.h"
#include "peer.h"
#include "tcp.h"

#include <linux/ptr_ring.h>
#include <linux/skbuff.h>
#include <net/route.h>

static void ovpn_tcp_state_change(struct sock *sk)
{
}

static void ovpn_tcp_data_ready(struct sock *sk)
{
	struct ovpn_struct *ovpn;
	struct ovpn_peer *peer = NULL;

	rcu_read_lock();
	ovpn = rcu_dereference_sk_user_data(sk);
	if (ovpn)
		peer = ovpn_peer_get(ovpn);
	rcu_read_unlock();

	if (!peer)
		return;

	queue_work(peer->ovpn->events_wq, &peer->tcp.rx_work);
	ovpn_peer_put(peer);
}

static void ovpn_tcp_write_space(struct sock *sk)
{
	struct ovpn_struct *ovpn;
	struct ovpn_peer *peer = NULL;

	rcu_read_lock();
	ovpn = rcu_dereference_sk_user_data(sk);
	if (ovpn)
		peer = ovpn_peer_get(ovpn);
	rcu_read_unlock();

	if (!peer)
		return;

	queue_work(peer->ovpn->events_wq, &peer->tcp.tx_work);
	ovpn_peer_put(peer);
}

void ovpn_tcp_sock_detach(struct socket *sock)
{
	struct ovpn_struct *ovpn;
	struct ovpn_peer *peer = NULL;

	rcu_read_lock();
	ovpn = rcu_dereference_sk_user_data(sock->sk);
	if (ovpn)
		peer = ovpn_peer_get(ovpn);
	rcu_read_unlock();

	if (!peer)
		goto release;

	/* restore CBs that were saved in ovpn_sock_set_tcp_cb() */
	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_state_change = peer->tcp.sk_cb.sk_state_change;
	sock->sk->sk_data_ready = peer->tcp.sk_cb.sk_data_ready;
	sock->sk->sk_write_space = peer->tcp.sk_cb.sk_write_space;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	/* cancel any ongoing work. Done after removing the CBs so that these workers cannot be
	 * re-armed
	 */
	cancel_work_sync(&peer->tcp.tx_work);
	cancel_work_sync(&peer->tcp.rx_work);

	ovpn_peer_put(peer);

	rcu_assign_sk_user_data(sock->sk, NULL);
release:
	sock_release(sock);
}

/* Set TCP encapsulation callbacks */
int ovpn_tcp_sock_attach(struct socket *sock, struct ovpn_peer *peer)
{
	void *old_data;
	int ret = 0;

	write_lock_bh(&sock->sk->sk_callback_lock);

	/* make sure no pre-existing encapsulation handler exists */
	rcu_read_lock();
	old_data = rcu_dereference_sk_user_data(sock->sk);
	rcu_read_unlock();
	if (old_data) {
		pr_err("provided socket already taken by other user\n");
		ret = -EBUSY;
		goto out;
	}

	/* verify UDP socket */
	if (sock->sk->sk_protocol != IPPROTO_TCP) {
		pr_err("expected TCP socket\n");
		ret = -EINVAL;
		goto out;
	}

	if (sock->sk->sk_state != TCP_ESTABLISHED) {
		pr_err("unexpected state for TCP socket: %d\n", sock->sk->sk_state);
		ret = -EINVAL;
		goto out;
	}

	rcu_assign_sk_user_data(sock->sk, peer->ovpn);

	/* save current CBs so that they can be restored upon socket release */
	peer->tcp.sk_cb.sk_state_change = sock->sk->sk_state_change;
	peer->tcp.sk_cb.sk_data_ready = sock->sk->sk_data_ready;
	peer->tcp.sk_cb.sk_write_space = sock->sk->sk_write_space;

	/* assign our static CBs */
	sock->sk->sk_state_change = ovpn_tcp_state_change;
	sock->sk->sk_data_ready = ovpn_tcp_data_ready;
	sock->sk->sk_write_space = ovpn_tcp_write_space;
out:
	write_unlock_bh(&sock->sk->sk_callback_lock);
	return ret;
}

/* Try to send one skb (or part of it) over the TCP stream.
 *
 * Return 0 on success or a negative error code otherwise.
 *
 * Note that the skb is modified by putting away the data being sent, therefore
 * the caller should check if skb->len is zero to understand if the full skb was
 * sent or not.
 */
static int ovpn_tcp_send_one(struct ovpn_struct *ovpn, struct sk_buff *skb)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct kvec iv = { .iov_base = skb->data, .iov_len = skb->len };
	int ret;

	if (skb_linearize(skb) < 0) {
		pr_err_ratelimited("%s: can't linearize packet\n", __func__);
		return -ENOMEM;
	}

	ret = kernel_sendmsg(ovpn->sock, &msg, &iv, 1, iv.iov_len);
	if (ret > 0) {
		__skb_pull(skb, ret);

		/* since we update per-cpu stats in process context,
		 * we need to disable softirqs
		 */
		local_bh_disable();
		dev_sw_netstats_tx_add(ovpn->dev, 1, ret);
		local_bh_enable();

		return 0;
	}

	return ret;
}

/* Process packets in TCP TX queue */
void ovpn_tcp_tx_work(struct work_struct *work)
{
	struct ovpn_peer *peer;
	struct sk_buff *skb;
	int ret;

	peer = container_of(work, struct ovpn_peer, tcp.tx_work);
	while ((skb = __ptr_ring_peek(&peer->tcp.tx_ring))) {
		ret = ovpn_tcp_send_one(peer->ovpn, skb);
		if (ret < 0 && ret != -EAGAIN) {
			pr_warn_ratelimited("%s: cannot send TCP packet: %d\n", __func__, ret);
			/* in case of TCP error stop sending loop, and, if peer is
			 * attached to ovpn_struct, delete it and notify userspace
			 */
			ovpn_peer_evict(peer, OVPN_DEL_PEER_REASON_TRANSPORT_ERROR);
			break;
		} else if (!skb->len) {
			/* skb was entirely consumed and can now be removed from the ring */
			__ptr_ring_discard_one(&peer->tcp.tx_ring);
			consume_skb(skb);
		}

		/* give a chance to be rescheduled if needed */
		if (need_resched())
			cond_resched();
	}
}

static int ovpn_tcp_rx_one(struct ovpn_peer *peer)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	int ret;

	/* no skb allocated means that we have to read (or finish reading) the 2 bytes prefix
	 * containing the actual packet size.
	 */
	if (!peer->tcp.skb) {
		struct kvec iv = {
			.iov_base = peer->tcp.raw_len + peer->tcp.offset,
			.iov_len = sizeof(u16) - peer->tcp.offset,
		};

		ret = kernel_recvmsg(peer->ovpn->sock, &msg, &iv, 1, iv.iov_len, msg.msg_flags);
		if (ret <= 0)
			return ret;

		peer->tcp.offset += ret;
		/* the entire packet size was read, prepare skb for reading data */
		if (peer->tcp.offset == sizeof(u16)) {
			u16 len = ntohs(*(__be16 *)peer->tcp.raw_len);
			/* invalid packet length: this is a fatal TCP error */
			if (!len) {
				pr_err("%s: received invalid packet length\n", __func__);
				return -EINVAL;
			}

			peer->tcp.skb = netdev_alloc_skb_ip_align(peer->ovpn->dev, len);
			peer->tcp.offset = 0;
			peer->tcp.data_len = len;
		}
	} else {
		struct kvec iv = {
			.iov_base = peer->tcp.skb->data + peer->tcp.offset,
			.iov_len = peer->tcp.data_len - peer->tcp.offset,
		};

		ret = kernel_recvmsg(peer->ovpn->sock, &msg, &iv, 1, iv.iov_len, msg.msg_flags);
		if (ret <= 0)
			return ret;

		peer->tcp.offset += ret;
		/* full packet received, send it up for processing */
		if (peer->tcp.offset == peer->tcp.data_len) {
			/* update the skb data structure with the amount of data written by
			 * kernel_recvmsg()
			 */
			skb_put(peer->tcp.skb, peer->tcp.data_len);

			/* hold reference to peer as requird by ovpn_recv() */
			ovpn_peer_hold(peer);
			ret = ovpn_recv(peer->ovpn, peer, peer->tcp.skb);
			/* skb not consumed - free it now */
			if (unlikely(ret < 0))
				kfree_skb(peer->tcp.skb);

			peer->tcp.skb = NULL;
			peer->tcp.offset = 0;
			peer->tcp.data_len = 0;
		}
	}

	return ret;
}

void ovpn_tcp_rx_work(struct work_struct *work)
{
	struct ovpn_peer *peer = container_of(work, struct ovpn_peer, tcp.rx_work);
	int ret;

	while (true) {
		/* give a chance to be rescheduled if needed */
		if (need_resched())
			cond_resched();

		ret = ovpn_tcp_rx_one(peer);
		if (ret <= 0)
			break;
	}

	if (ret < 0 && ret != -EAGAIN)
		pr_err("%s: TCP socket error: %d\n", __func__, ret);
}

/* Put packet into TCP TX queue and schedule a consumer */
void ovpn_queue_tcp_skb(struct ovpn_peer *peer, struct sk_buff *skb)
{
	int ret;

	ret = __ptr_ring_produce(&peer->tcp.tx_ring, skb);
	if (ret < 0) {
		kfree_skb_list(skb);
		return;
	}

	queue_work(peer->ovpn->events_wq, &peer->tcp.tx_work);
}
