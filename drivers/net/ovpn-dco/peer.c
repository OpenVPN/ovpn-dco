// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020-2021 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include "ovpn.h"
#include "bind.h"
#include "crypto.h"
#include "peer.h"
#include "netlink.h"
#include "tcp.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

static void ovpn_peer_ping(struct timer_list *t)
{
	struct ovpn_peer *peer = from_timer(peer, t, keepalive_xmit);

	rcu_read_lock();
	pr_debug("sending ping to peer %pIScp\n", &rcu_dereference(peer->bind)->sa);
	rcu_read_unlock();

	ovpn_keepalive_xmit(peer);
}

static void ovpn_peer_expire(struct timer_list *t)
{
	struct ovpn_peer *peer = from_timer(peer, t, keepalive_recv);

	rcu_read_lock();
	pr_debug("peer expired: %pIScp\n", &rcu_dereference(peer->bind)->sa);
	rcu_read_unlock();

	ovpn_peer_del(peer, OVPN_DEL_PEER_REASON_EXPIRED);
}

/* Construct a new peer */
static struct ovpn_peer *ovpn_peer_new(struct ovpn_struct *ovpn)
{
	struct ovpn_peer *peer;
	int ret;

	/* alloc and init peer object */
	peer = kzalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer)
		return ERR_PTR(-ENOMEM);

	peer->halt = false;
	peer->ovpn = ovpn;

	peer->vpn_addrs.ipv4.s_addr = INADDR_ANY;
	peer->vpn_addrs.ipv6 = in6addr_any;

	RCU_INIT_POINTER(peer->bind, NULL);
	ovpn_crypto_state_init(&peer->crypto);
	spin_lock_init(&peer->lock);
	kref_init(&peer->refcount);
	ovpn_peer_stats_init(&peer->stats);

	INIT_WORK(&peer->encrypt_work, ovpn_encrypt_work);
	INIT_WORK(&peer->decrypt_work, ovpn_decrypt_work);

	/* configure and start NAPI */
	netif_tx_napi_add(ovpn->dev, &peer->napi, ovpn_napi_poll,
			  NAPI_POLL_WEIGHT);
	napi_enable(&peer->napi);

	ret = dst_cache_init(&peer->dst_cache, GFP_KERNEL);
	if (ret < 0) {
		pr_err("cannot initialize dst cache\n");
		goto err;
	}

	ret = ptr_ring_init(&peer->tx_ring, OVPN_QUEUE_LEN, GFP_KERNEL);
	if (ret < 0) {
		pr_err("cannot allocate TX ring\n");
		goto err_dst_cache;
	}

	ret = ptr_ring_init(&peer->rx_ring, OVPN_QUEUE_LEN, GFP_KERNEL);
	if (ret < 0) {
		pr_err("cannot allocate RX ring\n");
		goto err_tx_ring;
	}

	ret = ptr_ring_init(&peer->netif_rx_ring, OVPN_QUEUE_LEN, GFP_KERNEL);
	if (ret < 0) {
		pr_err("cannot allocate NETIF RX ring\n");
		goto err_rx_ring;
	}

	dev_hold(ovpn->dev);

	timer_setup(&peer->keepalive_xmit, ovpn_peer_ping, 0);
	timer_setup(&peer->keepalive_recv, ovpn_peer_expire, 0);

	return peer;
err_rx_ring:
	ptr_ring_cleanup(&peer->rx_ring, NULL);
err_tx_ring:
	ptr_ring_cleanup(&peer->tx_ring, NULL);
err_dst_cache:
	dst_cache_destroy(&peer->dst_cache);
err:
	napi_disable(&peer->napi);
	netif_napi_del(&peer->napi);
	kfree(peer);
	return ERR_PTR(ret);
}

/* Reset the ovpn_sockaddr associated with a peer */
int ovpn_peer_reset_sockaddr(struct ovpn_peer *peer, const struct sockaddr *sa)
{
	struct ovpn_bind *bind;

	/* create new ovpn_bind object */
	bind = ovpn_bind_from_sockaddr(sa);
	if (IS_ERR(bind))
		return PTR_ERR(bind);

	/* set binding */
	ovpn_bind_reset(peer, bind);

	return 0;
}

static void ovpn_peer_timer_delete_all(struct ovpn_peer *peer)
{
	del_timer_sync(&peer->keepalive_xmit);
	del_timer_sync(&peer->keepalive_recv);
}

void ovpn_peer_release(struct ovpn_peer *peer)
{
	ovpn_bind_reset(peer, NULL);
	ovpn_peer_timer_delete_all(peer);

	WARN_ON(!__ptr_ring_empty(&peer->tx_ring));
	ptr_ring_cleanup(&peer->tx_ring, NULL);
	WARN_ON(!__ptr_ring_empty(&peer->rx_ring));
	ptr_ring_cleanup(&peer->rx_ring, NULL);
	WARN_ON(!__ptr_ring_empty(&peer->netif_rx_ring));
	ptr_ring_cleanup(&peer->netif_rx_ring, NULL);

	dst_cache_destroy(&peer->dst_cache);

	dev_put(peer->ovpn->dev);

	kfree(peer);
}

static void ovpn_peer_release_rcu(struct rcu_head *head)
{
	struct ovpn_peer *peer = container_of(head, struct ovpn_peer, rcu);

	ovpn_crypto_state_release(&peer->crypto);
	ovpn_socket_put(peer->sock);
	ovpn_peer_release(peer);
}

static void ovpn_peer_delete_work(struct work_struct *work)
{
	struct ovpn_peer *peer = container_of(work, struct ovpn_peer,
					      delete_work);

	napi_disable(&peer->napi);
	netif_napi_del(&peer->napi);
	ovpn_netlink_notify_del_peer(peer);

	call_rcu(&peer->rcu, ovpn_peer_release_rcu);
}

/* Use with kref_put calls, when releasing refcount
 * on ovpn_peer objects.  This method should only
 * be called from process context with config_mutex held.
 */
void ovpn_peer_release_kref(struct kref *kref)
{
	struct ovpn_peer *peer = container_of(kref, struct ovpn_peer, refcount);

	INIT_WORK(&peer->delete_work, ovpn_peer_delete_work);
	queue_work(peer->ovpn->events_wq, &peer->delete_work);
}

struct ovpn_peer *
ovpn_peer_new_with_sockaddr(struct ovpn_struct *ovpn, const struct sockaddr *sa,
			    struct socket *sock)
{
	struct ovpn_peer *peer;
	int ret;

	/* create new peer */
	peer = ovpn_peer_new(ovpn);
	if (IS_ERR(peer))
		return peer;

	/* set peer sockaddr */
	ret = ovpn_peer_reset_sockaddr(peer, sa);
	if (ret < 0) {
		ovpn_peer_release(peer);
		return ERR_PTR(ret);
	}

	peer->sock = ovpn_socket_new(sock, peer);
	if (IS_ERR(peer->sock)) {
		ovpn_peer_release(peer);
		return ERR_PTR(-ENOTSOCK);
	}

	/* schedule initial TCP RX work only after having assigned peer->sock */
	if (peer->sock->sock->sk->sk_protocol == IPPROTO_TCP)
		queue_work(peer->ovpn->events_wq, &peer->tcp.rx_work);

	return peer;
}

/* Configure keepalive parameters */
void ovpn_peer_keepalive_set(struct ovpn_peer *peer, u32 interval, u32 timeout)
{
	u32 delta;

	rcu_read_lock();
	pr_debug("scheduling keepalive for %pIScp: interval=%u timeout=%u\n",
		 &rcu_dereference(peer->bind)->sa, interval, timeout);
	rcu_read_unlock();

	peer->keepalive_interval = interval;
	delta = msecs_to_jiffies(interval * MSEC_PER_SEC);
	if (delta >= 1000)
		mod_timer(&peer->keepalive_xmit, jiffies + delta);
	else
		pr_warn("%s: ignoring keepalive interval smaller than 1s: %dms\n", __func__, delta);

	peer->keepalive_timeout = timeout;
	delta = msecs_to_jiffies(timeout * MSEC_PER_SEC);
	if (delta >= 1000)
		mod_timer(&peer->keepalive_recv, jiffies + delta);
	else
		pr_warn("%s: ignoring keepalive timeout smaller than 1s: %dms\n", __func__, delta);
}

#define ovpn_peer_index(_tbl, _key, _key_len)		\
	(jhash(_key, _key_len, 0) % HASH_SIZE(_tbl))	\

static struct ovpn_peer *ovpn_peer_lookup_vpn_addr4(struct hlist_head *head, __be32 *addr)
{
	struct ovpn_peer *tmp, *peer = NULL;

	rcu_read_lock();
	hlist_for_each_entry_rcu(tmp, head, hash_entry_addr4) {
		if (*addr != tmp->vpn_addrs.ipv4.s_addr)
			continue;

		if (!ovpn_peer_hold(tmp))
			continue;

		peer = tmp;
		break;
	}
	rcu_read_unlock();

	return peer;
}

static struct ovpn_peer *ovpn_peer_lookup_vpn_addr6(struct hlist_head *head, struct in6_addr *addr)
{
	struct ovpn_peer *tmp, *peer = NULL;
	int i;

	rcu_read_lock();
	hlist_for_each_entry_rcu(tmp, head, hash_entry_addr6) {
		for (i = 0; i < 4; i++) {
			if (addr->s6_addr32[i] != tmp->vpn_addrs.ipv6.s6_addr32[i])
				continue;
		}

		if (!ovpn_peer_hold(tmp))
			continue;

		peer = tmp;
		break;
	}
	rcu_read_unlock();

	return peer;
}

static struct rtable *ovpn_gw4(struct ovpn_struct *ovpn, __be32 dst)
{
	struct rtable *rt;
	struct flowi4 fl = {
		.daddr = dst
	};

	rt = ip_route_output_flow(dev_net(ovpn->dev), &fl, NULL);
	if (IS_ERR(rt)) {
		net_dbg_ratelimited("%s: no route to host %pI4\n", __func__, &dst);
		/* if we end up here this packet is probably going to be thrown away later */
		return NULL;
	}

	if (!rt->rt_uses_gateway) {
		ip_rt_put(rt);
		rt = NULL;
	}

	return rt;
}

static struct rtable *ovpn_gw6(struct ovpn_struct *ovpn, const struct in6_addr *dst)
{
	struct rtable *rt;
	struct flowi6 fl = {
		.daddr = *dst,
	};

	rt = (struct rtable *)ipv6_stub->ipv6_dst_lookup_flow(dev_net(ovpn->dev), NULL, &fl, NULL);
	if (IS_ERR(rt)) {
		net_dbg_ratelimited("%s: no route to host %pI6\n", __func__, dst);
		/* if we end up here this packet is probably going to be thrown away later */
		return false;
	}

	if (!rt->rt_uses_gateway) {
		ip_rt_put(rt);
		rt = NULL;
	}

	return rt;
}

/**
 * Lookup peer to send skb to.
 *
 * This function takes a tunnel packet and looks up the peer to send it to
 * after encapsulation. The skb is expected to be the in-tunnel packet, without
 * any OpenVPN related header.
 *
 * Assume that the IP header is accessible in the skb data.
 *
 * @ovpn: the private data representing the current VPN session
 * @skb: the skb to extract the destination address from
 *
 * Return the peer if found or NULL otherwise.
 */
struct ovpn_peer *ovpn_peer_lookup_vpn_addr(struct ovpn_struct *ovpn, struct sk_buff *skb)
{
	struct ovpn_peer *peer = NULL;
	struct hlist_head *head;
	struct rtable *rt = NULL;
	sa_family_t sa_fam;
	struct in6_addr *addr6;
	__be32 addr4;
	u32 index;

	sa_fam = skb_protocol_to_family(skb);

	switch (sa_fam) {
	case AF_INET:
		addr4 = ip_hdr(skb)->daddr;
		rt = ovpn_gw4(ovpn, addr4);
		if (rt)
			addr4 = rt->rt_gw4;

		index = ovpn_peer_index(ovpn->peers.by_vpn_addr, &addr4, sizeof(addr4));
		head = &ovpn->peers.by_vpn_addr[index];

		peer = ovpn_peer_lookup_vpn_addr4(head, &addr4);
		break;
	case AF_INET6:
		addr6 = &ipv6_hdr(skb)->daddr;
		rt = ovpn_gw6(ovpn, addr6);
		if (rt)
			addr6 = &rt->rt_gw6;

		index = ovpn_peer_index(ovpn->peers.by_vpn_addr, addr6, sizeof(*addr6));
		head = &ovpn->peers.by_vpn_addr[index];

		peer = ovpn_peer_lookup_vpn_addr6(head, addr6);
		break;
	}

	if (peer)
		pr_debug("%s: found peer: %u\n", __func__, peer->id);

	if (rt)
		ip_rt_put(rt);

	return peer;
}

struct ovpn_peer *ovpn_peer_lookup_transp_addr(struct ovpn_struct *ovpn, struct sk_buff *skb)
{
	struct ovpn_peer *peer = NULL, *tmp;
	struct sockaddr_in6 sa6 = { 0 };
	struct sockaddr_in sa4 = { 0 };
	struct hlist_head *head;
	struct ovpn_bind *bind;
	sa_family_t sa_fam;
	bool found;
	u32 index;

	sa_fam = skb_protocol_to_family(skb);

	switch (sa_fam) {
	case AF_INET:
		sa4.sin_family = AF_INET;
		sa4.sin_addr.s_addr = ip_hdr(skb)->saddr;
		sa4.sin_port = udp_hdr(skb)->source;
		index = ovpn_peer_index(ovpn->peers.by_transp_addr, &sa4, sizeof(sa4));
		break;
	case AF_INET6:
		sa6.sin6_family = AF_INET6;
		sa6.sin6_addr = ipv6_hdr(skb)->saddr;
		sa6.sin6_port = udp_hdr(skb)->source;
		index = ovpn_peer_index(ovpn->peers.by_transp_addr, &sa6, sizeof(sa6));
		break;
	}

	head = &ovpn->peers.by_transp_addr[index];

	rcu_read_lock();
	hlist_for_each_entry_rcu(tmp, head, hash_entry_transp_addr) {
		found = false;

		bind = rcu_dereference(tmp->bind);
		if (unlikely(!bind))
			continue;

		if (sa_fam != bind->sa.in4.sin_family)
			continue;

		switch (sa_fam) {
		case AF_INET:
			if (sa4.sin_addr.s_addr != bind->sa.in4.sin_addr.s_addr)
				break;
			if (sa4.sin_port != bind->sa.in4.sin_port)
				break;
			found = true;
			break;
		case AF_INET6:
			if (memcmp(&sa6.sin6_addr, &bind->sa.in6.sin6_addr,
				   sizeof(struct in6_addr)))
				break;
			if (sa6.sin6_port != bind->sa.in6.sin6_port)
				break;
			found = true;
			break;
		}

		if (!found)
			continue;

		if (!ovpn_peer_hold(tmp))
			continue;

		peer = tmp;
		break;
	}
	rcu_read_unlock();

	if (peer)
		pr_debug("%s: found peer: %u\n", __func__, peer->id);

	return peer;
}

struct ovpn_peer *ovpn_peer_lookup_id(struct ovpn_struct *ovpn, u32 peer_id)
{
	struct ovpn_peer *tmp,  *peer = NULL;
	struct hlist_head *head;
	u32 index;

	index = ovpn_peer_index(ovpn->peers.by_id, &peer_id, sizeof(peer_id));
	head = &ovpn->peers.by_id[index];

	rcu_read_lock();
	hlist_for_each_entry_rcu(tmp, head, hash_entry_id) {
		if (tmp->id != peer_id)
			continue;

		if (!ovpn_peer_hold(tmp))
			continue;

		peer = tmp;
		break;
	}
	rcu_read_unlock();

	return peer;
}

/* assume refcounter was increased by caller */
int ovpn_peer_add(struct ovpn_struct *ovpn, struct ovpn_peer *peer)
{
	struct sockaddr sa = { 0 };
	struct sockaddr_in6 *sa6;
	struct sockaddr_in *sa4;
	struct ovpn_bind *bind;
	struct ovpn_peer *tmp;
	size_t salen;
	int ret = 0;
	u32 index;

	spin_lock(&ovpn->peers.lock);
	/* do not add duplicates */
	tmp = ovpn_peer_lookup_id(ovpn, peer->id);
	if (tmp) {
		ovpn_peer_put(tmp);
		ret = -EEXIST;
		goto unlock;
	}

	index = ovpn_peer_index(ovpn->peers.by_id, &peer->id, sizeof(peer->id));
	hlist_add_head_rcu(&peer->hash_entry_id, &ovpn->peers.by_id[index]);

	if (peer->vpn_addrs.ipv4.s_addr != INADDR_ANY) {
		index = ovpn_peer_index(ovpn->peers.by_vpn_addr, &peer->vpn_addrs.ipv4,
					sizeof(peer->vpn_addrs.ipv4));
		hlist_add_head_rcu(&peer->hash_entry_addr4, &ovpn->peers.by_vpn_addr[index]);
	}

	hlist_del_init_rcu(&peer->hash_entry_addr6);
	if (memcmp(&peer->vpn_addrs.ipv6, &in6addr_any, sizeof(peer->vpn_addrs.ipv6))) {
		index = ovpn_peer_index(ovpn->peers.by_vpn_addr, &peer->vpn_addrs.ipv6,
					sizeof(peer->vpn_addrs.ipv6));
		hlist_add_head_rcu(&peer->hash_entry_addr6, &ovpn->peers.by_vpn_addr[index]);
	}

	hlist_del_init_rcu(&peer->hash_entry_transp_addr);
	bind = rcu_dereference_protected(peer->bind, true);
	if (WARN_ON(!bind)) {
		ovpn_peer_release(peer);
		ret = -EINVAL;
		goto unlock;
	}

	switch (bind->sa.in4.sin_family) {
	case AF_INET:
		sa4 = (struct sockaddr_in *)&sa;

		sa4->sin_family = AF_INET;
		sa4->sin_addr.s_addr = bind->sa.in4.sin_addr.s_addr;
		sa4->sin_port = bind->sa.in4.sin_port;
		salen = sizeof(*sa4);
		break;
	case AF_INET6:
		sa6 = (struct sockaddr_in6 *)&sa;

		sa6->sin6_family = AF_INET6;
		sa6->sin6_addr = bind->sa.in6.sin6_addr;
		sa6->sin6_port = bind->sa.in6.sin6_port;
		salen = sizeof(*sa6);
		break;
	}

	index = ovpn_peer_index(ovpn->peers.by_transp_addr, &sa, salen);
	hlist_add_head_rcu(&peer->hash_entry_transp_addr, &ovpn->peers.by_transp_addr[index]);

unlock:
	spin_unlock(&ovpn->peers.lock);

	return ret;
}

static void ovpn_peer_unhash(struct ovpn_peer *peer, enum ovpn_del_peer_reason reason)
{
	hlist_del_rcu(&peer->hash_entry_id);
	hlist_del_init_rcu(&peer->hash_entry_addr4);
	hlist_del_init_rcu(&peer->hash_entry_addr6);
	hlist_del_init_rcu(&peer->hash_entry_transp_addr);

	ovpn_peer_put(peer);
	peer->delete_reason = reason;
}

int ovpn_peer_del(struct ovpn_peer *peer, enum ovpn_del_peer_reason reason)
{
	struct ovpn_peer *tmp;
	int ret = 0;

	spin_lock(&peer->ovpn->peers.lock);
	tmp = ovpn_peer_lookup_id(peer->ovpn, peer->id);
	if (tmp != peer) {
		ret = -ENOENT;
		goto unlock;
	}
	ovpn_peer_unhash(peer, reason);

unlock:
	spin_unlock(&peer->ovpn->lock);

	if (tmp)
		ovpn_peer_put(tmp);

	return ret;
}

void ovpn_peers_free(struct ovpn_struct *ovpn)
{
	struct hlist_node *tmp;
	struct ovpn_peer *peer;
	int bkt;

	spin_lock(&ovpn->peers.lock);
	hash_for_each_safe(ovpn->peers.by_id, bkt, tmp, peer, hash_entry_id)
		ovpn_peer_unhash(peer, OVPN_DEL_PEER_REASON_TEARDOWN);
	spin_unlock(&ovpn->peers.lock);
}
