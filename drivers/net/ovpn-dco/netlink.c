// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include "main.h"
#include "ovpn.h"
#include "peer.h"
#include "netlink.h"
#include "ovpnstruct.h"
#include "udp.h"

#include <uapi/linux/ovpn_dco.h>

#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/rcupdate.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <net/genetlink.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>

enum ovpn_netlink_multicast_groups {
	OVPN_MCGRP_PEERS,
};

static const struct genl_multicast_group ovpn_netlink_mcgrps[] = {
	[OVPN_MCGRP_PEERS] = { .name = OVPN_NL_MULTICAST_GROUP_PEERS },
};

static const struct nla_policy
ovpn_netlink_policy_key_dir[OVPN_KEY_DIR_ATTR_MAX + 1] = {
	[OVPN_KEY_DIR_ATTR_CIPHER_KEY] = { .type = NLA_BINARY, .len = U8_MAX },
	[OVPN_KEY_DIR_ATTR_NONCE_TAIL] = NLA_POLICY_EXACT_LEN(NONCE_TAIL_SIZE),
};

static const struct nla_policy
ovpn_netlink_policy_sockaddr[OVPN_SOCKADDR_ATTR_MAX + 1] = {
	/* IPv4 only supported for now */
	[OVPN_SOCKADDR_ATTR_ADDRESS] = NLA_POLICY_MIN_LEN(4),
	[OVPN_SOCKADDR_ATTR_PORT] = { .type = NLA_U16 },
};

static const struct nla_policy ovpn_netlink_policy[OVPN_ATTR_MAX + 1] = {
	[OVPN_ATTR_IFINDEX] = { .type = NLA_U32 },
	[OVPN_ATTR_MODE] = { .type = NLA_U8 },
	[OVPN_ATTR_SOCKET] = { .type = NLA_U32 },
	[OVPN_ATTR_PROTO] = { .type = NLA_U8 },
	[OVPN_ATTR_REMOTE_PEER_ID] = { .type = NLA_U32 },
	[OVPN_ATTR_KEY_SLOT] = NLA_POLICY_RANGE(NLA_U8, __OVPN_KEY_SLOT_FIRST,
						__OVPN_KEY_SLOT_AFTER_LAST - 1),
	[OVPN_ATTR_DEL_PEER_REASON] = NLA_POLICY_RANGE(NLA_U8,
						       __OVPN_DEL_PEER_REASON_FIRST,
						       __OVPN_DEL_PEER_REASON_AFTER_LAST - 1),
	[OVPN_ATTR_CIPHER_ALG] = { .type = NLA_U16 },
	[OVPN_ATTR_ENCRYPT_KEY] =
		NLA_POLICY_NESTED(ovpn_netlink_policy_key_dir),
	[OVPN_ATTR_DECRYPT_KEY] =
		NLA_POLICY_NESTED(ovpn_netlink_policy_key_dir),
	[OVPN_ATTR_KEY_ID] = { .type = NLA_U16 },
	[OVPN_ATTR_KEEPALIVE_INTERVAL] = { .type = NLA_U32 },
	[OVPN_ATTR_KEEPALIVE_TIMEOUT] = { .type = NLA_U32 },
	[OVPN_ATTR_SOCKADDR_REMOTE] =
		NLA_POLICY_NESTED(ovpn_netlink_policy_sockaddr),
	[OVPN_ATTR_SOCKADDR_LOCAL] =
		NLA_POLICY_NESTED(ovpn_netlink_policy_sockaddr),
};

static struct net_device *
ovpn_get_dev_from_info(struct net *net, struct genl_info *info)
{
	struct net_device *dev;
	int ifindex;

	if (!info->attrs[OVPN_ATTR_IFINDEX])
		return ERR_PTR(-EINVAL);

	ifindex = nla_get_u32(info->attrs[OVPN_ATTR_IFINDEX]);

	dev = dev_get_by_index(net, ifindex);
	if (!dev)
		return ERR_PTR(-ENODEV);

	if (!ovpn_dev_is_valid(dev))
		goto err_put_dev;

	return dev;

err_put_dev:
	dev_put(dev);

	return ERR_PTR(-EINVAL);
}

/**
 * ovpn_pre_doit() - Prepare ovpn genl doit request
 * @ops: requested netlink operation
 * @skb: Netlink message with request data
 * @info: receiver information
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int ovpn_pre_doit(const struct genl_ops *ops, struct sk_buff *skb,
			 struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct ovpn_struct *ovpn;
	struct net_device *dev;

	dev = ovpn_get_dev_from_info(net, info);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	info->user_ptr[0] = netdev_priv(dev);

	/* when the VPN is uninitialized, the only allowed command is START_VPN */
	ovpn = info->user_ptr[0];
	if (ops->cmd != OVPN_CMD_START_VPN && ovpn->mode == OVPN_MODE_UNDEF) {
		dev_put(dev);
		pr_debug("%s: reject cmd %d since it comes before OVPN_CMD_START_VPN(%d)\n",
			 __func__, ops->cmd, OVPN_CMD_START_VPN);
		return -EINVAL;
	}

	return 0;
}

/**
 * ovpn_post_doit() - complete ovpn genl doit request
 * @ops: requested netlink operation
 * @skb: Netlink message with request data
 * @info: receiver information
 */
static void ovpn_post_doit(const struct genl_ops *ops, struct sk_buff *skb,
			   struct genl_info *info)
{
	struct ovpn_struct *ovpn;

	ovpn = info->user_ptr[0];
	dev_put(ovpn->dev);
}

static int ovpn_netlink_get_key_dir(struct genl_info *info, struct nlattr *key,
				    enum ovpn_cipher_alg cipher,
				    struct ovpn_key_direction *dir)
{
	struct nlattr *attr, *attrs[OVPN_KEY_DIR_ATTR_MAX + 1];
	int ret;

	ret = nla_parse_nested(attrs, OVPN_KEY_DIR_ATTR_MAX, key,
			       ovpn_netlink_policy_key_dir, info->extack);
	if (ret)
		return ret;

	switch (cipher) {
	case OVPN_CIPHER_ALG_AES_GCM:
	case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
		attr = attrs[OVPN_KEY_DIR_ATTR_CIPHER_KEY];
		if (!attr)
			return -EINVAL;

		dir->cipher_key = nla_data(attr);
		dir->cipher_key_size = nla_len(attr);

		attr = attrs[OVPN_KEY_DIR_ATTR_NONCE_TAIL];
		/* These algorithms require a 96bit nonce,
		 * Construct it by combining 4-bytes packet id and
		 * 8-bytes nonce-tail from userspace
		 */
		if (!attr)
			return -EINVAL;

		dir->nonce_tail = nla_data(attr);
		dir->nonce_tail_size = nla_len(attr);
		break;
	case OVPN_CIPHER_ALG_NONE:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int ovpn_netlink_new_key(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_peer_key_reset pkr;
	struct ovpn_peer *peer;
	int ret;

	if (!info->attrs[OVPN_ATTR_REMOTE_PEER_ID] ||
	    !info->attrs[OVPN_ATTR_KEY_SLOT] ||
	    !info->attrs[OVPN_ATTR_KEY_ID] ||
	    !info->attrs[OVPN_ATTR_CIPHER_ALG] ||
	    !info->attrs[OVPN_ATTR_ENCRYPT_KEY] ||
	    !info->attrs[OVPN_ATTR_DECRYPT_KEY])
		return -EINVAL;

	pkr.remote_peer_id = nla_get_u32(info->attrs[OVPN_ATTR_REMOTE_PEER_ID]);
	pkr.slot = nla_get_u8(info->attrs[OVPN_ATTR_KEY_SLOT]);
	pkr.key.key_id = nla_get_u16(info->attrs[OVPN_ATTR_KEY_ID]);

	pkr.key.cipher_alg = nla_get_u16(info->attrs[OVPN_ATTR_CIPHER_ALG]);

	ret = ovpn_netlink_get_key_dir(info, info->attrs[OVPN_ATTR_ENCRYPT_KEY],
				       pkr.key.cipher_alg, &pkr.key.encrypt);
	if (ret < 0)
		return ret;

	ret = ovpn_netlink_get_key_dir(info, info->attrs[OVPN_ATTR_DECRYPT_KEY],
				       pkr.key.cipher_alg, &pkr.key.decrypt);
	if (ret < 0)
		return ret;

	pkr.crypto_family = ovpn_keys_familiy_get(&pkr.key);

	peer = ovpn_peer_get(ovpn);
	if (!peer)
		return -ENOENT;

	mutex_lock(&peer->crypto.mutex);
	/* get crypto family and check for consistency */
	ret = ovpn_crypto_state_select_family(&peer->crypto, &pkr);
	if (ret < 0) {
		pr_debug("cannot select crypto family for peer\n");
		goto unlock;
	}

	ret = ovpn_crypto_state_reset(&peer->crypto, &pkr);
unlock:
	mutex_unlock(&peer->crypto.mutex);
	ovpn_peer_put(peer);
	return ret;
}

static int ovpn_netlink_del_key(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	enum ovpn_key_slot slot;
	struct ovpn_peer *peer;

	if (!info->attrs[OVPN_ATTR_KEY_SLOT])
		return -EINVAL;

	slot = nla_get_u8(info->attrs[OVPN_ATTR_KEY_SLOT]);

	peer = ovpn_peer_get(ovpn);
	if (!peer)
		return -ENOENT;

	ovpn_crypto_key_slot_delete(&peer->crypto, slot);
	ovpn_peer_put(peer);

	return 0;
}

static int ovpn_netlink_swap_keys(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_peer *peer;

	peer = ovpn_peer_get(ovpn);
	if (!peer)
		return -ENOENT;

	ovpn_crypto_key_slots_swap(&peer->crypto);
	ovpn_peer_put(peer);

	return 0;
}

static void ovpn_netlink_parse_sockaddr4(struct genl_info *info,
					 struct nlattr *attrs[],
					 struct sockaddr_in *sin)
{
	__be32 *addr;

	sin->sin_family = AF_INET;
	sin->sin_port = htons(nla_get_u16(attrs[OVPN_SOCKADDR_ATTR_PORT]));
	addr = nla_data(attrs[OVPN_SOCKADDR_ATTR_ADDRESS]);
	sin->sin_addr.s_addr = *addr;
}

#if IS_ENABLED(CONFIG_IPV6)
static void ovpn_netlink_parse_sockaddr6(struct genl_info *info,
					 struct nlattr *attrs[],
					 struct sockaddr_in6 *sin)
{
	sin->sin6_family = AF_INET6;
	sin->sin6_port = htons(nla_get_u16(attrs[OVPN_SOCKADDR_ATTR_PORT]));
	memcpy(&sin->sin6_addr, nla_data(attrs[OVPN_SOCKADDR_ATTR_ADDRESS]),
	       sizeof(sin->sin6_addr));
}
#endif

static int ovpn_netlink_parse_sockaddr(struct genl_info *info,
				       struct nlattr *key,
				       struct ovpn_sockaddr *sa)
{
	struct nlattr *attrs[OVPN_SOCKADDR_ATTR_MAX + 1];
	size_t addr_len;
	int ret;

	ret = nla_parse_nested(attrs, OVPN_SOCKADDR_ATTR_MAX, key,
			       ovpn_netlink_policy_sockaddr, info->extack);
	if (ret) {
		pr_err("error while parsing sockaddr: %s\n",
		       info->extack ? info->extack->_msg : "null");
		return -EINVAL;
	}

	if (!attrs[OVPN_SOCKADDR_ATTR_ADDRESS] ||
	    !attrs[OVPN_SOCKADDR_ATTR_PORT])
		return -EINVAL;

	/* decide address family based on address length */
	addr_len = nla_len(attrs[OVPN_SOCKADDR_ATTR_ADDRESS]);
	switch (addr_len) {
	case sizeof(struct in_addr):
		sa->family = AF_INET;
		ovpn_netlink_parse_sockaddr4(info, attrs, &sa->u.in4);
		return 0;
#if IS_ENABLED(CONFIG_IPV6)
	case sizeof(struct in6_addr):
		sa->family = AF_INET6;
		ovpn_netlink_parse_sockaddr6(info, attrs, &sa->u.in6);
		return 0;
#endif
	}

	return -EAFNOSUPPORT;
}

static int ovpn_netlink_new_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_sockaddr_pair pair;
	struct ovpn_peer *old, *new;
	struct nlattr *attr;
	int ret;

	if (!info->attrs[OVPN_ATTR_SOCKADDR_REMOTE] ||
	    !info->attrs[OVPN_ATTR_SOCKADDR_LOCAL])
		return -EINVAL;

	memset(&pair, 0, sizeof(pair));

	attr = info->attrs[OVPN_ATTR_SOCKADDR_REMOTE];
	ret = ovpn_netlink_parse_sockaddr(info, attr, &pair.remote);
	if (ret < 0)
		return ret;

	attr = info->attrs[OVPN_ATTR_SOCKADDR_LOCAL];
	ret = ovpn_netlink_parse_sockaddr(info, attr, &pair.local);
	if (ret < 0)
		return ret;

	/* local and remote endpoint must be both IPv4 or IPv6 */
	if (pair.remote.family != pair.local.family)
		return -EINVAL;

	new = ovpn_peer_new_with_sockaddr(ovpn, &pair);
	if (IS_ERR(new)) {
		pr_err("cannot create new peer object for %pIScp\n",
		       &pair.remote.u);
		return PTR_ERR(new);
	}

	spin_lock_bh(&ovpn->lock);
	new->sock = ovpn->sock;
	old = rcu_replace_pointer(ovpn->peer, new,
				  lockdep_is_held(&ovpn->lock));
	if (old)
		ovpn_peer_put(old);
	spin_unlock_bh(&ovpn->lock);

	pr_debug("%s: added peer %pIScp <-> %pIScp\n", __func__,
		 &pair.local.u, &pair.remote.u);

	return 0;
}

static int ovpn_netlink_set_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	bool keepalive_set = false;
	u32 interv, timeout;
	struct ovpn_peer *peer;

	peer = ovpn_peer_get(ovpn);
	if (!peer)
		return -ENOENT;

	/* when setting the keepalive, both parameters have to be configured */
	if (info->attrs[OVPN_ATTR_KEEPALIVE_INTERVAL] &&
	    info->attrs[OVPN_ATTR_KEEPALIVE_TIMEOUT]) {
		keepalive_set = true;
		interv = nla_get_u32(info->attrs[OVPN_ATTR_KEEPALIVE_INTERVAL]);
		timeout = nla_get_u32(info->attrs[OVPN_ATTR_KEEPALIVE_TIMEOUT]);
	}

	if (keepalive_set)
		ovpn_peer_keepalive_set(peer, interv, timeout);

	ovpn_peer_put(peer);
	return 0;
}

/**
 * ovpn_netlink_start_vpn() - Start VPN session
 * @skb: Netlink message with request data
 * @info: receiver information
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int ovpn_netlink_start_vpn(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	enum ovpn_proto proto;
	enum ovpn_mode mode;
	struct socket *sock;
	u32 sockfd;
	int ret;

	if (!info->attrs[OVPN_ATTR_SOCKET] ||
	    !info->attrs[OVPN_ATTR_MODE] ||
	    !info->attrs[OVPN_ATTR_PROTO])
		return -EINVAL;

	if (ovpn->sock)
		return -EBUSY;

	mode = nla_get_u8(info->attrs[OVPN_ATTR_MODE]);
	if (mode != OVPN_MODE_CLIENT)
		return -EOPNOTSUPP;

	proto = nla_get_u8(info->attrs[OVPN_ATTR_PROTO]);
	switch (proto) {
	case OVPN_PROTO_UDP4:
	case OVPN_PROTO_UDP6:
	case OVPN_PROTO_TCP4:
	case OVPN_PROTO_TCP6:
		break;
	default:
		return -EOPNOTSUPP;
	}

	/* lookup the fd in the kernel table and extract the socket object */
	sockfd = nla_get_u32(info->attrs[OVPN_ATTR_SOCKET]);
	/* sockfd_lookup() increases sock's refcounter */
	sock = sockfd_lookup(sockfd, &ret);
	if (!sock) {
		pr_debug("%s: cannot lookup socket passed from userspace: %d\n", __func__, ret);
		return -ENOTSOCK;
	}

	/* make sure the transport protocol matches the socket protocol */
	switch (sock->sk->sk_protocol) {
	case IPPROTO_UDP:
		if (proto == OVPN_PROTO_UDP4 || proto == OVPN_PROTO_UDP6) {
			/* customize sock's internals for ovpn encapsulation */
			ret = ovpn_sock_attach_udp(sock, ovpn);
			if (ret < 0)
				goto sockfd_release;
			break;
		}

		pr_debug("%s: passed UDP socket but VPN is not configured as such\n", __func__);
		ret = -EINVAL;
		goto sockfd_release;
	case IPPROTO_TCP:
		if (proto == OVPN_PROTO_TCP4 || proto == OVPN_PROTO_TCP6)
			break;

		pr_debug("%s: passed TCP socket but VPN is not configured as such\n", __func__);
		ret = -EINVAL;
		goto sockfd_release;
	default:
		pr_debug("%s: unexpected socket protocol: %d\n", __func__, sock->sk->sk_protocol);
		ret = -EINVAL;
		goto sockfd_release;
	}

	ovpn->mode = mode;
	ovpn->proto = proto;
	ovpn->sock = sock;

	pr_debug("%s: mode %u proto %u\n", __func__, ovpn->mode, ovpn->proto);

	return 0;

sockfd_release:
	sockfd_put(sock);
	return ret;
}

static int ovpn_netlink_stop_vpn(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct socket *sock = ovpn->sock;
	struct ovpn_peer *peer;

	if (!sock)
		return -EINVAL;

	ovpn->sock = NULL;
	ovpn_sock_detach(sock);

	spin_lock_bh(&ovpn->lock);
	peer = rcu_replace_pointer(ovpn->peer, NULL,
				   lockdep_is_held(&ovpn->lock));
	if (peer)
		ovpn_peer_delete(peer, OVPN_DEL_PEER_REASON_TEARDOWN);
	spin_unlock_bh(&ovpn->lock);

	ovpn->registered_nl_portid_set = false;

	ovpn->mode = OVPN_MODE_UNDEF;

	return 0;
}

static int ovpn_netlink_register_packet(struct sk_buff *skb,
					struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];

	/* only one registered process per interface is allowed for now */
	if (ovpn->registered_nl_portid_set) {
		pr_debug("%s: userspace listener already registered\n",
			 __func__);
		return -EBUSY;
	}

	pr_debug("%s: registering userspace at %u\n", __func__,
		 info->snd_portid);

	ovpn->registered_nl_portid = info->snd_portid;
	ovpn->registered_nl_portid_set = true;

	return 0;
}

static int ovpn_netlink_packet(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	const u8 *packet;
	size_t len;

	if (!info->attrs[OVPN_ATTR_PACKET]) {
		pr_debug("received netlink packet with no payload\n");
		return -EINVAL;
	}

	len = nla_len(info->attrs[OVPN_ATTR_PACKET]);
	if (len > 1400) {
		pr_debug("netlink packet too large\n");
		return -EINVAL;
	}

	packet = nla_data(info->attrs[OVPN_ATTR_PACKET]);

	pr_debug("%s: sending userspace packet to peer...\n", __func__);

	return ovpn_send_data(ovpn, packet, len);
}

static const struct genl_ops ovpn_netlink_ops[] = {
	{
		.cmd = OVPN_CMD_START_VPN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_start_vpn,
	},
	{
		.cmd = OVPN_CMD_STOP_VPN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_stop_vpn,
	},
	{
		.cmd = OVPN_CMD_NEW_PEER,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_new_peer,
	},
	{
		.cmd = OVPN_CMD_SET_PEER,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_set_peer,
	},
	{
		.cmd = OVPN_CMD_NEW_KEY,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_new_key,
	},
	{
		.cmd = OVPN_CMD_DEL_KEY,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_del_key,
	},
	{
		.cmd = OVPN_CMD_SWAP_KEYS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_swap_keys,
	},
	{
		.cmd = OVPN_CMD_REGISTER_PACKET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_register_packet,
	},
	{
		.cmd = OVPN_CMD_PACKET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_packet,
	},
};

static struct genl_family ovpn_netlink_family __ro_after_init = {
	.hdrsize = 0,
	.name = OVPN_NL_NAME,
	.version = 1,
	.maxattr = OVPN_ATTR_MAX,
	.policy = ovpn_netlink_policy,
	.netnsok = true,
	.pre_doit = ovpn_pre_doit,
	.post_doit = ovpn_post_doit,
	.module = THIS_MODULE,
	.ops = ovpn_netlink_ops,
	.n_ops = ARRAY_SIZE(ovpn_netlink_ops),
	.mcgrps = ovpn_netlink_mcgrps,
	.n_mcgrps = ARRAY_SIZE(ovpn_netlink_mcgrps),
};

int ovpn_netlink_notify_del_peer(struct ovpn_peer *peer)
{
	struct sk_buff *msg;
	void *hdr;
	int ret;

	pr_info("%s: deleting peer, reason %d\n", peer->ovpn->dev->name,
		peer->delete_reason);

	msg = nlmsg_new(100, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &ovpn_netlink_family, 0,
			  OVPN_CMD_DEL_PEER);
	if (!hdr) {
		ret = -ENOBUFS;
		goto err_free_msg;
	}

	if (nla_put_u32(msg, OVPN_ATTR_IFINDEX, peer->ovpn->dev->ifindex)) {
		ret = -EMSGSIZE;
		goto err_free_msg;
	}

	if (nla_put_u8(msg, OVPN_ATTR_DEL_PEER_REASON, peer->delete_reason)) {
		ret = -EMSGSIZE;
		goto err_free_msg;
	}

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&ovpn_netlink_family, dev_net(peer->ovpn->dev),
				msg, 0, OVPN_MCGRP_PEERS, GFP_KERNEL);

	return 0;

err_free_msg:
	nlmsg_free(msg);
	return ret;
}

int ovpn_netlink_send_packet(struct ovpn_struct *ovpn, const uint8_t *buf,
			     size_t len)
{
	struct sk_buff *msg;
	void *hdr;
	int ret;

	if (!ovpn->registered_nl_portid_set) {
		pr_warn_ratelimited("%s: no userspace listener\n", __func__);
		return 0;
	}

	pr_debug("%s: sending packet to userspace, len: %zd\n", __func__, len);
	ovpn_print_hex_debug(buf, len);

	msg = nlmsg_new(100 + len, GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &ovpn_netlink_family, 0,
			  OVPN_CMD_PACKET);
	if (!hdr) {
		ret = -ENOBUFS;
		goto err_free_msg;
	}

	if (nla_put(msg, OVPN_ATTR_PACKET, len, buf)) {
		ret = -EMSGSIZE;
		goto err_free_msg;
	}

	genlmsg_end(msg, hdr);

	return genlmsg_unicast(dev_net(ovpn->dev), msg,
			       ovpn->registered_nl_portid);

err_free_msg:
	nlmsg_free(msg);
	return ret;
}

static int ovpn_netlink_notify(struct notifier_block *nb, unsigned long state,
			       void *_notify)
{
	struct netlink_notify *notify = _notify;
	struct ovpn_struct *ovpn;
	struct net_device *dev;
	struct net *netns;
	bool found = false;

	if (state != NETLINK_URELEASE || notify->protocol != NETLINK_GENERIC)
		return NOTIFY_DONE;

	rcu_read_lock();
	for_each_net_rcu(netns) {
		for_each_netdev_rcu(netns, dev) {
			if (!ovpn_dev_is_valid(dev))
				continue;

			ovpn = netdev_priv(dev);
			if (notify->portid != ovpn->registered_nl_portid)
				continue;

			found = true;
			pr_debug("%s: deregistering userspace listener\n",
				 __func__);
			ovpn->registered_nl_portid_set = false;
			break;
		}
	}
	rcu_read_unlock();

	/* if no interface matched our purposes, pass the notification along */
	if (!found)
		return NOTIFY_DONE;

	return NOTIFY_OK;
}

static struct notifier_block ovpn_netlink_notifier = {
	.notifier_call = ovpn_netlink_notify,
};

int ovpn_netlink_init(struct ovpn_struct *ovpn)
{
	ovpn->registered_nl_portid_set = false;

	return 0;
}

/**
 * ovpn_netlink_register() - register the ovpn genl netlink family
 */
int __init ovpn_netlink_register(void)
{
	int ret;

	ret = genl_register_family(&ovpn_netlink_family);
	if (ret)
		return ret;

	ret = netlink_register_notifier(&ovpn_netlink_notifier);
	if (ret)
		goto err;

	return 0;
err:
	genl_unregister_family(&ovpn_netlink_family);
	return ret;
}

/**
 * ovpn_netlink_unregister() - unregister the ovpn genl netlink family
 */
void __exit ovpn_netlink_unregister(void)
{
	netlink_unregister_notifier(&ovpn_netlink_notifier);
	genl_unregister_family(&ovpn_netlink_family);
}
