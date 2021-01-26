// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020-2021 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include "main.h"
#include "ovpn.h"
#include "peer.h"
#include "proto.h"
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

/** Key direction policy. Can be used for configuring an encryption and a decryption key */
static const struct nla_policy ovpn_netlink_policy_key_dir[OVPN_KEY_DIR_ATTR_MAX + 1] = {
	[OVPN_KEY_DIR_ATTR_CIPHER_KEY] = NLA_POLICY_MAX_LEN(U8_MAX),
	[OVPN_KEY_DIR_ATTR_NONCE_TAIL] = NLA_POLICY_EXACT_LEN(NONCE_TAIL_SIZE),
};

/** CMD_NEW_KEY policy */
static const struct nla_policy ovpn_netlink_policy_new_key[OVPN_NEW_KEY_ATTR_MAX + 1] = {
	[OVPN_NEW_KEY_ATTR_PEER_ID] = { .type = NLA_U32 },
	[OVPN_NEW_KEY_ATTR_KEY_SLOT] = NLA_POLICY_RANGE(NLA_U8, __OVPN_KEY_SLOT_FIRST,
							__OVPN_KEY_SLOT_AFTER_LAST - 1),
	[OVPN_NEW_KEY_ATTR_KEY_ID] = { .type = NLA_U8 },
	[OVPN_NEW_KEY_ATTR_CIPHER_ALG] = { .type = NLA_U16 },
	[OVPN_NEW_KEY_ATTR_ENCRYPT_KEY] = NLA_POLICY_NESTED(ovpn_netlink_policy_key_dir),
	[OVPN_NEW_KEY_ATTR_DECRYPT_KEY] = NLA_POLICY_NESTED(ovpn_netlink_policy_key_dir),
};

/** CMD_DEL_KEY policy */
static const struct nla_policy ovpn_netlink_policy_del_key[OVPN_DEL_KEY_ATTR_MAX + 1] = {
	[OVPN_DEL_KEY_ATTR_PEER_ID] = { .type = NLA_U32 },
	[OVPN_DEL_KEY_ATTR_KEY_SLOT] = NLA_POLICY_RANGE(NLA_U8, __OVPN_KEY_SLOT_FIRST,
							__OVPN_KEY_SLOT_AFTER_LAST - 1),
};

/** CMD_SWAP_KEYS policy */
static const struct nla_policy ovpn_netlink_policy_swap_keys[OVPN_SWAP_KEYS_ATTR_MAX + 1] = {
	[OVPN_SWAP_KEYS_ATTR_PEER_ID] = { .type = NLA_U32 },
};

/** CMD_NEW_PEER policy */
static const struct nla_policy ovpn_netlink_policy_new_peer[OVPN_NEW_PEER_ATTR_MAX + 1] = {
	[OVPN_NEW_PEER_ATTR_PEER_ID] = { .type = NLA_U32 },
	[OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE] = NLA_POLICY_MIN_LEN(sizeof(struct sockaddr)),
	[OVPN_NEW_PEER_ATTR_SOCKET] = { .type = NLA_U32 },
	[OVPN_NEW_PEER_ATTR_IPV4] = { .type = NLA_U32 },
	[OVPN_NEW_PEER_ATTR_IPV6] = NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
};

/** CMD_SET_PEER policy */
static const struct nla_policy ovpn_netlink_policy_set_peer[OVPN_SET_PEER_ATTR_MAX + 1] = {
	[OVPN_SET_PEER_ATTR_PEER_ID] = { .type = NLA_U32 },
	[OVPN_SET_PEER_ATTR_KEEPALIVE_INTERVAL] = { .type = NLA_U32 },
	[OVPN_SET_PEER_ATTR_KEEPALIVE_TIMEOUT] = { .type = NLA_U32 },
};

/** CMD_DEL_PEER policy */
static const struct nla_policy ovpn_netlink_policy_del_peer[OVPN_DEL_PEER_ATTR_MAX + 1] = {
	[OVPN_DEL_PEER_ATTR_REASON] = NLA_POLICY_RANGE(NLA_U8, __OVPN_DEL_PEER_REASON_FIRST,
						       __OVPN_DEL_PEER_REASON_AFTER_LAST - 1),
};

/** CMD_PACKET polocy */
static const struct nla_policy ovpn_netlink_policy_packet[OVPN_PACKET_ATTR_MAX + 1] = {
	[OVPN_PACKET_ATTR_PEER_ID] = { .type = NLA_U32 },
	[OVPN_PACKET_ATTR_PACKET] = NLA_POLICY_MAX_LEN(1280),
};

/** Generic message container policy */
static const struct nla_policy ovpn_netlink_policy[OVPN_ATTR_MAX + 1] = {
	[OVPN_ATTR_IFINDEX] = { .type = NLA_U32 },
	[OVPN_ATTR_NEW_PEER] = NLA_POLICY_NESTED(ovpn_netlink_policy_new_peer),
	[OVPN_ATTR_SET_PEER] = NLA_POLICY_NESTED(ovpn_netlink_policy_set_peer),
	[OVPN_ATTR_DEL_PEER] = NLA_POLICY_NESTED(ovpn_netlink_policy_del_peer),
	[OVPN_ATTR_NEW_KEY] = NLA_POLICY_NESTED(ovpn_netlink_policy_new_key),
	[OVPN_ATTR_SWAP_KEYS] = NLA_POLICY_NESTED(ovpn_netlink_policy_swap_keys),
	[OVPN_ATTR_DEL_KEY] = NLA_POLICY_NESTED(ovpn_netlink_policy_del_key),
	[OVPN_ATTR_PACKET] = NLA_POLICY_NESTED(ovpn_netlink_policy_packet),
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
	struct net_device *dev;

	dev = ovpn_get_dev_from_info(net, info);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	info->user_ptr[0] = netdev_priv(dev);

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

	ret = nla_parse_nested(attrs, OVPN_KEY_DIR_ATTR_MAX, key, NULL, info->extack);
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
	struct nlattr *attrs[OVPN_NEW_KEY_ATTR_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_peer_key_reset pkr;
	struct ovpn_peer *peer;
	u32 peer_id;
	int ret;

	ret = nla_parse_nested(attrs, OVPN_NEW_KEY_ATTR_MAX, info->attrs[OVPN_ATTR_NEW_KEY],
			       NULL, info->extack);
	if (ret)
		return ret;

	if (!attrs[OVPN_NEW_KEY_ATTR_PEER_ID] ||
	    !attrs[OVPN_NEW_KEY_ATTR_KEY_SLOT] ||
	    !attrs[OVPN_NEW_KEY_ATTR_KEY_ID] ||
	    !attrs[OVPN_NEW_KEY_ATTR_CIPHER_ALG] ||
	    !attrs[OVPN_NEW_KEY_ATTR_ENCRYPT_KEY] ||
	    !attrs[OVPN_NEW_KEY_ATTR_DECRYPT_KEY])
		return -EINVAL;

	peer_id = nla_get_u32(attrs[OVPN_NEW_KEY_ATTR_PEER_ID]);
	pkr.slot = nla_get_u8(attrs[OVPN_NEW_KEY_ATTR_KEY_SLOT]);
	pkr.key.key_id = nla_get_u16(attrs[OVPN_NEW_KEY_ATTR_KEY_ID]);

	pkr.key.cipher_alg = nla_get_u16(attrs[OVPN_NEW_KEY_ATTR_CIPHER_ALG]);

	ret = ovpn_netlink_get_key_dir(info, attrs[OVPN_NEW_KEY_ATTR_ENCRYPT_KEY],
				       pkr.key.cipher_alg, &pkr.key.encrypt);
	if (ret < 0)
		return ret;

	ret = ovpn_netlink_get_key_dir(info, attrs[OVPN_NEW_KEY_ATTR_DECRYPT_KEY],
				       pkr.key.cipher_alg, &pkr.key.decrypt);
	if (ret < 0)
		return ret;

	pkr.crypto_family = ovpn_keys_familiy_get(&pkr.key);

	peer = ovpn_peer_lookup_id(ovpn, peer_id);
	if (!peer)
		return -ENOENT;

	mutex_lock(&peer->crypto.mutex);
	/* get crypto family and check for consistency */
	ret = ovpn_crypto_state_select_family(&peer->crypto, &pkr);
	if (ret < 0) {
		pr_debug("%s: cannot select crypto family for peer %u\n", __func__, peer_id);
		goto unlock;
	}

	ret = ovpn_crypto_state_reset(&peer->crypto, &pkr);
	if (ret < 0) {
		pr_debug("%s: cannot install new key for peer %u\n", __func__, peer_id);
		goto unlock;
	}

	pr_debug("%s: new key installed (id=%u) for peer %u\n", __func__, pkr.key.key_id, peer_id);
unlock:
	mutex_unlock(&peer->crypto.mutex);
	ovpn_peer_put(peer);
	return ret;
}

static int ovpn_netlink_del_key(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *attrs[OVPN_DEL_KEY_ATTR_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	enum ovpn_key_slot slot;
	struct ovpn_peer *peer;
	u32 peer_id;
	int ret;

	ret = nla_parse_nested(attrs, OVPN_DEL_KEY_ATTR_MAX, info->attrs[OVPN_ATTR_DEL_KEY], NULL,
			       info->extack);
	if (ret)
		return ret;

	if (!attrs[OVPN_DEL_KEY_ATTR_PEER_ID] || !attrs[OVPN_DEL_KEY_ATTR_KEY_SLOT])
		return -EINVAL;

	peer_id = nla_get_u32(attrs[OVPN_DEL_KEY_ATTR_PEER_ID]);
	slot = nla_get_u8(attrs[OVPN_DEL_KEY_ATTR_KEY_SLOT]);

	peer = ovpn_peer_lookup_id(ovpn, peer_id);
	if (!peer)
		return -ENOENT;

	ovpn_crypto_key_slot_delete(&peer->crypto, slot);
	ovpn_peer_put(peer);

	return 0;
}

static int ovpn_netlink_swap_keys(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *attrs[OVPN_SWAP_KEYS_ATTR_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_peer *peer;
	u32 peer_id;
	int ret;

	ret = nla_parse_nested(attrs, OVPN_SWAP_KEYS_ATTR_MAX, info->attrs[OVPN_ATTR_SWAP_KEYS],
			       NULL, info->extack);
	if (ret)
		return ret;

	if (!attrs[OVPN_SWAP_KEYS_ATTR_PEER_ID])
		return -EINVAL;

	peer_id = nla_get_u32(attrs[OVPN_SWAP_KEYS_ATTR_PEER_ID]);

	peer = ovpn_peer_lookup_id(ovpn, peer_id);
	if (!peer)
		return -ENOENT;

	ovpn_crypto_key_slots_swap(&peer->crypto);
	ovpn_peer_put(peer);

	return 0;
}

static int ovpn_netlink_new_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *attrs[OVPN_NEW_PEER_ATTR_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_peer *peer;
	struct sockaddr *sa;
	struct socket *sock;
	size_t sa_len;
	u32 sockfd;
	int ret;

	ret = nla_parse_nested(attrs, OVPN_NEW_PEER_ATTR_MAX, info->attrs[OVPN_ATTR_NEW_PEER], NULL,
			       info->extack);
	if (ret)
		return ret;

	if (!attrs[OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE] || !attrs[OVPN_NEW_PEER_ATTR_SOCKET])
		return -EINVAL;

	if (!attrs[OVPN_NEW_PEER_ATTR_IPV4] && !attrs[OVPN_NEW_PEER_ATTR_IPV6]) {
		pr_err("%s: can't add peer with no VPN IP\n", __func__);
		return -EINVAL;
	}

	sa = nla_data(attrs[OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE]);
	sa_len = nla_len(attrs[OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE]);
	switch (sa_len) {
	case sizeof(struct sockaddr_in):
		if (sa->sa_family != AF_INET)
			return -EINVAL;
		break;
	case sizeof(struct sockaddr_in6):
		if (sa->sa_family != AF_INET6)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	/* lookup the fd in the kernel table and extract the socket object */
	sockfd = nla_get_u32(attrs[OVPN_NEW_PEER_ATTR_SOCKET]);
	/* sockfd_lookup() increases sock's refcounter */
	sock = sockfd_lookup(sockfd, &ret);
	if (!sock) {
		pr_debug("%s: cannot lookup peer socket: %d\n", __func__, ret);
		return -ENOTSOCK;
	}

	peer = ovpn_peer_new_with_sockaddr(ovpn, sa, sock);
	if (IS_ERR(peer)) {
		pr_err("%s: cannot create new peer object for %pIScp\n", __func__, sa);
		ret = PTR_ERR(peer);
		goto sockfd_release;
	}

	if (attrs[OVPN_NEW_PEER_ATTR_IPV4]) {
		if (nla_len(attrs[OVPN_NEW_PEER_ATTR_IPV4]) != sizeof(struct in_addr)) {
			ret = -EINVAL;
			goto peer_release;
		}

		peer->vpn_addrs.ipv4.s_addr = nla_get_be32(attrs[OVPN_NEW_PEER_ATTR_IPV4]);
	}

	if (attrs[OVPN_NEW_PEER_ATTR_IPV6]) {
		if (nla_len(attrs[OVPN_NEW_PEER_ATTR_IPV6]) != sizeof(struct in6_addr)) {
			ret = -EINVAL;
			goto peer_release;
		}

		memcpy(&peer->vpn_addrs.ipv6, nla_data(attrs[OVPN_NEW_PEER_ATTR_IPV6]),
		       sizeof(struct in6_addr));
	}

	ret = ovpn_peer_add(ovpn, peer);
	if (ret < 0) {
		pr_err("%s: cannot add new peer to hashtable: %d\n", __func__, ret);
		goto peer_release;
	}

	pr_debug("%s: added peer endpoint=%pIScp id=%d VPN-IPv4=%pI4 VPN-IPv6=%pI6c\n", __func__,
		 sa, peer->id, &peer->vpn_addrs.ipv4.s_addr, &peer->vpn_addrs.ipv6);

	return 0;

peer_release:
	/* release right away because peer is not really used in any context */
	ovpn_peer_release(peer);
sockfd_release:
	sockfd_put(sock);
	return ret;
}

static int ovpn_netlink_set_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *attrs[OVPN_SET_PEER_ATTR_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	u32 peer_id, interv, timeout;
	bool keepalive_set = false;
	struct ovpn_peer *peer;
	int ret;

	ret = nla_parse_nested(attrs, OVPN_SET_PEER_ATTR_MAX, info->attrs[OVPN_ATTR_SET_PEER], NULL,
			       info->extack);
	if (ret)
		return ret;

	if (!attrs[OVPN_SET_PEER_ATTR_PEER_ID])
		return -EINVAL;

	peer_id = nla_get_u32(attrs[OVPN_SET_PEER_ATTR_PEER_ID]);

	peer = ovpn_peer_lookup_id(ovpn, peer_id);
	if (!peer)
		return -ENOENT;

	/* when setting the keepalive, both parameters have to be configured */
	if (attrs[OVPN_SET_PEER_ATTR_KEEPALIVE_INTERVAL] &&
	    attrs[OVPN_SET_PEER_ATTR_KEEPALIVE_TIMEOUT]) {
		keepalive_set = true;
		interv = nla_get_u32(attrs[OVPN_SET_PEER_ATTR_KEEPALIVE_INTERVAL]);
		timeout = nla_get_u32(attrs[OVPN_SET_PEER_ATTR_KEEPALIVE_TIMEOUT]);
	}

	if (keepalive_set)
		ovpn_peer_keepalive_set(peer, interv, timeout);

	ovpn_peer_put(peer);
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
	struct nlattr *attrs[OVPN_PACKET_ATTR_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	const u8 *packet;
	u32 peer_id;
	size_t len;
	int ret;

	ret = nla_parse_nested(attrs, OVPN_PACKET_ATTR_MAX, info->attrs[OVPN_ATTR_PACKET],
			       NULL, info->extack);
	if (ret)
		return ret;

	if (!attrs[OVPN_PACKET_ATTR_PACKET] || !attrs[OVPN_PACKET_ATTR_PEER_ID]) {
		pr_debug("received netlink packet with no payload\n");
		return -EINVAL;
	}

	peer_id = nla_get_u32(attrs[OVPN_PACKET_ATTR_PEER_ID]);

	len = nla_len(attrs[OVPN_PACKET_ATTR_PACKET]);
	if (len > 1280) {
		pr_debug("netlink packet too large\n");
		return -EINVAL;
	}

	packet = nla_data(attrs[OVPN_PACKET_ATTR_PACKET]);

	pr_debug("%s: sending userspace packet to peer...\n", __func__);

	return ovpn_send_data(ovpn, peer_id, packet, len);
}

static const struct genl_ops ovpn_netlink_ops[] = {
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

	if (nla_put_u8(msg, OVPN_DEL_PEER_ATTR_REASON, peer->delete_reason)) {
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
