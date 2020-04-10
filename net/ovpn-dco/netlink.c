// SPDX-License-Identifier: GPL-2.0-only
/*
 *  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include "main.h"
#include "peer.h"
#include "debug.h"
#include "netlink.h"
#include "ovpnstruct.h"

#include <uapi/linux/ovpn_dco.h>

#include <linux/netlink.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <net/genetlink.h>
#include <uapi/linux/in.h>

static struct genl_family ovpn_netlink_family __ro_after_init;

static const struct nla_policy
ovpn_netlink_policy_key_dir[OVPN_KEY_DIR_ATTR_MAX + 1] = {
	[OVPN_KEY_DIR_ATTR_CIPHER_KEY] = { .type = NLA_BINARY, .len = U8_MAX },
	[OVPN_KEY_DIR_ATTR_HMAC_KEY] = { .type = NLA_BINARY, .len = U8_MAX },
	[OVPN_KEY_DIR_ATTR_NONCE_TAIL] = { .type = NLA_BINARY, .len = 12 },
};

static const struct nla_policy
ovpn_netlink_policy_key[OVPN_KEY_ATTR_MAX + 1] = {
	[OVPN_KEY_ATTR_CIPHER_ALG] = { .type = NLA_U16 },
	[OVPN_KEY_ATTR_HMAC_ALG] = { .type = NLA_U16 },
	[OVPN_KEY_ATTR_ENCRYPT] =
		NLA_POLICY_NESTED(ovpn_netlink_policy_key_dir),
	[OVPN_KEY_ATTR_DECRYPT] =
		NLA_POLICY_NESTED(ovpn_netlink_policy_key_dir),
	[OVPN_KEY_ATTR_ID] = { .type = NLA_U16 },
};

static const struct nla_policy
ovpn_netlink_policy_sockaddr[OVPN_SOCKADDR_ATTR_MAX + 1] = {
	/* IPv4 only supported for now */
	[OVPN_SOCKADDR_ATTR_ADDRESS] = { .type = NLA_BINARY, .len = 4 },
	[OVPN_SOCKADDR_ATTR_PORT] = { .type = NLA_U16 },
};

static const struct nla_policy ovpn_netlink_policy[OVPN_ATTR_MAX + 1] = {
	[OVPN_ATTR_IFINDEX] = { .type = NLA_U32 },
	[OVPN_ATTR_MODE] = { .type = NLA_U8 },
	[OVPN_ATTR_SOCKET] = { .type = NLA_U32 },
	[OVPN_ATTR_PROTO] = { .type = NLA_U8 },
	[OVPN_ATTR_KEY_PRIMARY] = NLA_POLICY_NESTED(ovpn_netlink_policy_key),
	[OVPN_ATTR_KEY_SECONDARY] = NLA_POLICY_NESTED(ovpn_netlink_policy_key),
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

static int ovpn_netlink_copy_key_dir(struct genl_info *info,
				     struct nlattr *key,
				     struct ovpn_key_direction *dir)
{
	struct nlattr *attrs[OVPN_KEY_DIR_ATTR_MAX + 1];
	int ret;

	ret = nla_parse_nested(attrs, OVPN_KEY_DIR_ATTR_MAX, key,
			       ovpn_netlink_policy_key_dir, info->extack);
	if (ret)
		return ret;

	if (!attrs[OVPN_KEY_DIR_ATTR_CIPHER_KEY] ||
	    !attrs[OVPN_KEY_DIR_ATTR_HMAC_KEY])
		return -EINVAL;

	dir->cipher_key = nla_data(attrs[OVPN_KEY_DIR_ATTR_CIPHER_KEY]);
	dir->cipher_key_size = nla_len(attrs[OVPN_KEY_DIR_ATTR_CIPHER_KEY]);
	dir->hmac_key = nla_data(attrs[OVPN_KEY_DIR_ATTR_HMAC_KEY]);
	dir->hmac_key_size = nla_len(attrs[OVPN_KEY_DIR_ATTR_HMAC_KEY]);

	if (attrs[OVPN_KEY_DIR_ATTR_NONCE_TAIL]) {
		uint8_t *data;
		size_t len;

		data = nla_data(attrs[OVPN_KEY_DIR_ATTR_NONCE_TAIL]);
		len = nla_len(attrs[OVPN_KEY_DIR_ATTR_NONCE_TAIL]);

		memcpy(dir->nonce_tail, data, len);
	}

	return 0;
}

static struct ovpn_key_config *
ovpn_netlink_copy_key_config(struct genl_info *info, struct nlattr *key)
{
	struct nlattr *attrs[OVPN_KEY_ATTR_MAX + 1];
	enum ovpn_cipher_alg cipher;
	struct ovpn_key_config *kc;
	int ret;

	ret = nla_parse_nested(attrs, OVPN_KEY_ATTR_MAX, key,
			       ovpn_netlink_policy_key, info->extack);
	if (ret)
		return ERR_PTR(-EINVAL);

	if (!attrs[OVPN_KEY_ATTR_CIPHER_ALG] ||
	    !attrs[OVPN_KEY_ATTR_ID] ||
	    !attrs[OVPN_KEY_ATTR_ENCRYPT] ||
	    !attrs[OVPN_KEY_ATTR_DECRYPT])
		return ERR_PTR(-EINVAL);

	/* only AES-GCM is allowed to have no auth algorithm */
	cipher = nla_get_u16(attrs[OVPN_KEY_ATTR_CIPHER_ALG]);
	if (cipher != OVPN_CIPHER_ALG_AES_GCM &&
	    !attrs[OVPN_KEY_ATTR_HMAC_ALG])
		return ERR_PTR(-EINVAL);

	kc = kcalloc(1, sizeof(*kc), GFP_KERNEL);
	if (!kc)
		return ERR_PTR(-ENOMEM);

	kc->cipher_alg = cipher;
	kc->hmac_alg = nla_get_u16(attrs[OVPN_KEY_ATTR_HMAC_ALG]);
	kc->key_id = nla_get_u16(attrs[OVPN_KEY_ATTR_ID]);

	ret = ovpn_netlink_copy_key_dir(info, attrs[OVPN_KEY_ATTR_ENCRYPT],
					&kc->encrypt);
	if (ret < 0)
		goto err_free;

	ret = ovpn_netlink_copy_key_dir(info,
					attrs[OVPN_KEY_ATTR_DECRYPT],
					&kc->decrypt);
	if (ret < 0)
		goto err_free;

	return kc;
err_free:
	kfree(kc);
	return ERR_PTR(ret);
}

static int ovpn_netlink_copy_keys(struct ovpn_peer_keys_reset *keys,
				  struct genl_info *info)
{
	struct nlattr *attr;

	keys->primary = NULL;
	keys->secondary = NULL;

	attr = info->attrs[OVPN_ATTR_KEY_PRIMARY];
	if (attr) {
		keys->primary = ovpn_netlink_copy_key_config(info, attr);
		if (IS_ERR(keys->primary))
			return PTR_ERR(keys->primary);
	}

	attr = info->attrs[OVPN_ATTR_KEY_SECONDARY];
	if (attr) {
		keys->secondary = ovpn_netlink_copy_key_config(info, attr);
		if (IS_ERR(keys->primary)) {
			ovpn_key_config_free(keys->primary);
			return PTR_ERR(keys->secondary);
		}
	}

	return 0;
}

static int ovpn_netlink_set_keys(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	const struct ovpn_crypto_ops *cops;
	struct ovpn_peer_keys_reset keys;
	struct ovpn_peer *peer;
	int ret;

	peer = ovpn_peer_get(ovpn);
	if (!peer)
		return -ENOENT;

	ret = ovpn_netlink_copy_keys(&keys, info);
	if (ret < 0)
		goto release_peer;

	/* grab peer mutex */
	mutex_lock(&peer->mutex);

	/* get crypto family and check for consistency */
	cops = ovpn_crypto_state_select_family(peer, &keys, &ret);
	if (ret < 0)
		goto unlock_mutex;

	if (!cops) {
		ovpn_peer_keys_reset_free(&keys);
		keys.primary = NULL;
		keys.secondary = NULL;
	}

	ret = ovpn_crypto_state_reset(&peer->crypto, &keys, peer);

unlock_mutex:
	mutex_unlock(&peer->mutex);
	ovpn_peer_keys_reset_free(&keys);
release_peer:
	ovpn_peer_put(peer);
	return ret;
}

static int ovpn_netlink_parse_sockaddr(struct genl_info *info,
				       struct nlattr *key,
				       struct sockaddr_in *sin)
{
	struct nlattr *attrs[OVPN_SOCKADDR_ATTR_MAX + 1];
	__be32 *addr;
	int err;

	err = nla_parse_nested(attrs, OVPN_SOCKADDR_ATTR_MAX, key,
			       ovpn_netlink_policy_sockaddr, info->extack);
	if (err)
		return -EINVAL;

	if (!attrs[OVPN_SOCKADDR_ATTR_ADDRESS] ||
	    !attrs[OVPN_SOCKADDR_ATTR_PORT])
		return -EINVAL;

	/* assume IPv4 as that's the only supported family for now */
	sin->sin_family = AF_INET;
	sin->sin_port = nla_get_be16(attrs[OVPN_SOCKADDR_ATTR_PORT]);

	if (nla_len(attrs[OVPN_SOCKADDR_ATTR_ADDRESS]) != 4)
		return -EINVAL;

	addr = nla_data(attrs[OVPN_SOCKADDR_ATTR_ADDRESS]);
	sin->sin_addr.s_addr = *addr;

	ovpn_debug(KERN_INFO, "ovpn_netlink_parse_sockaddr: addr=%pI4 port=%hu",
		   &sin->sin_addr.s_addr, ntohs(sin->sin_port));

	return 0;
}

static int ovpn_netlink_add_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_sockaddr_pair pair;
	struct ovpn_peer *old, *new;
	int ret;

	if (!info->attrs[OVPN_ATTR_SOCKADDR_REMOTE] ||
	    !info->attrs[OVPN_ATTR_SOCKADDR_LOCAL])
		return -EINVAL;

	pair.remote.family = AF_INET;
	ret = ovpn_netlink_parse_sockaddr(info,
					  info->attrs[OVPN_ATTR_SOCKADDR_REMOTE],
					  &pair.remote.u.in4);
	if (ret < 0)
		return ret;

	ret = ovpn_netlink_parse_sockaddr(info,
					  info->attrs[OVPN_ATTR_SOCKADDR_LOCAL],
					  &pair.local.u.in4);
	if (ret < 0)
		return ret;

	new = ovpn_peer_new_with_sockaddr(ovpn, &pair);
	if (IS_ERR(new))
		return PTR_ERR(new);

	spin_lock(&ovpn->lock);
	old = rcu_dereference_protected(ovpn->peer,
					lockdep_is_held(&ovpn->lock));
	if (old)
		ovpn_peer_put(old);

	new->sock = ovpn->sock;
	rcu_assign_pointer(ovpn->peer, new);
	spin_unlock(&ovpn->lock);

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
	struct socket *sock;
	uint32_t sockfd;
	int ret;

	if (!info->attrs[OVPN_ATTR_SOCKET] ||
	    !info->attrs[OVPN_ATTR_MODE] ||
	    !info->attrs[OVPN_ATTR_PROTO])
		return -EINVAL;

	if (ovpn->sock)
		return -EBUSY;

	ovpn->mode = nla_get_u8(info->attrs[OVPN_ATTR_MODE]);
	if (ovpn->mode != OVPN_MODE_CLIENT)
		return -ENOTSUPP;

	ovpn->proto = nla_get_u8(info->attrs[OVPN_ATTR_PROTO]);
	if (ovpn->proto != OVPN_PROTO_UDP4)
		return -ENOTSUPP;

	/* lookup the fd in the kernel table and extract the socket object */
	sockfd = nla_get_u32(info->attrs[OVPN_ATTR_SOCKET]);
	/* sockfd_lookup() increases sock's refcounter */
	sock = sockfd_lookup(sockfd, &ret);
	if (!sock)
		return ret;

	/* only UDP is supported for now */
	if (sock->sk->sk_protocol != IPPROTO_UDP) {
		ret = -EINVAL;
		goto sockfd_release;
	}

	/* customize sock's internals for ovpn encapsulation */
	ret = ovpn_sock_attach_udp(ovpn, sock);
	if (ret < 0)
		goto sockfd_release;

	ovpn->sock = sock;

	return 0;

sockfd_release:
	sockfd_put(sock);
	return ret;
}

static int ovpn_netlink_stop_vpn(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_peer *peer;

	if (!ovpn->sock)
		return -EINVAL;

	ovpn_sock_detach(ovpn->sock);
	ovpn->sock = NULL;

	spin_lock(&ovpn->lock);
	peer = rcu_dereference_protected(ovpn->peer,
					 lockdep_is_held(&ovpn->lock));
	rcu_assign_pointer(ovpn->peer, NULL);
	ovpn_peer_put(peer);
	spin_unlock(&ovpn->lock);

	ovpn->registered_nl_portid_set = false;

	return 0;
}

static int ovpn_netlink_register_packet(struct sk_buff *skb,
					struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];

	/* Only one registered process per interface is allowed for now.
	 * In case of double registration, the latter will cancel the previous
	 * one
	 */
	ovpn->registered_nl_portid = info->snd_portid;
	ovpn->registered_nl_portid_set = true;

	return 0;
}

int ovpn_netlink_send_packet(struct ovpn_struct *ovpn, const uint8_t *buf,
			     size_t len)
{
	struct sk_buff *msg;
	void *hdr;
	int ret;

	if (!ovpn->registered_nl_portid_set)
		return 0;

	msg = nlmsg_new(100 + len, GFP_KERNEL);
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
		.cmd = OVPN_CMD_ADD_PEER,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_add_peer,
	},
	{
		.cmd = OVPN_CMD_SET_KEYS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_set_keys,
	},
	{
		.cmd = OVPN_CMD_REGISTER_PACKET,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_ADMIN_PERM,
		.doit = ovpn_netlink_register_packet,
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
	.n_ops = ARRAY_SIZE(ovpn_netlink_ops)
};

/**
 * ovpn_netlink_register() - register the ovpn genl netlink family
 */
int __init ovpn_netlink_register(void)
{
	return genl_register_family(&ovpn_netlink_family);
}

/**
 * ovpn_netlink_unregister() - unregister the ovpn genl netlink family
 */
void __exit ovpn_netlink_unregister(void)
{
	genl_unregister_family(&ovpn_netlink_family);
}
