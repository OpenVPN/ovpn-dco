// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020-2023 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#include "main.h"

#include "io.h"
#include "ovpnstruct.h"
#include "netlink.h"
#include "tcp.h"

#include <linux/ethtool.h>
#include <linux/genetlink.h>
#include <linux/inetdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include <net/ip_tunnels.h>

/* Driver info */
#define DRV_NAME	"ovpn"
#define DRV_VERSION	OVPN_VERSION
#define DRV_DESCRIPTION	"OpenVPN data channel offload (ovpn)"
#define DRV_COPYRIGHT	"(C) 2020-2023 OpenVPN, Inc."

static LIST_HEAD(dev_list);

static void ovpn_struct_free(struct net_device *net)
{
	struct ovpn_struct *ovpn = netdev_priv(net);

	printk("CALLING DESTRUCTOR ON %s\n", net->name);

	switch (ovpn->mode) {
	case OVPN_MODE_P2P:
		ovpn_peer_release_p2p(ovpn);
		break;
	default:
		ovpn_peers_free(ovpn);
		break;
	}

	security_tun_dev_free_security(ovpn->security);
	free_percpu(net->tstats);
	flush_workqueue(ovpn->crypto_wq);
	flush_workqueue(ovpn->events_wq);
	destroy_workqueue(ovpn->crypto_wq);
	destroy_workqueue(ovpn->events_wq);
	rcu_barrier();
}

/* Net device open */
static int ovpn_net_open(struct net_device *dev)
{
	struct in_device *dev_v4 = __in_dev_get_rtnl(dev);

	if (dev_v4) {
		/* disable redirects as Linux gets confused by ovpn handling same-LAN routing */
		IN_DEV_CONF_SET(dev_v4, SEND_REDIRECTS, false);
		IPV4_DEVCONF_ALL(dev_net(dev), SEND_REDIRECTS) = false;
	}

	netif_tx_start_all_queues(dev);
	return 0;
}

/* Net device stop -- called prior to device unload */
static int ovpn_net_stop(struct net_device *dev)
{
	netif_tx_stop_all_queues(dev);
	return 0;
}

/*******************************************
 * ovpn ethtool ops
 *******************************************/

static int ovpn_get_link_ksettings(struct net_device *dev,
				   struct ethtool_link_ksettings *cmd)
{
	ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.supported, 0);
	ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.advertising, 0);
	cmd->base.speed	= SPEED_1000;
	cmd->base.duplex = DUPLEX_FULL;
	cmd->base.port = PORT_TP;
	cmd->base.phy_address = 0;
	cmd->base.transceiver = XCVR_INTERNAL;
	cmd->base.autoneg = AUTONEG_DISABLE;

	return 0;
}

static void ovpn_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	strscpy(info->driver, DRV_NAME, sizeof(info->driver));
	strscpy(info->version, DRV_VERSION, sizeof(info->version));
	strscpy(info->bus_info, "ovpn", sizeof(info->bus_info));
}

bool ovpn_dev_is_valid(const struct net_device *dev)
{
	return dev->netdev_ops->ndo_start_xmit == ovpn_net_xmit;
}

/*******************************************
 * ovpn exported methods
 *******************************************/

static const struct net_device_ops ovpn_netdev_ops = {
	.ndo_open		= ovpn_net_open,
	.ndo_stop		= ovpn_net_stop,
	.ndo_start_xmit		= ovpn_net_xmit,
	.ndo_get_stats64        = dev_get_tstats64,
};

static const struct ethtool_ops ovpn_ethtool_ops = {
	.get_link_ksettings	= ovpn_get_link_ksettings,
	.get_drvinfo		= ovpn_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_ts_info		= ethtool_op_get_ts_info,
};

static void ovpn_setup(struct net_device *dev)
{
	/* compute the overhead considering AEAD encryption */
	const int overhead = sizeof(u32) + NONCE_WIRE_SIZE + 16 + sizeof(struct udphdr) +
			     max(sizeof(struct ipv6hdr), sizeof(struct iphdr));

	netdev_features_t feat = NETIF_F_SG | NETIF_F_LLTX |
				 NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_GSO |
				 NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA;

	dev->ethtool_ops = &ovpn_ethtool_ops;
	dev->needs_free_netdev = true;

	dev->netdev_ops = &ovpn_netdev_ops;

	dev->priv_destructor = ovpn_struct_free;

	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = ETH_DATA_LEN - overhead;
	dev->min_mtu = IPV4_MIN_MTU;
	dev->max_mtu = IP_MAX_MTU - overhead;

	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;

	dev->features |= feat;
	dev->hw_features |= feat;
	dev->hw_enc_features |= feat;

	dev->needed_headroom = OVPN_HEAD_ROOM;
	dev->needed_tailroom = OVPN_MAX_PADDING;
}

int ovpn_iface_create(const char *name, enum ovpn_mode mode, struct net *net)
{
	struct net_device *dev;
	struct ovpn_struct *ovpn;
	int ret;

	dev = alloc_netdev(sizeof(struct ovpn_struct), name, NET_NAME_USER, ovpn_setup);

	dev_net_set(dev, net);

	ret = ovpn_struct_init(dev);
	if (ret < 0)
		goto err;

	ovpn = netdev_priv(dev);
	ovpn->mode = mode;

	printk("LOCKING\n");
	rtnl_lock();

	printk("REGISTERING!\n");
	ret = register_netdevice(dev);
	if (ret < 0) {
		netdev_dbg(dev, "cannot register interface %s: %d\n", dev->name, ret);
		rtnl_unlock();
		goto err;
	}
	printk("UNLOCKING!\n");
	rtnl_unlock();

	return ret;

err:
	free_netdev(dev);
	return ret;
}

void ovpn_iface_destruct(struct ovpn_struct *ovpn, bool unregister_netdev)
{
	ASSERT_RTNL();

	dev_put(ovpn->dev);
	list_del(&ovpn->dev_list);
	ovpn->registered = false;
	if (unregister_netdev)
		unregister_netdevice(ovpn->dev);
}

static int ovpn_netdev_notifier_call(struct notifier_block *nb,
				     unsigned long state, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct ovpn_struct *ovpn;

	if (!ovpn_dev_is_valid(dev))
		return NOTIFY_DONE;

	ovpn = netdev_priv(dev);

	switch (state) {
	case NETDEV_POST_INIT:
		printk("==> POST_INIT! %s\n", dev->name);
		break;
	case NETDEV_REGISTER:
		printk("==> REGISTER! %s\n", dev->name);
		list_add(&ovpn->dev_list, &dev_list);
		ovpn->registered = true;
		break;
	case NETDEV_UNREGISTER:
		printk("==> UNREGISTER! %s\n", dev->name);
		/* can be deleivered multiple times, so check registered flag */
		if (!ovpn->registered)
			return NOTIFY_DONE;

		ovpn_iface_destruct(ovpn, false);
		break;
	case NETDEV_GOING_DOWN:
		printk("==> GOING DOWN! %s\n", dev->name);
		/* cancel work */
		break;
	case NETDEV_DOWN:
		printk("==> DOWN! %s\n", dev->name);
		break;
	case NETDEV_UP:
		printk("==> UP! %s\n", dev->name);
		break;
	case NETDEV_PRE_UP:
		printk("==> PRE_UP %s\n", dev->name);
			//return notifier_from_errno(-EOPNOTSUPP);
		break;
	default:
		printk("==> UNKNOWN: %lu %s\n", state, dev->name);
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

static struct notifier_block ovpn_netdev_notifier = {
	.notifier_call = ovpn_netdev_notifier_call,
};

/*static void ovpn_ns_pre_exit(struct net *net)
{
	struct ovpn_struct *ovpn;

	rtnl_lock();
	list_for_each_entry(ovpn, &dev_list, dev_list) {
		if (dev_net(ovpn->dev) != net)
			continue;

		netif_carrier_off(ovpn->dev);
		ovpn_iface_destruct(ovpn);
		dev_net_set(ovpn->dev, NULL);
	}
	rtnl_unlock();
}*/

/*static struct pernet_operations pernet_ops = {
	.pre_exit = ovpn_ns_pre_exit
};*/

static int __init ovpn_init(void)
{
	int err = 0;

	pr_info("%s %s -- %s\n", DRV_DESCRIPTION, DRV_VERSION, DRV_COPYRIGHT);

	err = ovpn_tcp_init();
	if (err) {
		pr_err("ovpn: can't initialize TCP subsystem\n");
		return err;
	}

	err = ovpn_nl_register();
	if (err) {
		pr_err("ovpn: can't register netlink family: %d\n", err);
		return err;
	}

	err = register_netdevice_notifier(&ovpn_netdev_notifier);
	if (err) {
		pr_err("ovpn: can't register netdevice notifier: %d\n", err);
		goto unreg_nl;
	}

/*	err = register_pernet_device(&pernet_ops);
	if (err) {
		pr_err("ovpn: can't register pernet ops: %d\n", err);
		goto unreg_nl;
	}
	*/

	return 0;

unreg_nl:
	ovpn_nl_unregister();
	return err;
}

static __exit void ovpn_cleanup(void)
{
//	unregister_pernet_device(&pernet_ops);
	unregister_netdevice_notifier(&ovpn_netdev_notifier);
	ovpn_nl_unregister();
	rcu_barrier(); /* because we use call_rcu */
}

module_init(ovpn_init);
module_exit(ovpn_cleanup);

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_ALIAS_GENL_FAMILY(OVPN_NL_NAME);
