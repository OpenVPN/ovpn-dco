// SPDX-License-Identifier: GPL-2.0-only
/*
 *  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#include "main.h"

#include "ovpn.h"
#include "ovpnstruct.h"
#include "debug.h"
#include "netlink.h"

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/version.h>


/*
 * Driver info
 */
#define DRV_NAME	"ovpn-dco"
#define DRV_VERSION	OVPN_DCO_VERSION
#define DRV_DESCRIPTION	"OpenVPN data channel offload (ovpn-dco)"
#define DRV_COPYRIGHT	"(C) 2020 OpenVPN, Inc."

/*
 * per-CPU stats
 */

static void
ovpn_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *tot)
{
	struct ovpn_stats s;
	struct ovpn_struct *ovpn = netdev_priv(dev);

	ovpn_stats_get(ovpn, &s);

	tot->rx_packets += s.rx_packets;
	tot->tx_packets += s.tx_packets;
	tot->rx_bytes += s.rx_bytes;
	tot->tx_bytes += s.tx_bytes;

	tot->rx_errors = dev->stats.rx_errors;
	tot->rx_dropped = dev->stats.rx_dropped;
	tot->rx_frame_errors = dev->stats.rx_frame_errors;

	tot->tx_errors = dev->stats.tx_errors;
	tot->tx_dropped = dev->stats.tx_dropped;
}

/*
 * ovpn_struct release methods
 */

static void ovpn_struct_free(struct net_device *net)
{
	struct ovpn_struct *ovpn = netdev_priv(net);

	ovpn_debug(KERN_INFO, "ovpn_struct_free()");

	ovpn_sock_detach(ovpn->sock);

	security_tun_dev_free_security(ovpn->security);

	debug_log_stats64(ovpn);
	free_percpu(ovpn->stats);

	rcu_barrier();
}

/* lockdep stuff */

static struct lock_class_key ovpn_netdev_xmit_lock_key;
static struct lock_class_key ovpn_netdev_addr_lock_key;
static struct lock_class_key ovpn_tx_busylock_key;

static void ovpn_set_lockdep_class_one(struct net_device *dev,
					struct netdev_queue *txq,
					void *unused)
{
	lockdep_set_class(&txq->_xmit_lock,
			  &ovpn_netdev_xmit_lock_key);
}

static void ovpn_set_lockdep_class(struct net_device *dev)
{
	lockdep_set_class(&dev->addr_list_lock,
			  &ovpn_netdev_addr_lock_key);
	netdev_for_each_tx_queue(dev, ovpn_set_lockdep_class_one, NULL);
	dev->qdisc_tx_busylock_key = ovpn_tx_busylock_key;
}

static int ovpn_net_init(struct net_device *dev)
{
	int ret;

	ovpn_set_lockdep_class(dev);

	ret = security_tun_dev_create();
	if (ret < 0)
		return ret;

	ret = ovpn_struct_init(dev);

	return 0;
}

/* Net device open */
static int ovpn_net_open(struct net_device *dev)
{
	netif_tx_start_all_queues(dev);
	return 0;
}

/* Net device stop -- called prior to device unload */
static int ovpn_net_stop(struct net_device *dev)
{
	netif_tx_stop_all_queues(dev);
	return 0;
}

static int ovpn_net_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < IPV4_MIN_MTU ||
	    new_mtu + dev->hard_header_len > IP_MAX_MTU)
		return -EINVAL;

	dev->mtu = new_mtu;

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
	cmd->base.speed		= SPEED_1000;
	cmd->base.duplex	= DUPLEX_FULL;
	cmd->base.port		= PORT_TP;
	cmd->base.phy_address	= 0;
	cmd->base.transceiver	= XCVR_INTERNAL;
	cmd->base.autoneg	= AUTONEG_DISABLE;
	return 0;
}

static void ovpn_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
	strlcpy(info->bus_info, "ovpn", sizeof(info->bus_info));
}

bool ovpn_dev_is_valid(const struct net_device *dev)
{
	return dev->netdev_ops->ndo_start_xmit == ovpn_net_xmit;
}

/*******************************************
 * ovpn exported methods
 *******************************************/

static const struct net_device_ops ovpn_netdev_ops = {
	.ndo_init		= ovpn_net_init,
	.ndo_change_mtu		= ovpn_net_change_mtu,
	.ndo_open		= ovpn_net_open,
	.ndo_stop		= ovpn_net_stop,
	.ndo_start_xmit		= ovpn_net_xmit,
	.ndo_get_stats64        = ovpn_get_stats64,
};

static const struct ethtool_ops ovpn_ethtool_ops = {
	.get_link_ksettings	= ovpn_get_link_ksettings,
	.get_drvinfo		= ovpn_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_ts_info		= ethtool_op_get_ts_info,
};

static void ovpn_setup(struct net_device *dev)
{
	dev->ethtool_ops = &ovpn_ethtool_ops;
	dev->needs_free_netdev = true;

	dev->netdev_ops = &ovpn_netdev_ops;

	dev->priv_destructor = ovpn_struct_free;

	/* Point-to-Point TUN Device */
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = ETH_DATA_LEN;

	/* Zero header length */
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
	dev->tx_queue_len = OVPN_MAX_DEV_TX_QUEUE_LEN;

	dev->hw_features = NETIF_F_SG | NETIF_F_FRAGLIST;
	dev->hw_features |= NETIF_F_HW_CSUM;
	dev->features = dev->hw_features;
}

static void ovpn_dellink(struct net_device *dev, struct list_head *head)
{
	struct ovpn_struct *ovpn = netdev_priv(dev);
	struct ovpn_peer *peer;

	rcu_read_lock();
	peer = rcu_dereference(ovpn->peer);
	if (peer)
		ovpn_peer_put(peer);
	rcu_read_unlock();

	unregister_netdevice_queue(dev, head); /* calls ovpn_net_uninit */
}

/**
 * ovpn_num_queues - define number of queues to allocate per device
 *
 * The value returned by this function is used to decide how many RX and TX
 * queues to allocate when creating the netdev object
 *
 * Return the number of queues to allocate
 */
static unsigned int ovpn_num_queues(void)
{
	return num_online_cpus();
}

static struct rtnl_link_ops ovpn_link_ops __read_mostly = {
	.kind			= DRV_NAME,
	.priv_size		= sizeof(struct ovpn_struct),
	.setup			= ovpn_setup,
	.dellink		= ovpn_dellink,
	.get_num_tx_queues	= ovpn_num_queues,
	.get_num_rx_queues	= ovpn_num_queues,
};

static int __init ovpn_init(void)
{
	int err = 0;

	printk(KERN_INFO "%s %s -- %s\n", DRV_DESCRIPTION, DRV_VERSION,
	       DRV_COPYRIGHT);

	/* init random secret used to prevent hash collision attacks */
	ovpn_hash_secret_init();

	/* init RTNL link ops */
	err = rtnl_link_register(&ovpn_link_ops);
	if (err) {
		printk(KERN_ERR "ovpn: can't register RTNL link ops\n");
		goto err;
	}

	err = ovpn_netlink_register();
	if (err) {
		printk(KERN_ERR "ovpn: can't register netlink family\n");
		goto err_rtnl_unregister;
	}

	return 0;

err_rtnl_unregister:
	rtnl_link_unregister(&ovpn_link_ops);
err:
	printk(KERN_ERR "ovpn: initialization failed, error status=%d\n", err);
	return err;
}

static __exit void ovpn_cleanup(void)
{
	printk(KERN_INFO "ovpn cleanup\n");
	ovpn_netlink_unregister();
	rtnl_link_unregister(&ovpn_link_ops);
	rcu_barrier(); /* because we use call_rcu */
}

module_init(ovpn_init);
module_exit(ovpn_cleanup);

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
