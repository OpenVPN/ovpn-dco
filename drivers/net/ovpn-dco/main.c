// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#include "main.h"

#include "ovpn.h"
#include "ovpnstruct.h"
#include "netlink.h"

#include <linux/genetlink.h>
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
#define DRV_NAME	"ovpn-dco"
#define DRV_VERSION	OVPN_DCO_VERSION
#define DRV_DESCRIPTION	"OpenVPN data channel offload (ovpn-dco)"
#define DRV_COPYRIGHT	"(C) 2020 OpenVPN, Inc."

static void ovpn_struct_free(struct net_device *net)
{
	struct ovpn_struct *ovpn = netdev_priv(net);

	ovpn_sock_detach(ovpn->sock);
	security_tun_dev_free_security(ovpn->security);
	free_percpu(net->tstats);
	flush_workqueue(ovpn->crypto_wq);
	flush_workqueue(ovpn->events_wq);
	destroy_workqueue(ovpn->crypto_wq);
	destroy_workqueue(ovpn->events_wq);
	rcu_barrier();
}

static int ovpn_net_init(struct net_device *dev)
{
	int ret;

	ret = security_tun_dev_create();
	if (ret < 0)
		return ret;

	return ovpn_struct_init(dev);
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
	.ndo_get_stats64        = ip_tunnel_get_stats64,
};

static const struct ethtool_ops ovpn_ethtool_ops = {
	.get_link_ksettings	= ovpn_get_link_ksettings,
	.get_drvinfo		= ovpn_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_ts_info		= ethtool_op_get_ts_info,
};

static void ovpn_setup(struct net_device *dev)
{
	netdev_features_t feat = NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_LLTX |
				 NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_GSO |
				 NETIF_F_GSO_SOFTWARE;

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

	dev->features |= feat;
	dev->hw_features |= feat;
	dev->hw_enc_features |= feat;

	dev->needed_headroom = OVPN_HEAD_ROOM;
	dev->needed_tailroom = OVPN_MAX_PADDING;
}

static void ovpn_dellink(struct net_device *dev, struct list_head *head)
{
	struct ovpn_struct *ovpn = netdev_priv(dev);
	struct ovpn_peer *peer;

	spin_lock_bh(&ovpn->lock);
	peer = ovpn_peer_get(ovpn);
	if (peer) {
		RCU_INIT_POINTER(ovpn->peer, NULL);
		ovpn_peer_delete(peer, OVPN_DEL_PEER_REASON_TEARDOWN);
		ovpn_peer_put(peer);
	}
	spin_unlock_bh(&ovpn->lock);

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

	pr_info("%s %s -- %s\n", DRV_DESCRIPTION, DRV_VERSION, DRV_COPYRIGHT);

	/* init random secret used to prevent hash collision attacks */
	ovpn_hash_secret_init();

	/* init RTNL link ops */
	err = rtnl_link_register(&ovpn_link_ops);
	if (err) {
		pr_err("ovpn: can't register RTNL link ops\n");
		goto err;
	}

	err = ovpn_netlink_register();
	if (err) {
		pr_err("ovpn: can't register netlink family\n");
		goto err_rtnl_unregister;
	}

	return 0;

err_rtnl_unregister:
	rtnl_link_unregister(&ovpn_link_ops);
err:
	pr_err("ovpn: initialization failed, error status=%d\n", err);
	return err;
}

static __exit void ovpn_cleanup(void)
{
	rtnl_link_unregister(&ovpn_link_ops);
	ovpn_netlink_unregister();
	rcu_barrier(); /* because we use call_rcu */
}

module_init(ovpn_init);
module_exit(ovpn_cleanup);

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
MODULE_ALIAS_GENL_FAMILY(OVPN_NL_NAME);
