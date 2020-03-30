/*
 *  OVPN -- OpenVPN protocol accelerator for Linux
 *  Copyright (C) 2012-2020 OpenVPN Technologies, Inc.
 *  All rights reserved.
 *  Author: James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_DCO_OVPNRCU_H_
#define _NET_OVPN_DCO_OVPNRCU_H_

static inline void ovpn_rcu_lockdep_assert_held(void)
{
#ifdef CONFIG_PROVE_RCU
	RCU_LOCKDEP_WARN(!rcu_read_lock_held(), "kovpn RCU read lock not held");
#endif
}

#endif /* _NET_OVPN_DCO_OVPNRCU_H_ */
