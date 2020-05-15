#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020 OpenVPN, Inc.
#
#  Author:	Antonio Quartulli <antonio@openvpn.net>

set -x

OVPN_CLI=./ovpn-cli

function create_ns() {
	ip -n peer$1 link del tun0
	ip -n peer$1 link del veth$1
	ip netns del peer$1
	ip netns add peer$1
}

function setup_ns() {
	ip link set veth$1 netns peer$1
	ip -n peer$1 addr add $2/$3 dev veth$1
	ip -n peer$1 link set veth$1 up

	ip -n peer$1 link add tun0 type ovpn-dco
	ip -n peer$1 addr add $4 dev tun0
	ip -n peer$1 link set tun0 up

	ip netns exec peer$1 $OVPN_CLI tun0 start $5 $8
	ip netns exec peer$1 $OVPN_CLI tun0 new_peer $2 $5 $6 $7
	ip netns exec peer$1 $OVPN_CLI tun0 new_key $1 data64.key
}

create_ns 0
create_ns 1

ip link del veth0
ip link add veth0 type veth peer veth1

if [ "$1" == "-6" ]; then
	setup_ns 0 fc00::1 64 5.5.5.1/24 1 fc00::2 2 ipv6
	setup_ns 1 fc00::2 64 5.5.5.2/24 2 fc00::1 1 ipv6
else
	setup_ns 0 10.10.10.1 24 5.5.5.1/24 1 10.10.10.2 2
	setup_ns 1 10.10.10.2 24 5.5.5.2/24 2 10.10.10.1 1
fi
