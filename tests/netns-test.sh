#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020 OpenVPN, Inc.
#
#  Author:	Antonio Quartulli <antonio@openvpn.net>

set -x
set -e

OVPN_CLI=./ovpn-cli
ALG=${ALG:-aes}

function create_ns() {
	ip -n peer$1 link del tun0 || true
	ip -n peer$1 link del veth$1 || true
	ip netns del peer$1 || true
	ip netns add peer$1
}

function setup_ns() {
	ip link set veth$1 netns peer$1
	ip -n peer$1 addr add $2/$3 dev veth$1
	ip -n peer$1 link set veth$1 up
	if [ $ipv6 -eq 1 ]; then
		sleep 5
	fi

	ip -n peer$1 link add tun0 type ovpn-dco
	ip -n peer$1 addr add $4 dev tun0
	ip -n peer$1 link set tun0 up

	if [ $tcp -eq 0 ]; then
#		ip netns exec peer$1 $OVPN_CLI tun0 start_udp $5 $9
		ip netns exec peer$1 $OVPN_CLI tun0 new_peer $5 $6 $7 $8
		ip netns exec peer$1 $OVPN_CLI tun0 new_key $ALG $1 data64.key
	else
		if [ $1 -eq 0 ]; then
			(ip netns exec peer$1 $OVPN_CLI tun0 listen $5 $8 && \
				ip netns exec peer$1 $OVPN_CLI tun0 new_key $ALG $1 data64.key) &
		else
			ip netns exec peer$1 $OVPN_CLI tun0 connect $6 $7
			ip netns exec peer$1 $OVPN_CLI tun0 new_key $ALG $1 data64.key
		fi
	fi
}

create_ns 0
create_ns 1

ip link del veth0 || true
ip link add veth0 type veth peer name veth1

ipv6=0
if [ "$1" == "-6" ]; then
	ipv6=1
	shift
fi

tcp=0
if [ "$1" == "-t" ]; then
	tcp=1
	shift
fi


if [ $ipv6 -eq 1 ]; then
	setup_ns 0 fc00::1 64 5.5.5.1/24 1 fc00::2 2 5.5.5.2 ipv6
	setup_ns 1 fc00::2 64 5.5.5.2/24 2 fc00::1 1 5.5.5.1 ipv6
else
	setup_ns 0 10.10.10.1 24 5.5.5.1/24 1 10.10.10.2 2 5.5.5.2
	setup_ns 1 10.10.10.2 24 5.5.5.2/24 2 10.10.10.1 1 5.5.5.1
fi

ip netns exec peer0 ping -c 3 5.5.5.2
