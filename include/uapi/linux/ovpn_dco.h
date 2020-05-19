/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 */

#ifndef _UAPI_LINUX_OVPN_DCO_H_
#define _UAPI_LINUX_OVPN_DCO_H_

#define OVPN_NL_NAME "ovpn-dco"

/**
 * enum ovpn_nl_commands - supported netlink commands
 */
enum ovpn_nl_commands {
	/**
	 * @OVPN_CMD_UNSPEC: unspecified command to catch errors
	 */
	OVPN_CMD_UNSPEC = 0,

	/**
	 * @OVPN_CMD_START_VPN: Start VPN session
	 */
	OVPN_CMD_START_VPN,

	/**
	 * @OVPN_CMD_STOP_VPN: Stop VPN session
	 */
	OVPN_CMD_STOP_VPN,

	/**
	 * @OVPN_CMD_NEW_PEER: Configure peer with its crypto keys
	 */
	OVPN_CMD_NEW_PEER,

	/**
	 * @OVPN_CMD_SET_PEER: Tweak parameters for an existing peer
	 */
	OVPN_CMD_SET_PEER,

	/**
	 * @OVPN_CMD_DEL_PEER: Remove peer from internal table
	 */
	OVPN_CMD_DEL_PEER,

	OVPN_CMD_NEW_KEY,

	OVPN_CMD_DEL_KEY,

	/**
	 * @OVPN_CMD_REGISTER_PACKET: Register for specific packet types to be
	 * forwarded to userspace
	 */
	OVPN_CMD_REGISTER_PACKET,

	/**
	 * @OVPN_CMD_PACKET: Send a packet from userspace to kernelspace. Also
	 * used to send to userspace packets for which a process had registered
	 * with OVPN_CMD_REGISTER_PACKET
	 */
	OVPN_CMD_PACKET,
};

enum ovpn_mode {
	OVPN_MODE_CLIENT = 0,
	OVPN_MODE_SERVER,
};

enum ovpn_proto {
	OVPN_PROTO_UDP4,
	OVPN_PROTO_UDP6,
	OVPN_PROTO_TCP4,
	OVPN_PROTO_TCP6,
};

enum ovpn_cipher_alg {
	OVPN_CIPHER_ALG_AES_GCM = 0,
	OVPN_CIPHER_ALG_AES_CBC,
};

enum ovpn_hmac_alg {
	OVPN_HMAC_ALG_SHA128 = 0,
	OVPN_HMAC_ALG_SHA256,
	OVPN_HMAC_ALG_SHA512,
};

enum ovpn_key_slot {
	__OVPN_KEY_SLOT_FIRST,
	OVPN_KEY_SLOT_PRIMARY = __OVPN_KEY_SLOT_FIRST,
	OVPN_KEY_SLOT_SECONDARY,
	__OVPN_KEY_SLOT_AFTER_LAST,
};

enum ovpn_key_dir_attrs {
	OVPN_KEY_DIR_ATTR_UNSPEC,

	OVPN_KEY_DIR_ATTR_CIPHER_KEY,
	OVPN_KEY_DIR_ATTR_HMAC_KEY,
	OVPN_KEY_DIR_ATTR_NONCE_TAIL,
	__OVPN_KEY_DIR_ATTR_AFTER_LAST,
	OVPN_KEY_DIR_ATTR_MAX = __OVPN_KEY_DIR_ATTR_AFTER_LAST - 1,
};

enum ovpn_sockaddr_attrs {
	OVPN_SOCKADDR_ATTR_UNSPEC,

	OVPN_SOCKADDR_ATTR_ADDRESS,
	OVPN_SOCKADDR_ATTR_PORT,
	__OVPN_SOCKADDR_ATTR_AFTER_LAST,
	OVPN_SOCKADDR_ATTR_MAX = __OVPN_SOCKADDR_ATTR_AFTER_LAST,
};

enum ovpn_attrs {
	OVPN_ATTR_UNSPEC,

	OVPN_ATTR_IFINDEX,

	OVPN_ATTR_MODE,
	OVPN_ATTR_SOCKET,
	OVPN_ATTR_PROTO,

	OVPN_ATTR_REMOTE_PEER_ID,

	OVPN_ATTR_KEY_SLOT,
	OVPN_ATTR_CIPHER_ALG,
	OVPN_ATTR_HMAC_ALG,
	OVPN_ATTR_ENCRYPT_KEY,
	OVPN_ATTR_DECRYPT_KEY,
	OVPN_ATTR_KEY_ID,

	OVPN_ATTR_SOCKADDR_REMOTE,
	OVPN_ATTR_SOCKADDR_LOCAL,

	OVPN_ATTR_PACKET,

	__OVPN_ATTR_AFTER_LAST,
	OVPN_ATTR_MAX = __OVPN_ATTR_AFTER_LAST - 1,
};

#endif /* _UAPI_LINUX_OVPN_DCO_H_ */
