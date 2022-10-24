/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 *  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2022 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _UAPI_LINUX_OVPN_DCO_H_
#define _UAPI_LINUX_OVPN_DCO_H_

#define OVPN_NL_NAME "ovpn-dco"

#define OVPN_NL_MULTICAST_GROUP_PEERS "peers"

/**
 * enum ovpn_nl_commands - supported netlink commands
 */
enum ovpn_nl_commands {
	/**
	 * @OVPN_CMD_UNSPEC: unspecified command to catch errors
	 */
	OVPN_CMD_UNSPEC = 0,
	/**
	 * @OVPN_CMD_NEW_IFACE: create a new OpenVPN interface
	 */
	OVPN_CMD_NEW_IFACE,
	/**
	 * @OVPN_CMD_DEL_IFACE: delete an existing OpenVPN interface
	 */
	OVPN_CMD_DEL_IFACE,
	/**
	 * @OVPN_CMD_SET_PEER: create or update a peer
	 */
	OVPN_CMD_SET_PEER,
	/**
	 * @OVPN_CMD_GET_PEER: retrieve the status of a peer or all peers
	 */
	OVPN_CMD_GET_PEER,
	/**
	 * @OVPN_CMD_DEL_PEER: remove a peer
	 */
	OVPN_CMD_DEL_PEER,
	/**
	 * @OVPN_CMD_SET_KEY: create or update an existing key in the specified key slot
	 */
	OVPN_CMD_SET_KEY,
	/**
	 * @OVPN_CMD_SWAP_KEYS: swap keys stored in primary and secondary slots
	 */
	OVPN_CMD_SWAP_KEYS,
	/**
	 * @OVPN_CMD_DEL_KEY: delete the key stored in the specified key slot
	 */
	OVPN_CMD_DEL_KEY,
};

enum ovpn_cipher_alg {
	/**
	 * @OVPN_CIPHER_ALG_NONE: No encryption - reserved for debugging only
	 */
	OVPN_CIPHER_ALG_NONE = 0,
	/**
	 * @OVPN_CIPHER_ALG_AES_GCM: AES-GCM AEAD cipher with any allowed key size
	 */
	OVPN_CIPHER_ALG_AES_GCM,
	/**
	 * @OVPN_CIPHER_ALG_CHACHA20_POLY1305: ChaCha20Poly1305 AEAD cipher
	 */
	OVPN_CIPHER_ALG_CHACHA20_POLY1305,
};

enum ovpn_del_peer_reason {
	__OVPN_DEL_PEER_REASON_FIRST,
	OVPN_DEL_PEER_REASON_TEARDOWN = __OVPN_DEL_PEER_REASON_FIRST,
	OVPN_DEL_PEER_REASON_USERSPACE,
	OVPN_DEL_PEER_REASON_EXPIRED,
	OVPN_DEL_PEER_REASON_TRANSPORT_ERROR,

	/* new attrs above this line */
	NUM_OVPN_DEL_PEER_REASON
};

enum ovpn_key_slot {
	__OVPN_KEY_SLOT_FIRST = 0,
	OVPN_KEY_SLOT_PRIMARY = __OVPN_KEY_SLOT_FIRST,
	OVPN_KEY_SLOT_SECONDARY,

	/* new attrs above this line */
	NUM_OVPN_KEY_SLOT
};

enum ovpn_mode {
	__OVPN_MODE_FIRST = 0,
	OVPN_MODE_P2P = __OVPN_MODE_FIRST,
	OVPN_MODE_MP,

	/* new attrs above this line */
	NUM_OVPN_MODE
};


enum ovpn_nl_attrs {
	OVPN_A_UNSPEC = 0,
	OVPN_A_IFINDEX,
	OVPN_A_IFNAME,
	OVPN_A_PEER,

	/* new attrs above this line */
	NUM_OVPN_A
};

enum ovpn_nl_peer_attrs {
	OVPN_A_PEER_UNSPEC = 0,
	OVPN_A_PEER_ID,
	OVPN_A_PEER_RX_STATS,
	OVPN_A_PEER_TX_STATS,
	OVPN_A_PEER_SOCKADDR_REMOTE,
	OVPN_A_PEER_SOCKET,
	OVPN_A_PEER_VPN_IPV4,
	OVPN_A_PEER_VPN_IPV6,
	OVPN_A_PEER_LOCAL_IP,
	OVPN_A_PEER_LOCAL_PORT,
	OVPN_A_PEER_KEEPALIVE_INTERVAL,
	OVPN_A_PEER_KEEPALIVE_TIMEOUT,
	OVPN_A_PEER_DEL_REASON,
	OVPN_A_PEER_KEYCONF,
	OVPN_A_PEER_RX_BYTES,
	OVPN_A_PEER_TX_BYTES,
	OVPN_A_PEER_RX_PACKETS,
	OVPN_A_PEER_TX_PACKETS,

	/* new attrs above this line */
	NUM_OVPN_A_PEER
};

enum ovpn_nl_keyconf_attrs {
	OVPN_A_KEYCONF_UNSPEC = 0,
	OVPN_A_KEYCONF_SLOT,
	OVPN_A_KEYCONF_KEY_ID,
	OVPN_A_KEYCONF_CIPHER_ALG,
	OVPN_A_KEYCONF_ENCRYPT_DIR,
	OVPN_A_KEYCONF_DECRYPT_DIR,

	/* new attrs above this line */
	NUM_OVPN_A_KEYCONF
};

enum ovpn_nl_keydir_attrs {
	OVPN_A_KEYDIR_UNSPEC = 0,
	OVPN_A_KEYDIR_CIPHER_KEY,
	OVPN_A_KEYDIR_NONCE_TAIL,

	/* new attrs above this line */
	NUM_OVPN_A_KEYDIR
};

#endif /* _UAPI_LINUX_OVPN_DCO_H_ */
