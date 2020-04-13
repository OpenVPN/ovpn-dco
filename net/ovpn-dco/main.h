// SPDX-License-Identifier: GPL-2.0-only
/*
 *  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2019-2020 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */


#ifndef _NET_OVPN_DCO_MAIN_H_
#define _NET_OVPN_DCO_MAIN_H_


#ifndef OVPN_DCO_VERSION
#define OVPN_DCO_VERSION "2.0.0"
#endif

#define DEBUG_FREE		0
#define DEBUG_CRYPTO		0
#define DEBUG_PEER_BY_ID	0
#define DEBUG_CPU_SWITCH	0
#define DEBUG_PING		0
#define DEBUG_IN		0
#define DEBUG_DTAB		0
#define DEBUG_MTU		0
#define DEBUG_ERR_VERBOSE	0

/*
 * Our UDP encapsulation types, must be unique
 * (other values in include/uapi/linux/udp.h)
 */
#define UDP_ENCAP_OVPNINUDP 100  /* transport layer */

/*
 * If 1, filter replay packets
 */
#define ENABLE_REPLAY_PROTECTION 1

#include <linux/cache.h>
#include <linux/kref.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>

static __cacheline_aligned_in_smp DEFINE_MUTEX(ovpn_config_mutex);

struct net_device;
bool ovpn_dev_is_valid(const struct net_device *dev);

static const unsigned char ovpn_keepalive_message[] = {
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

static const unsigned char ovpn_explicit_exit_notify_message[] = {
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
	6 // OCC_EXIT
};

void ovpn_release_lock(struct kref *kref);

/*
 * Structs for passing info to API methods via ioctl
 */

/* for OVPN_DEV_INIT */

/* max allowed parameter values */
#define OVPN_MAX_PEERS                1000000
#define OVPN_MAX_DEV_QUEUES           0x1000
#define OVPN_MAX_DEV_TX_QUEUE_LEN     0x10000
#define OVPN_MAX_TUN_QUEUE_LEN        0x10000
#define OVPN_MAX_TCP_SEND_QUEUE_LEN   0x10000
#define OVPN_MAX_THROTTLE_PERIOD_MS   10000

/* ovpn_peer_keys_reset.op values */

enum ovpn_key_op {
/* Assign primary key (may be NULL to reset),
   leave secondary key unchanged */
	OVPN_DCO_KEY_OP_PRIMARY_ONLY = 0,
/* Assign secondary key (may be NULL to reset),
   leave primary key unchanged */
	OVPN_DCO_KEY_OP_SECONDARY_ONLY,
/* Assign both primary and secondary keys
   (either may be NULL to reset) */
	OVPN_DCO_KEY_OP_BOTH,
/* Assign primary key (may be NULL to reset),
   atomically move previous primary key to secondary */
	OVPN_DCO_KEY_OP_PRIMARY_ASSIGN_MOVE,
/* Swap primary and secondary keys */
	OVPN_DCO_KEYS_PRIMARY_SECONDARY_SWAP,
};

/* ovpn_peer_keys_reset.crypto_family values */
#define OVPN_CRYPTO_FAMILY_UNDEF    0
#define OVPN_CRYPTO_FAMILY_AEAD     1
#define OVPN_CRYPTO_FAMILY_CBC_HMAC 2

/* pass to OVPN_PEER_KEYS_RESET */
struct ovpn_peer_keys_reset {
	int crypto_family;                  /* see OVPN_CRYPTO_FAMILY_x above */
	int peer_id;                        /* peer ID */
	int op;                             /* see OVPN_KEYS_x values above */
	struct ovpn_key_config *primary;    /* primary key */
	struct ovpn_key_config *secondary;  /* secondary key */
};

/*
 * 64-bit tun header
 */

/* struct ovpn_tun_head types */
#define OVPN_TH_TRANS_BY_PEER_ID       0
#define OVPN_TH_TRANS_BY_SOCKADDR_PAIR 1
#define OVPN_TH_NOTIFY_STATUS          2
#define OVPN_TH_NOTIFY_PKTID_WRAP_WARN 3
#define OVPN_TH_NOTIFY_DATA_LIMIT      4
#define OVPN_TH_NOTIFY_FLOAT           5
#define OVPN_TH_NOTIFY_RES             6

struct ovpn_tun_head {
	u8 type;          /* OVPN_TH_x */
	u8 status;        /* OVPN_STATUS_x for OVPN_TH_NOTIFY_STATUS */
	u16 reserved;
	u32 peer_id;
} __attribute__ ((__packed__));

/* OVPN_TH_NOTIFY_STATUS variant of ovpn_tun_head */
struct ovpn_tun_head_status {
	struct ovpn_tun_head head;
	u64 rx_bytes;
	u64 tx_bytes;
};

/* OVPN_TH_NOTIFY_PKTID_WRAP_WARN variant of ovpn_tun_head */
struct ovpn_tun_head_pktid_wrap {
	struct ovpn_tun_head head;
	unsigned int key_id;      /* key ID that is close to wrapping */
};

/*
 * OVPN_TH_NOTIFY_DATA_LIMIT variant of ovpn_tun_head.
 * All flags below set in head.status.
 */
#define OVPN_CDL_STATUS_KEY_ID_MASK    0x7    /* key ID */
#define OVPN_CDL_STATUS_DECRYPT        0x8    /* decrypt if set, otherwise encrypt */
#define OVPN_CDL_STATUS_RED            0x10   /* red data limit if set, otherwise green limit */
struct ovpn_tun_head_data_limit {
	struct ovpn_tun_head head;
};

/* ovpn error codes */

enum {
	/* ioctl parameter errors */
	OVPN_ERR_PARM_IS_NULL=200,
	OVPN_ERR_PARM_SIZE,
	OVPN_ERR_DEV_NAME,
	OVPN_ERR_IV_SIZE,
	OVPN_ERR_PEER_KEYS_RESET_OP,
	OVPN_ERR_PEER_NOT_FOUND,
	OVPN_ERR_PEER_ID_OUT_OF_RANGE,
	OVPN_ERR_PEER_LOOKUP_OUT_OF_RANGE,
	OVPN_ERR_BAD_CIPHER_ALG,
	OVPN_ERR_BAD_HMAC_ALG,
	OVPN_ERR_BAD_CRYPTO_FAMILY,
	OVPN_ERR_BAD_COMP_ALG,
	OVPN_ERR_MAX_DECOMP_SIZE,
	OVPN_ERR_TOO_MANY_ROUTES,
	OVPN_ERR_MSSFIX,
	OVPN_ERR_QUEUE_ORDER,

	/* OVPN_PEER_NEW_WITH_SOCKADDR errors */
	OVPN_ERR_PEER_EXISTS,

	/* capacity limits */
	OVPN_ERR_MAX_PEERS_EXCEEDED,
	OVPN_ERR_MAX_QUEUES_EXCEEDED,
	OVPN_ERR_THROTTLE_DROP,

	/* IP version errors */
	OVPN_ERR_IPVER_NOTIMP,
	OVPN_ERR_IPVER_INCONSISTENT,

	/* bad packet errors */
	OVPN_ERR_NULL_IP_PKT,
	OVPN_ERR_IP_HEADER_LEN,
	OVPN_ERR_BOGUS_PKT_LEN,
	OVPN_ERR_SKB_NOT_ENOUGH_HEADROOM,
	OVPN_ERR_SKB_COPY,
	OVPN_ERR_ORPHAN_FRAGS,

        /* address/binding errors */
	OVPN_ERR_ADDR4_ZERO,
	OVPN_ERR_ADDR4_MUST_BE_UDP,
	OVPN_ERR_ADDR6_MUST_BE_UDP,
	OVPN_ERR_ADDR4_BIND,
	OVPN_ERR_ADDR6_BIND,

	/* transport/socket errors */
	OVPN_ERR_BAD_SOCK,
	OVPN_ERR_SOCK_MUST_BE_UDP,
	OVPN_ERR_SOCK_MUST_BE_TCP,
	OVPN_ERR_SOCK_NOT_ESTABLISHED,
	OVPN_ERR_SOCK_ENCAP_EXISTS,
	OVPN_ERR_SOCK_UNKNOWN_ENCAP,
	OVPN_ERR_NO_TRANSPORT_SOCK,
	OVPN_ERR_TRANSPORT_ADDR_CONFLICT,
	OVPN_ERR_NO_PEER_BINDING,
	OVPN_ERR_TCP_SEND_QUEUE_OVERFLOW,
	OVPN_ERR_TCP_MAX_PKT_SIZE,

	/* tun socket errors */
	OVPN_ERR_TUN_HEAD,
	OVPN_ERR_TUN_QUEUE_FULL,

	/* routing errors */
	OVPN_ERR_ROUTE_NOT_OWNED_BY_PEER,
	OVPN_ERR_ROUTE_NOT_CANONICAL,
	OVPN_ERR_ROUTE_ID,
	OVPN_ERR_ROUTING_MODEL_CONFLICT,
	OVPN_ERR_BAD_PREFIX_LEN,
	OVPN_ERR_ROUTE_CONFLICT,
	OVPN_ERR_PEER_LOOKUP_VANISHED,
	OVPN_ERR_PEER_LOOKUP_NO_ROUTE,
	OVPN_ERR_PEER_LOOKUP_NO_ROUTE2,
	OVPN_ERR_PEER_LOOKUP_INTERNAL,
	OVPN_ERR_RTMARK_MISS,
	OVPN_ERR_RX_STEERING_MISS,
	OVPN_ERR_TRANSPORT_STEERING_MISS,
	OVPN_ERR_USERSPACE_STEERING_MISS,
	OVPN_ERR_RX_CPU_SWITCH,
	OVPN_ERR_TRANSPORT_CPU_SWITCH,
	OVPN_ERR_INCOMING_PROHIBITED,
	OVPN_ERR_INTERN_ERR_DROP,
	OVPN_ERR_SHIM_DROP,

	/* crypto errors */
	OVPN_ERR_CRYPTO_EBUSY,
	OVPN_ERR_DECRYPTION_FAILED,
	OVPN_ERR_HMAC,
	OVPN_ERR_RANDOM,
	OVPN_ERR_PKCS7_PADDING,
	OVPN_ERR_NO_PRIMARY_KEY,
	OVPN_ERR_DATA_V1_REQUIRED,
	OVPN_ERR_DATA_V2_REQUIRED,
	OVPN_ERR_DATA_V1_V2_REQUIRED,
	OVPN_ERR_ENCRYPT_COW_HEAD,
	OVPN_ERR_ENCRYPT_COW_DATA,
	OVPN_ERR_DECRYPT_PKT_SIZE,
	OVPN_ERR_DECRYPT_COW_DATA,
	OVPN_ERR_NFRAGS,
	OVPN_ERR_NO_EXISTING_KEYS,

	/* compress errors */
	OVPN_ERR_PULL_COMPRESS_OP,
	OVPN_ERR_PUSH_COMPRESS_OP,
	OVPN_ERR_DIDNT_COMPRESS,
	OVPN_ERR_NO_DECOMPRESS_METHOD,
	OVPN_ERR_COMPRESS,
	OVPN_ERR_DECOMPRESS,

	/* packet ID replay protection */
	OVPN_ERR_PKTID_REPLAY,
	OVPN_ERR_PKTID_ID_BACKTRACK,
	OVPN_ERR_PKTID_TIME_BACKTRACK,
	OVPN_ERR_PKTID_EXPIRE,
	OVPN_ERR_PKTID_ID_ZERO,
	OVPN_ERR_PKTID_WRAP,
	OVPN_ERR_PKTID_WRAP_WARN,

	/* TCP linear mode */
	OVPN_ERR_TCPLIN_PKTID,
	OVPN_ERR_TCPLIN_QUEUE,

	/* problems getting context */
	OVPN_ERR_NO_CONTEXT,
	OVPN_ERR_NO_OVPN_CONTEXT,
	OVPN_ERR_NO_OVPN_FILE_CONTEXT,
	OVPN_ERR_NO_CRYPTO_CONTEXT,
	OVPN_ERR_NO_CRYPTO_OPS,
	OVPN_ERR_CANNOT_GRAB_OVPN_REF,
	OVPN_ERR_CANNOT_GRAB_FILE_REF,
	OVPN_ERR_CANNOT_GRAB_PEER_REF,
	OVPN_ERR_CANNOT_GRAB_CRYPTO_REF,
	OVPN_ERR_OVPN_FILE_HALT,

	/* connection errors */
	OVPN_ERR_KEEPALIVE_TIMEOUT,
	OVPN_ERR_EXPLICIT_EXIT,
	OVPN_ERR_USURPED,
	OVPN_ERR_ADDR_IN_USE,
	OVPN_ERR_TCP_SOCK,
	OVPN_ERR_TCP_CRYPTO,
	OVPN_ERR_DISCONNECT,
	OVPN_ERR_USERSPACE_HALT,

	/* markers */
	OVPN_ERR_LAST,
};

#endif /* _NET_OVPN_DCO_OVPN_DCO_H_ */
