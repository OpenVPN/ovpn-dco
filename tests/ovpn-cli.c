// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include <linux/ovpn_dco.h>
#include <linux/types.h>

#include <mbedtls/base64.h>
#include <mbedtls/error.h>

/* libnl < 3.5.0 does not set the NLA_F_NESTED on its own, therefore we
 * have to explicitly do it to prevent the kernel from failing upon
 * parsing of the message
 */
#define nla_nest_start(_msg, _type) \
	nla_nest_start(_msg, (_type) | NLA_F_NESTED)

typedef int (*ovpn_nl_cb)(struct nl_msg *msg, void *arg);

enum ovpn_key_direction {
	KEY_DIR_IN = 0,
	KEY_DIR_OUT,
};

#define KEY_LEN (256 / 8)
#define NONCE_LEN 12

struct nl_ctx {
	struct nl_sock *nl_sock;
	struct nl_msg *nl_msg;
	struct nl_cb *nl_cb;

	int ovpn_dco_id;
};

struct ovpn_ctx {
	__u8 key_enc[KEY_LEN];
	__u8 key_dec[KEY_LEN];
	__u8 nonce[NONCE_LEN];

	sa_family_t sa_family;

	union {
		struct in_addr in4;
		struct in6_addr in6;
	} local;
	__u16 lport;

	union {
		struct in_addr in4;
		struct in6_addr in6;
	} remote;
	__u16 rport;

	unsigned int ifindex;

	int socket;

	__u32 keepalive_interval;
	__u32 keepalive_timeout;

	enum ovpn_key_direction key_dir;
};

static int ovpn_nl_recvmsgs(struct nl_ctx *ctx)
{
	int ret;

	ret = nl_recvmsgs(ctx->nl_sock, ctx->nl_cb);

	switch (ret) {
	case -NLE_INTR:
		fprintf(stderr,
			"netlink received interrupt due to signal - ignoring\n");
		break;
	case -NLE_NOMEM:
		fprintf(stderr, "netlink out of memory error\n");
		break;
	case -NLE_AGAIN:
		fprintf(stderr,
			"netlink reports blocking read - aborting wait\n");
		break;
	default:
		if (ret)
			fprintf(stderr, "netlink reports error (%d): %s\n",
				ret, nl_geterror(-ret));
		break;
	}

	return ret;
}

static struct nl_ctx *nl_ctx_alloc(struct ovpn_ctx *ovpn,
				   enum ovpn_nl_commands cmd)
{
	struct nl_ctx *ctx;
	int ret;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->nl_sock = nl_socket_alloc();
	if (!ctx->nl_sock) {
		fprintf(stderr, "cannot allocate netlink socket\n");
		goto err_free;
	}

	nl_socket_set_buffer_size(ctx->nl_sock, 8192, 8192);

	ret = genl_connect(ctx->nl_sock);
	if (ret) {
		fprintf(stderr, "cannot connect to generic netlink: %s\n",
			nl_geterror(ret));
		goto err_sock;
	}

	ctx->ovpn_dco_id = genl_ctrl_resolve(ctx->nl_sock, OVPN_NL_NAME);
	if (ctx->ovpn_dco_id < 0) {
		fprintf(stderr, "cannot find ovpn_dco netlink component: %d\n",
			ctx->ovpn_dco_id);
		goto err_free;
	}

	ctx->nl_msg = nlmsg_alloc();
	if (!ctx->nl_msg) {
		fprintf(stderr, "cannot allocate netlink message\n");
		goto err_sock;
	}

	ctx->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!ctx->nl_cb) {
		fprintf(stderr, "failed to allocate netlink callback\n");
		goto err_msg;
	}

	nl_socket_set_cb(ctx->nl_sock, ctx->nl_cb);

	genlmsg_put(ctx->nl_msg, 0, 0, ctx->ovpn_dco_id, 0, 0, cmd, 0);
	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_IFINDEX, ovpn->ifindex);

	return ctx;
nla_put_failure:
err_msg:
	nlmsg_free(ctx->nl_msg);
err_sock:
	nl_socket_free(ctx->nl_sock);
err_free:
	free(ctx);
	return NULL;
}

static void nl_ctx_free(struct nl_ctx *ctx)
{
	if (!ctx)
		return;

	nl_socket_free(ctx->nl_sock);
	nlmsg_free(ctx->nl_msg);
	nl_cb_put(ctx->nl_cb);
	free(ctx);
}

static int ovpn_nl_cb_error(struct sockaddr_nl (*nla)__attribute__((unused)),
			    struct nlmsgerr *err, void *arg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
	struct nlattr *tb_msg[NLMSGERR_ATTR_MAX + 1];
	int len = nlh->nlmsg_len;
	struct nlattr *attrs;
	int *ret = arg;
	int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

	*ret = err->error;

	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return NL_STOP;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		ack_len += err->msg.nlmsg_len - sizeof(*nlh);

	if (len <= ack_len)
		return NL_STOP;

	attrs = (void *)((unsigned char *)nlh + ack_len);
	len -= ack_len;

	nla_parse(tb_msg, NLMSGERR_ATTR_MAX, attrs, len, NULL);
	if (tb_msg[NLMSGERR_ATTR_MSG]) {
		len = strnlen((char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]),
			      nla_len(tb_msg[NLMSGERR_ATTR_MSG]));
		fprintf(stderr, "kernel error: %*s\n", len,
			(char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]));
	}

	return NL_STOP;
}

static int ovpn_nl_cb_finish(struct nl_msg (*msg)__attribute__((unused)),
			     void *arg)
{
	int *status = arg;

	*status = 0;
	return NL_SKIP;
}

static int ovpn_nl_msg_send(struct nl_ctx *ctx, ovpn_nl_cb cb)
{
	int status = 1;

	nl_cb_err(ctx->nl_cb, NL_CB_CUSTOM, ovpn_nl_cb_error, &status);
	nl_cb_set(ctx->nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, ovpn_nl_cb_finish,
		  &status);
	nl_cb_set(ctx->nl_cb, NL_CB_ACK, NL_CB_CUSTOM, ovpn_nl_cb_finish,
		  &status);

	if (cb)
		nl_cb_set(ctx->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, cb, ctx);

	nl_send_auto_complete(ctx->nl_sock, ctx->nl_msg);

	while (status == 1)
		ovpn_nl_recvmsgs(ctx);

	if (status < 0)
		fprintf(stderr, "failed to send netlink message: %s (%d)\n",
			strerror(-status), status);

	return status;
}

static int ovpn_read_key(const char *file, struct ovpn_ctx *ctx)
{
	int idx_enc, idx_dec, ret = -1;
	unsigned char *ckey = NULL;
	__u8 *bkey = NULL;
	size_t olen = 0;
	long ckey_len;
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "cannot open: %s\n", file);
		return -1;
	}

	/* get file size */
	fseek(fp, 0L, SEEK_END);
	ckey_len = ftell(fp);
	rewind(fp);

	/* if the file is longer, let's just read a portion */
	if (ckey_len > 256)
		ckey_len = 256;

	ckey = malloc(ckey_len);
	if (!ckey)
		goto err;

	ret = fread(ckey, 1, ckey_len, fp);
	if (ret != ckey_len) {
		fprintf(stderr,
			"couldn't read enough data from key file: %dbytes read\n",
			ret);
		goto err;
	}

	olen = 0;
	ret = mbedtls_base64_decode(NULL, 0, &olen, ckey, ckey_len);
	if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
		char buf[256];

		mbedtls_strerror(ret, buf, sizeof(buf));
		fprintf(stderr, "unexpected base64 error1: %s (%d)\n", buf,
			ret);

		goto err;
	}

	bkey = malloc(olen);
	if (!bkey) {
		fprintf(stderr, "cannot allocate binary key buffer\n");
		goto err;
	}

	ret = mbedtls_base64_decode(bkey, olen, &olen, ckey, ckey_len);
	if (ret) {
		char buf[256];

		mbedtls_strerror(ret, buf, sizeof(buf));
		fprintf(stderr, "unexpected base64 error2: %s (%d)\n", buf,
			ret);

		goto err;
	}

	if (olen < 2 * KEY_LEN + NONCE_LEN) {
		fprintf(stderr,
			"not enough data in key file, found %zdB but needs %dB\n",
			olen, 2 * KEY_LEN + NONCE_LEN);
		goto err;
	}

	switch (ctx->key_dir) {
	case KEY_DIR_IN:
		idx_enc = 0;
		idx_dec = 1;
		break;
	case KEY_DIR_OUT:
		idx_enc = 1;
		idx_dec = 0;
		break;
	}

	memcpy(ctx->key_enc, bkey + KEY_LEN * idx_enc, KEY_LEN);
	memcpy(ctx->key_dec, bkey + KEY_LEN * idx_dec, KEY_LEN);
	memcpy(ctx->nonce, bkey + 2 * KEY_LEN, NONCE_LEN);

	ret = 0;

err:
	fclose(fp);
	free(bkey);
	free(ckey);

	return ret;
}

static int ovpn_read_key_direction(const char *dir, struct ovpn_ctx *ctx)
{
	int in_dir;

	in_dir = strtoll(dir, NULL, 10);
	switch (in_dir) {
	case KEY_DIR_IN:
	case KEY_DIR_OUT:
		ctx->key_dir = in_dir;
		break;
	default:
		fprintf(stderr,
			"invalid key direction provided. Can be 0 or 1 only\n");
		return -1;
	}

	return 0;
}

static int ovpn_socket(struct ovpn_ctx *ctx, sa_family_t family)
{
	struct sockaddr local_sock;
	struct sockaddr_in6 *in6;
	struct sockaddr_in *in;
	size_t sock_len;
	int ret, s;

	s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0) {
		perror("cannot create socket");
		return -1;
	}

	memset((char *)&local_sock, 0, sizeof(local_sock));

	switch (family) {
	case AF_INET:
		in = (struct sockaddr_in *)&local_sock;
		in->sin_family = family;
		in->sin_port = htons(ctx->lport);
		in->sin_addr.s_addr = htonl(INADDR_ANY);
		sock_len = sizeof(*in);
		break;
	case AF_INET6:
		in6 = (struct sockaddr_in6 *)&local_sock;
		in6->sin6_family = family;
		in6->sin6_port = htons(ctx->lport);
		in6->sin6_addr = in6addr_any;
		sock_len = sizeof(*in6);
		break;
	default:
		return -1;
	}

	ret = bind(s, &local_sock, sock_len);
	if (ret < 0) {
		perror("cannot bind socket");
		goto err_socket;
	}

	ctx->socket = s;
	return 0;

err_socket:
	close(s);
	return -1;
}

static int ovpn_start(struct ovpn_ctx *ovpn)
{
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_START_VPN);
	if (!ctx)
		return -ENOMEM;

	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_SOCKET, ovpn->socket);
	NLA_PUT_U8(ctx->nl_msg, OVPN_ATTR_PROTO, OVPN_PROTO_UDP4);
	NLA_PUT_U8(ctx->nl_msg, OVPN_ATTR_MODE, OVPN_MODE_CLIENT);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_new_peer(struct ovpn_ctx *ovpn)
{
	struct nlattr *addr;
	struct nl_ctx *ctx;
	size_t alen;
	int ret = -1;

	switch (ovpn->sa_family) {
	case AF_INET:
		alen = sizeof(struct in_addr);
		break;
	case AF_INET6:
		alen = sizeof(struct in6_addr);
		break;
	default:
		fprintf(stderr, "Invalid family for local/remote address\n");
		return -1;
	}

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_NEW_PEER);
	if (!ctx)
		return -ENOMEM;

	addr = nla_nest_start(ctx->nl_msg, OVPN_ATTR_SOCKADDR_REMOTE);

	NLA_PUT(ctx->nl_msg, OVPN_SOCKADDR_ATTR_ADDRESS, alen, &ovpn->remote);
	NLA_PUT_U16(ctx->nl_msg, OVPN_SOCKADDR_ATTR_PORT, ovpn->rport);

	nla_nest_end(ctx->nl_msg, addr);

	addr = nla_nest_start(ctx->nl_msg, OVPN_ATTR_SOCKADDR_LOCAL);

	NLA_PUT(ctx->nl_msg, OVPN_SOCKADDR_ATTR_ADDRESS, alen, &ovpn->local);
	NLA_PUT_U16(ctx->nl_msg, OVPN_SOCKADDR_ATTR_PORT, ovpn->lport);

	nla_nest_end(ctx->nl_msg, addr);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_set_peer(struct ovpn_ctx *ovpn)
{
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_SET_PEER);
	if (!ctx)
		return -ENOMEM;

	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_KEEPALIVE_INTERVAL,
		    ovpn->keepalive_interval);
	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_KEEPALIVE_TIMEOUT,
		    ovpn->keepalive_timeout);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_new_key(struct ovpn_ctx *ovpn)
{
	struct nlattr *key_dir;
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_NEW_KEY);
	if (!ctx)
		return -ENOMEM;

	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_REMOTE_PEER_ID, 0);
	NLA_PUT_U8(ctx->nl_msg, OVPN_ATTR_KEY_SLOT, OVPN_KEY_SLOT_PRIMARY);
	NLA_PUT_U16(ctx->nl_msg, OVPN_ATTR_KEY_ID, 0);

	NLA_PUT_U16(ctx->nl_msg, OVPN_ATTR_CIPHER_ALG,
		    OVPN_CIPHER_ALG_AES_GCM);

	key_dir = nla_nest_start(ctx->nl_msg, OVPN_ATTR_ENCRYPT_KEY);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, KEY_LEN,
		ovpn->key_enc);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_NONCE_TAIL, NONCE_LEN,
		ovpn->nonce);
	nla_nest_end(ctx->nl_msg, key_dir);

	key_dir = nla_nest_start(ctx->nl_msg, OVPN_ATTR_DECRYPT_KEY);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, KEY_LEN,
		ovpn->key_dec);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_NONCE_TAIL, NONCE_LEN,
		ovpn->nonce);
	nla_nest_end(ctx->nl_msg, key_dir);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_del_key(struct ovpn_ctx *ovpn)
{
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_DEL_KEY);
	if (!ctx)
		return -ENOMEM;

	NLA_PUT_U8(ctx->nl_msg, OVPN_ATTR_KEY_SLOT, OVPN_KEY_SLOT_PRIMARY);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_swap_keys(struct ovpn_ctx *ovpn)
{
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_SWAP_KEYS);
	if (!ctx)
		return -ENOMEM;

	ret = ovpn_nl_msg_send(ctx, NULL);
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_send_data(struct ovpn_ctx *ovpn, const void *data, size_t len)
{
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_PACKET);
	if (!ctx)
		return -ENOMEM;

	NLA_PUT(ctx->nl_msg, OVPN_ATTR_PACKET, len, data);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_handle_packet(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attrs[OVPN_ATTR_MAX + 1];
	const __u8 *data;
	size_t i, len;

	fprintf(stderr, "received message\n");

	nla_parse(attrs, OVPN_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!attrs[OVPN_ATTR_PACKET]) {
		fprintf(stderr, "no packet content in netlink message\n");;
		return NL_SKIP;
	}

	len = nla_len(attrs[OVPN_ATTR_PACKET]);
	data = nla_data(attrs[OVPN_ATTR_PACKET]);

	fprintf(stderr, "received message, len=%zd:\n", len);
	for (i = 0; i < len; i++) {
		if (i && !(i % 16))
			fprintf(stderr, "\n");
		fprintf(stderr, "%.2x ", data[i]);
	}
	fprintf(stderr, "\n");

	return NL_SKIP;
}

static int nl_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static struct nl_ctx *ovpn_register(struct ovpn_ctx *ovpn)
{
	struct nl_ctx *ctx;
	int ret;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_REGISTER_PACKET);
	if (!ctx)
		return NULL;

	nl_cb_set(ctx->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl_seq_check,
		  NULL);

	ret = ovpn_nl_msg_send(ctx, ovpn_handle_packet);
	if (ret < 0) {
		nl_ctx_free(ctx);
		return NULL;
	}

	return ctx;
}

struct mcast_handler_args {
	const char *group;
	int id;
};

static int mcast_family_handler(struct nl_msg *msg, void *arg)
{
	struct mcast_handler_args *grp = arg;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *mcgrp;
	int rem_mcgrp;

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return NL_SKIP;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
		struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

		nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
			  nla_data(mcgrp), nla_len(mcgrp), NULL);

		if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
			continue;
		if (strncmp(nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
			    grp->group, nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
			continue;
		grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
		break;
	}

	return NL_SKIP;
}

static int mcast_error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			       void *arg)
{
	int *ret = arg;

	*ret = err->error;
	return NL_STOP;
}

static int mcast_ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	*ret = 0;
	return NL_STOP;
}

static int ovpn_handle_msg(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attrs[OVPN_ATTR_MAX + 1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	enum ovpn_del_peer_reason reason;
	char ifname[IF_NAMESIZE];
	__u32 ifindex;

	fprintf(stderr, "received message from ovpn-dco\n");

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fprintf(stderr, "invalid header\n");
		return NL_STOP;
	}

	if (nla_parse(attrs, OVPN_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		      genlmsg_attrlen(gnlh, 0), NULL)) {
		fprintf(stderr, "received bogus data from ovpn-dco\n");
		return NL_STOP;
	}

	if (!attrs[OVPN_ATTR_IFINDEX]) {
		fprintf(stderr, "no ifindex in this message\n");
		return NL_STOP;
	}

	ifindex = nla_get_u32(attrs[OVPN_ATTR_IFINDEX]);
	if (!if_indextoname(ifindex, ifname)) {
		fprintf(stderr, "cannot resolve ifname for ifinxed: %u\n",
			ifindex);
		return NL_STOP;
	}

	switch (gnlh->cmd) {
	case OVPN_CMD_DEL_PEER:
		if (!attrs[OVPN_ATTR_DEL_PEER_REASON]) {
			fprintf(stderr, "no reason in DEL_PEER message\n");
			return NL_STOP;
		}
		reason = nla_get_u8(attrs[OVPN_ATTR_DEL_PEER_REASON]);
		fprintf(stderr,
			"received CMD_DEL_PEER, ifname: %s reason: %d\n",
			ifname, reason);
		break;
	default:
		fprintf(stderr, "received unknown command: %d\n", gnlh->cmd);
		return NL_STOP;
	}

	return NL_OK;
}

static int ovpn_get_mcast_id(struct nl_sock *sock, const char *family,
			     const char *group)
{
	struct nl_msg *msg;
	struct nl_cb *cb;
	int ret, ctrlid;
	struct mcast_handler_args grp = {
		.group = group,
		.id = -ENOENT,
	};

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		ret = -ENOMEM;
		goto out_fail_cb;
	}

	ctrlid = genl_ctrl_resolve(sock, "nlctrl");

	genlmsg_put(msg, 0, 0, ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);

	ret = -ENOBUFS;
	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

	ret = nl_send_auto_complete(sock, msg);
	if (ret < 0)
		goto nla_put_failure;

	ret = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, mcast_error_handler, &ret);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, mcast_ack_handler, &ret);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, mcast_family_handler, &grp);

	while (ret > 0)
		nl_recvmsgs(sock, cb);

	if (ret == 0)
		ret = grp.id;
 nla_put_failure:
	nl_cb_put(cb);
 out_fail_cb:
	nlmsg_free(msg);
	return ret;
}

static void ovpn_listen_mcast(void)
{
	struct nl_sock *sock;
	struct nl_cb *cb;
	int mcid, ret;

	sock = nl_socket_alloc();
	if (!sock) {
		fprintf(stderr, "cannot allocate netlink socket\n");
		goto err_free;
	}

	nl_socket_set_buffer_size(sock, 8192, 8192);

	ret = genl_connect(sock);
	if (ret < 0) {
		fprintf(stderr, "cannot connect to generic netlink: %s\n",
			nl_geterror(ret));
		goto err_free;
	}

	mcid = ovpn_get_mcast_id(sock, OVPN_NL_NAME,
				 OVPN_NL_MULTICAST_GROUP_PEERS);
	if (mcid < 0) {
		fprintf(stderr, "cannot get mcast group: %s\n",
			nl_geterror(mcid));
		goto err_free;
	}

	ret = nl_socket_add_membership(sock, mcid);
	if (ret) {
		fprintf(stderr, "failed to join mcast group: %d\n", ret);
		goto err_free;
	}

	ret = 0;
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl_seq_check, NULL);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, ovpn_handle_msg, &ret);
	nl_cb_err(cb, NL_CB_CUSTOM, ovpn_nl_cb_error, &ret);

	while (ret != -EINTR)
		ret = nl_recvmsgs(sock, cb);

	nl_cb_put(cb);
err_free:
	nl_socket_free(sock);
}

static void usage(const char *cmd)
{
	fprintf(stderr, "Error: invalid arguments.\n\n");
	fprintf(stderr,
		"Usage %s <iface> <start|new_peer|set_peer|new_key|del_key|recv|send> [arguments..]\n",
		cmd);
	fprintf(stderr, "\tiface: tun interface name\n\n");

	fprintf(stderr, "* start <lport>: start VPN session on port\n");
	fprintf(stderr, "\tlocal-port: UDP port to listen to\n\n");

	fprintf(stderr,
		"* new_peer <laddr> <lport> <raddr> <rport>: set peer link\n");
	fprintf(stderr, "\tlocal-addr: src IP address\n");
	fprintf(stderr, "\tlocal-port: src UDP port\n");
	fprintf(stderr, "\tremote-addr: peer IP address\n");
	fprintf(stderr, "\tremote-port: peer UDP port\n\n");

	fprintf(stderr,
		"* set_peer <keepalive_interval> <keepalive_timeout>: set peer attributes\n");
	fprintf(stderr,
		"\tkeepalive_interval: interval for sending ping messages\n");
	fprintf(stderr,
		"\tkeepalive_timeout: time after which a peer is timed out\n\n");

	fprintf(stderr,
		"* new_key <key_dir> <key_file>: set data channel key\n");
	fprintf(stderr,
		"\tkey_dir: key direction, must 0 on one host and 1 on the other\n");
	fprintf(stderr, "\tkey_file: file containing the pre-shared key\n\n");

	fprintf(stderr, "* del_key: erase existing data channel key\n\n");

	fprintf(stderr, "* swap_keys: swap primary and seconday key slots\n\n");

	fprintf(stderr, "* recv: receive packet and exit\n\n");

	fprintf(stderr, "* send <string>: send packet with string\n");
	fprintf(stderr, "\tstring: message to send to the peer\n");
}

static int ovpn_parse_new_peer(struct ovpn_ctx *ovpn, int argc, char *argv[])
{
	int ret;

	if (argc < 7) {
		usage(argv[0]);
		return -1;
	}

	/* assume IPv4 unless parsing fallsback to IPv6 */
	ovpn->sa_family = AF_INET;

	ret = inet_pton(AF_INET, argv[3], &ovpn->local);
	if (ret < 1) {
		/* parsing IPv4 failed, try with IPv6 */
		ret = inet_pton(AF_INET6, argv[3], &ovpn->local);
		if (ret < 1) {
			fprintf(stderr, "invalid local address\n");
			return -1;
		}

		/* valid IPv6 found */
		ovpn->sa_family = AF_INET6;
	}

	ovpn->lport = strtoul(argv[4], NULL, 10);
	if (errno == ERANGE || ovpn->lport > 65535) {
		fprintf(stderr, "lport value out of range\n");
		return -1;
	}

	ret = inet_pton(AF_INET, argv[5], &ovpn->remote);
	if (ret < 1) {
		ret = inet_pton(AF_INET6, argv[5], &ovpn->remote);
		if (ret < 1) {
			fprintf(stderr, "invalid remote address\n");
			return -1;
		}

		/* make sure we had already switched to IPv6 for the local
		 * address
		 */
		if (ovpn->sa_family != AF_INET6)
			return -1;
	}

	ovpn->rport = strtoul(argv[6], NULL, 10);
	if (errno == ERANGE || ovpn->rport > 65535) {
		fprintf(stderr, "rport value out of range\n");
		return -1;
	}

	return 0;
}

static int ovpn_parse_set_peer(struct ovpn_ctx *ovpn, int argc, char *argv[])
{
	if (argc < 5) {
		usage(argv[0]);
		return -1;
	}

	ovpn->keepalive_interval = strtoul(argv[3], NULL, 10);
	if (errno == ERANGE) {
		fprintf(stderr, "keepalive interval value out of range\n");
		return -1;
	}

	ovpn->keepalive_timeout = strtoul(argv[4], NULL, 10);
	if (errno == ERANGE) {
		fprintf(stderr, "keepalive interval value out of range\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	sa_family_t family = AF_INET;
	struct ovpn_ctx ovpn;
	struct nl_ctx *ctx;
	int ret;

	if (argc < 3) {
		usage(argv[0]);
		return -1;
	}

	memset(&ovpn, 0, sizeof(ovpn));

	ovpn.ifindex = if_nametoindex(argv[1]);
	if (!ovpn.ifindex) {
		fprintf(stderr, "cannot find interface: %s\n",
			strerror(errno));
		return -1;
	}

	if (!strcmp(argv[2], "start")) {
		if (argc < 4) {
			usage(argv[0]);
			return -1;
		}

		ovpn.lport = strtoul(argv[3], NULL, 10);
		if (errno == ERANGE || ovpn.lport > 65535) {
			fprintf(stderr, "lport value out of range\n");
			return -1;
		}

		if (argc > 4 && !strcmp(argv[4], "ipv6"))
			family = AF_INET6;

		ret = ovpn_socket(&ovpn, family);
		if (ret < 0)
			return ret;

		ret = ovpn_start(&ovpn);
		if (ret < 0) {
			fprintf(stderr, "cannot start VPN\n");
			close(ovpn.socket);
			return ret;
		}
	} else if (!strcmp(argv[2], "new_peer")) {
		ret = ovpn_parse_new_peer(&ovpn, argc, argv);
		if (ret < 0)
			return ret;

		ret = ovpn_new_peer(&ovpn);
		if (ret < 0) {
			fprintf(stderr, "cannot add peer to VPN\n");
			return ret;
		}
	} else if (!strcmp(argv[2], "set_peer")) {
		ret = ovpn_parse_set_peer(&ovpn, argc, argv);
		if (ret < 0)
			return ret;

		ret = ovpn_set_peer(&ovpn);
		if (ret < 0) {
			fprintf(stderr, "cannot set peer to VPN\n");
			return ret;
		}
	} else if (!strcmp(argv[2], "new_key")) {
		if (argc < 5) {
			usage(argv[0]);
			return -1;
		}

		ret = ovpn_read_key_direction(argv[3], &ovpn);
		if (ret < 0)
			return ret;

		ret = ovpn_read_key(argv[4], &ovpn);
		if (ret)
			return ret;

		ret = ovpn_new_key(&ovpn);
		if (ret < 0) {
			fprintf(stderr, "cannot set key\n");
			return ret;
		}
	} else if (!strcmp(argv[2], "del_key")) {
		ret = ovpn_del_key(&ovpn);
		if (ret < 0) {
			fprintf(stderr, "cannot delete key\n");
			return ret;
		}
	} else if (!strcmp(argv[2], "swap_keys")) {
		ret = ovpn_swap_keys(&ovpn);
		if (ret < 0) {
			fprintf(stderr, "cannot swap keys\n");
			return ret;
		}
	} else if (!strcmp(argv[2], "recv")) {
		ctx = ovpn_register(&ovpn);
		if (!ctx) {
			fprintf(stderr, "cannot register for packets\n");
			return -1;
		}

		ret = ovpn_nl_recvmsgs(ctx);
		nl_ctx_free(ctx);
	} else if (!strcmp(argv[2], "send")) {
		if (argc < 4) {
			usage(argv[0]);
			return -1;
		}

		ret = ovpn_send_data(&ovpn, argv[3], strlen(argv[3]) + 1);
		if (ret < 0)
			fprintf(stderr, "cannot send data\n");
	} else if (!strcmp(argv[2], "listen")) {
		ovpn_listen_mcast();
	} else {
		usage(argv[0]);
		return -1;
	}

	return ret;
}
