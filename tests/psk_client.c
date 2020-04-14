// SPDX-License-Identifier: GPL-2.0-only
/*
 *  OpenVPN data channel accelerator
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

#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include <uapi/linux/ovpn_dco.h>

#include <mbedtls/base64.h>
#include <mbedtls/error.h>

#define UNUSED(x) (x)__attribute__((unused))

/* libnl < 3.5.0 does not set the NLA_F_NESTED on its own, therefore we
 * have to explicitly do it to prevent the kernel from failing upon
 * parsing of the message
 */
#define nla_nest_start(_msg, _type) \
	nla_nest_start(_msg, _type | NLA_F_NESTED);

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
	uint8_t key_enc[KEY_LEN];
	uint8_t key_dec[KEY_LEN];
	uint8_t nonce[NONCE_LEN];

	struct in_addr local;
	uint16_t lport;
	struct in_addr remote;
	uint16_t rport;

	unsigned int ifindex;

	int socket;

	enum ovpn_key_direction key_dir;
};

static void ovpn_nl_recvmsgs(struct nl_ctx *ctx)
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
			fprintf(stderr, "netlink reports error: %d\n",
				ret);
		break;
	}
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

static int ovpn_nl_cb_error(struct sockaddr_nl UNUSED(*nla),
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

static int ovpn_nl_cb_finish(struct nl_msg UNUSED(*msg), void *arg)
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

	//nl_wait_for_ack(ctx->nl_sock);
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
	uint8_t *bkey = NULL;
	char *ckey = NULL;
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
		fprintf(stderr, "couldn't read enough data from key file: %dbytes read\n",
			ret);
		goto err;
	}

	olen = 0;
	ret = mbedtls_base64_decode(NULL, 0, &olen, ckey, ckey_len);
	if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
		char buf[256];

		mbedtls_strerror(ret, buf, sizeof(buf));
		fprintf(stderr, "unexpected base64 error1: %s (%d)\n", buf, ret);

		goto err;
	}

	bkey = malloc(olen);
	if (!bkey) {
		fprintf(stderr, "cannot allocate binary key buffer\n");
		goto err;
	}

	ret = mbedtls_base64_decode(bkey, olen, &olen, ckey, strlen(ckey));
	if (ret) {
		char buf[256];

		mbedtls_strerror(ret, buf, sizeof(buf));
		fprintf(stderr, "unexpected base64 error2: %s (%d)\n", buf, ret);

		goto err;
	}

	if (olen < 2 * KEY_LEN + NONCE_LEN) {
		fprintf(stderr, "not enough data in key file, found %zdB but needs %dB\n",
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
		fprintf(stderr, "invalid key direction provided. Can be 0 or 1 only\n");
		return -1;
	}

	return 0;
}

static int ovpn_socket(struct ovpn_ctx *ctx)
{
	struct sockaddr_in local_sock;
	int ret, s;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0) {
		perror("cannot create socket");
		return -1;
	}

	memset((char *)&local_sock, 0, sizeof(local_sock));

	local_sock.sin_family = AF_INET;
	local_sock.sin_port = htons(ctx->lport);
	local_sock.sin_addr.s_addr = htonl(INADDR_ANY);

	ret = bind(s, (struct sockaddr *)&local_sock, sizeof(local_sock));
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

static int ovpn_add_peer(struct ovpn_ctx *ovpn)
{
	struct nlattr *addr;
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_ADD_PEER);
	if (!ctx)
		return -ENOMEM;

	addr = nla_nest_start(ctx->nl_msg, OVPN_ATTR_SOCKADDR_REMOTE);

	NLA_PUT(ctx->nl_msg, OVPN_SOCKADDR_ATTR_ADDRESS, 4, &ovpn->remote);
	NLA_PUT_U16(ctx->nl_msg, OVPN_SOCKADDR_ATTR_PORT, ovpn->rport);

	nla_nest_end(ctx->nl_msg, addr);

	addr = nla_nest_start(ctx->nl_msg, OVPN_ATTR_SOCKADDR_LOCAL);

	NLA_PUT(ctx->nl_msg, OVPN_SOCKADDR_ATTR_ADDRESS, 4, &ovpn->local);
	NLA_PUT_U16(ctx->nl_msg, OVPN_SOCKADDR_ATTR_PORT, ovpn->lport);

	nla_nest_end(ctx->nl_msg, addr);

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static int ovpn_set_single_key(struct ovpn_ctx *ovpn, struct nl_ctx *ctx,
			       int type)
{
	struct nlattr *key, *key_dir;

	key = nla_nest_start(ctx->nl_msg, type);

	NLA_PUT_U16(ctx->nl_msg, OVPN_KEY_ATTR_CIPHER_ALG,
		    OVPN_CIPHER_ALG_AES_GCM);
	NLA_PUT_U16(ctx->nl_msg, OVPN_KEY_ATTR_ID, 0);

	key_dir = nla_nest_start(ctx->nl_msg, OVPN_KEY_ATTR_ENCRYPT);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, KEY_LEN,
		ovpn->key_enc);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_NONCE_TAIL, NONCE_LEN,
		ovpn->nonce);
	nla_nest_end(ctx->nl_msg, key_dir);

	key_dir = nla_nest_start(ctx->nl_msg, OVPN_KEY_ATTR_DECRYPT);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, KEY_LEN,
		ovpn->key_dec);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_NONCE_TAIL, NONCE_LEN,
		ovpn->nonce);
	nla_nest_end(ctx->nl_msg, key_dir);

	nla_nest_end(ctx->nl_msg, key);

	return 0;

nla_put_failure:
	return -1;
}

static int ovpn_set_keys(struct ovpn_ctx *ovpn)
{
	struct nlattr *primary;
	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_SET_KEYS);
	if (!ctx)
		return -ENOMEM;

	ret = ovpn_set_single_key(ovpn, ctx, OVPN_ATTR_KEY_PRIMARY);
	if (ret < 0)
		goto nla_put_failure;

	ret = ovpn_nl_msg_send(ctx, NULL);
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

static void usage(const char *cmd)
{
	fprintf(stderr, "Error: invalid arguments.\n\n");
	fprintf(stderr, "Usage %s <iface> <key_dir> <key_file> <l-port> <r-addr> <r-port>\n\n", cmd);
	fprintf(stderr, "\tiface: tun interface name\n");
	fprintf(stderr, "\tkey_dir: key direction, must 0 on one host and 1 on the other\n");
	fprintf(stderr, "\tkey_file: file containing the pre-shared key\n");
	fprintf(stderr, "\tlocal-addr: IP address of this peer\n");
	fprintf(stderr, "\tlocal-port: UDP port to listen to\n");
	fprintf(stderr, "\tremote-addr: IP address of the other peer\n");
	fprintf(stderr, "\tremote-port: UDP port of the other peer\n");
}

int main(int argc, char *argv[])
{
	struct ovpn_ctx ovpn;
	int ret;

	if (argc < 7) {
		usage(argv[0]);
		return -1;
	}

	memset(&ovpn, 0, sizeof(ovpn));

	ovpn.ifindex = if_nametoindex(argv[1]);
	if (!ovpn.ifindex) {
		fprintf(stderr, "cannot resolve interface name: %s\n",
			strerror(errno));
		return -1;
	}

	ret = ovpn_read_key_direction(argv[2], &ovpn);
	if (ret < 0)
		return ret;

	ret = ovpn_read_key(argv[3], &ovpn);
	if (ret)
		return ret;

	ret = inet_pton(AF_INET, argv[4], &ovpn.local);
	if (!ret) {
		fprintf(stderr, "invalid local address\n");
		return ret;
	}

	ovpn.lport = strtoul(argv[5], NULL, 10);
	if (errno == ERANGE || ovpn.lport > 65535) {
		fprintf(stderr, "lport value out of range\n");
		return ret;
	}

	ret = inet_pton(AF_INET, argv[6], &ovpn.remote);
	if (!ret) {
		fprintf(stderr, "invalid remote address\n");
		return ret;
	}

	ovpn.rport = strtoul(argv[7], NULL, 10);
	if (errno == ERANGE || ovpn.rport > 65535) {
		fprintf(stderr, "rport value out of range\n");
		return ret;
	}

	ret = ovpn_socket(&ovpn);
	if (ret < 0)
		return ret;

	ret = ovpn_start(&ovpn);
	if (ret < 0) {
		fprintf(stderr, "cannot start VPN\n");
		close(ovpn.socket);
		return ret;
	}

	ret = ovpn_add_peer(&ovpn);
	if (ret < 0) {
		fprintf(stderr, "cannot add peer to VPN\n");
		return ret;
	}

	ret = ovpn_set_keys(&ovpn);
	if (ret < 0) {
		fprintf(stderr, "cannot set keys\n");
		return ret;
	}

	return 0;
}
