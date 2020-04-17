# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020 OpenVPN, Inc.
#
#  Author:	Antonio Quartulli <antonio@openvpn.net>

RM ?= rm -f

psk_client:
	$(CC) $@.c -I../include/uapi `pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0` \
		-lmbedtls -lmbedcrypto -o $@

clean:
	$(RM) psk_client

.PHONY: all
