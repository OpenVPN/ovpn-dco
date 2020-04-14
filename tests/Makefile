# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020 OpenVPN, Inc.
#
#  Author:	Antonio Quartulli <antonio@openvpn.net>

PWD:=$(shell pwd)
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
ifeq ($(shell cd $(KERNEL_SRC) && pwd),)
$(warning $(KERNEL_SRC) is missing, please set KERNEL_SRC)
endif

RM ?= rm -f
CP := cp -fpR
LN := ln -sf

REVISION= $(shell	if [ -d "$(PWD)/.git" ]; then \
				echo $$(git --git-dir="$(PWD)/.git" describe --always --dirty --match "v*" |sed 's/^v//' 2> /dev/null || echo "[unknown]"); \
			fi)
psk_client:
	$(CC) $@.c -I../include `pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0` \
		-lmbedtls -lmbedcrypto -o $@

clean:
	$(RM) psk_client

.PHONY: all
