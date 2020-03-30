# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020 OpenVPN, Inc.
#
#  Author:	Antonio Quartulli <antonio@openvpn.net>

PWD:=$(shell pwd)
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
ifeq ($(shell cd $(KERNEL_SRC) && pwd),)
$(warning $(KERNEL_SRC) is missing, please set KERNELSRC)
endif

export KERNEL_SRC
RM ?= rm -f
CP := cp -fpR
LN := ln -sf
DEPMOD := depmod -a

REVISION= $(shell	if [ -d "$(PWD)/.git" ]; then \
				echo $$(git --git-dir="$(PWD)/.git" describe --always --dirty --match "v*" |sed 's/^v//' 2> /dev/null || echo "[unknown]"); \
			fi)
NOSTDINC_FLAGS += \
	-I$(PWD)/include/ \
	$(CFLAGS)
#	-I$(PWD)/compat-include/ \
#	-include $(PWD)/linux-compat.h \

ifneq ($(REVISION),)
NOSTDINC_FLAGS += -DOVPN_DCO_VERSION=\"$(REVISION)\"
endif

obj-y += net/ovpn-dco/
export ovpn-dco-y

BUILD_FLAGS := \
	M=$(PWD) \
	PWD=$(PWD) \
	REVISION=$(REVISION) \
	CONFIG_OVPN_DCO=m \
	INSTALL_MOD_DIR=updates/

all: config
	$(MAKE) -C $(KERNEL_SRC) $(BUILD_FLAGS)	modules

clean:
	$(RM) compat-autoconf.h*
	$(MAKE) -C $(KERNEL_SRC) $(BUILD_FLAGS) clean

install: config
	$(MAKE) -C $(KERNEL_SRC) $(BUILD_FLAGS) modules_install
	$(DEPMOD)

config:
	$(PWD)/gen-compat-autoconf.sh $(PWD)/compat-autoconf.h

.PHONY: all clean install config
