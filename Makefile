# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020- OpenVPN, Inc.
#
#  Author:	Antonio Quartulli <antonio@openvpn.net>

PWD:=$(shell pwd)
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
ifeq ($(shell cd $(KERNEL_SRC) && pwd),)
$(warning $(KERNEL_SRC) is missing, please set KERNEL_SRC)
endif

export KERNEL_SRC
RM ?= rm -f
CP := cp -fpR
LN := ln -sf
DEPMOD := depmod -a

REVISION= $(shell	if [ -d "$(PWD)/.git" ]; then \
				echo $$(git --git-dir="$(PWD)/.git" describe --always --dirty --match "v*" |sed 's/^v//' 2> /dev/null || echo "[unknown]"); \
			fi)
ifneq ("$(wildcard $(KERNEL_SRC)/include/generated/uapi/linux/suse_version.h)","")
VERSION_INCLUDE = -include linux/suse_version.h
endif

NOSTDINC_FLAGS += \
	-I$(PWD)/include/ \
	$(CFLAGS) \
	$(VERSION_INCLUDE) \
	-include $(PWD)/linux-compat.h \
	-I$(PWD)/compat-include/

ifneq ($(REVISION),)
NOSTDINC_FLAGS += -DOVPN_DCO_VERSION=\"$(REVISION)\"
endif

# Ubuntu backports can change APIs without changing the upstream version.
# ABI numbers are specific to a kernel series and flavor, so expose both
# values from the target headers rather than the running kernel.
ifneq ("$(wildcard $(KERNEL_SRC)/include/generated/utsrelease.h)","")
OVPN_UBUNTU_RELEASE_ABI := $(shell \
	sed -n 's/^\#define UTS_UBUNTU_RELEASE_ABI \([0-9][0-9]*\)$$/\1/p' \
		$(KERNEL_SRC)/include/generated/utsrelease.h)
ifneq ($(OVPN_UBUNTU_RELEASE_ABI),)
NOSTDINC_FLAGS += -DOVPN_UBUNTU_RELEASE_ABI=$(OVPN_UBUNTU_RELEASE_ABI)
OVPN_UBUNTU_FLAVOR := $(shell \
	sed -n 's/^\#define UTS_RELEASE "[^"]*-[0-9][0-9]*-\([^"]*\)"$$/\1/p' \
		$(KERNEL_SRC)/include/generated/utsrelease.h)
ifeq ($(OVPN_UBUNTU_FLAVOR),generic)
NOSTDINC_FLAGS += -DOVPN_UBUNTU_FLAVOR=OVPN_UBUNTU_FLAVOR_GENERIC
else ifeq ($(OVPN_UBUNTU_FLAVOR),aws)
NOSTDINC_FLAGS += -DOVPN_UBUNTU_FLAVOR=OVPN_UBUNTU_FLAVOR_AWS
else ifeq ($(OVPN_UBUNTU_FLAVOR),azure)
NOSTDINC_FLAGS += -DOVPN_UBUNTU_FLAVOR=OVPN_UBUNTU_FLAVOR_AZURE
else ifeq ($(OVPN_UBUNTU_FLAVOR),oracle)
NOSTDINC_FLAGS += -DOVPN_UBUNTU_FLAVOR=OVPN_UBUNTU_FLAVOR_ORACLE
else ifeq ($(OVPN_UBUNTU_FLAVOR),ibm)
NOSTDINC_FLAGS += -DOVPN_UBUNTU_FLAVOR=OVPN_UBUNTU_FLAVOR_IBM
else ifeq ($(OVPN_UBUNTU_FLAVOR),gcp)
NOSTDINC_FLAGS += -DOVPN_UBUNTU_FLAVOR=OVPN_UBUNTU_FLAVOR_GCP
endif # OVPN_UBUNTU_FLAVOR
endif # OVPN_UBUNTU_RELEASE_ABI
endif # generated/utsrelease.h exists

ifeq ($(DEBUG),1)
NOSTDINC_FLAGS += -DDEBUG=1
endif

obj-y += drivers/net/ovpn-dco/
export ovpn-dco-v2-y

BUILD_FLAGS := \
	M=$(PWD) \
	PWD=$(PWD) \
	REVISION=$(REVISION) \
	CONFIG_OVPN_DCO_V2=m \
	INSTALL_MOD_DIR=updates/

all: config
	$(MAKE) -C $(KERNEL_SRC) $(BUILD_FLAGS)	modules

clean:
	$(RM) psk_client
	$(RM) compat-autoconf.h*
	$(MAKE) -C $(KERNEL_SRC) $(BUILD_FLAGS) clean
	$(MAKE) -C tests clean

install: config
	$(MAKE) -C $(KERNEL_SRC) $(BUILD_FLAGS) modules_install
	$(DEPMOD)

config:
	$(PWD)/gen-compat-autoconf.sh $(PWD)/compat-autoconf.h

tests:
	$(MAKE) -C tests

.PHONY: all clean install config tests 
