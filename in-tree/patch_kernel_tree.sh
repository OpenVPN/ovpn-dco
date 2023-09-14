#!/bin/bash

# Copy ovpn_dco_v2 source and headers into kernel tree
# Apply diff to relevant configuration files for in-tree builds
# Set KDIR to appropriate source tree and run this script

KDIR="${KDIR:="/usr/src/linux"}"
COMMIT="$(git log|head -1|cut -d' ' -f2|cut -c 1-8)"
DIFFDIR="$(cd $( dirname "${BASH_SOURCE[0]}") && pwd )"
echo "Patching kernel in $KDIR from $DIFFDIR @ $COMMIT"

if [[ ! -d "$KDIR" ]]; then
  echo "KDIR improperly set"
  exit 1
else
  if [[ ! -f "$KDIR/Kconfig" ]]; then
    echo "$KDIR does not appear to be a kernel tree"
    exit 1
  fi

  cd "$DIFFDIR"
  cp -r ../drivers/net/ovpn-dco "$KDIR/net/"
  cp -r ../include/* "$KDIR/include/"

  cd "$KDIR"
  if [[  $(patch -p1 -i "$DIFFDIR/config.diff" -i "$DIFFDIR/proto.diff") ]]; then
    if [[ -d "$KDIR/.git" ]]; then
      git add "$KDIR/drivers/net"
      git add "$KDIR/include"
      git commit -am "OVPN DCO: in-tree @ $COMMIT"
    fi
    echo "Update kernel build configuration to enable OVPN_DCO module"
    exit 0
  else
    echo "Failed to patch kernel tree, review output and PR a fix please"
    exit 1
  fi
fi

