#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

cd /repo

echo "Guest OS:"
cat /etc/os-release
echo
echo "Guest kernel:"
uname -a
echo
echo "Kernel build directory:"
readlink -f "/lib/modules/$(uname -r)/build"

# The repo is copied from the host, so root in the guest sees different
# ownership and Git may reject it as a dubious worktree.
git config --global --add safe.directory /repo

make -j"$(nproc)"
make install
modprobe ovpn-dco-v2
rmmod ovpn-dco-v2
