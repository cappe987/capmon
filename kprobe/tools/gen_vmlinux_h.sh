#/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2020 Facebook

$(dirname "$0")/bpftool btf dump file ${1:-/sys/kernel/btf/vmlinux} format c
