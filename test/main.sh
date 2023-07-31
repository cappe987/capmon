# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>
#!/bin/bash

capmon=$1
passed=0

echo "[TEST]"

OUT=$($capmon "ip tuntap add test-capmon-tap mode tap 2>/dev/null")
ip link del dev test-capmon-tap 2>/dev/null

if echo "$OUT" | grep -q "CAP_NET_ADMIN"; then
	echo -e "[\e[32mPASS\e[0m] $t"
else
	echo "Got output: $OUT"
	echo -e "[\e[31mFAIL\e[0m] $t"
	passed=1
fi


exit $passed
