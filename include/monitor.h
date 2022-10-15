// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#ifndef _CAPMON_MONITOR_H_
#define _CAPMON_MONITOR_H_

#include <stdbool.h>

#include "libcapmon.h"

#define BUFSIZE 1000

int run_monitor_mode(struct capmon *cm);

#endif /* _CAPMON_MONITOR_H_ */
