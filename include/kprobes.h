// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#ifndef _CAPMON_KPROBES_H
#define _CAPMON_KPROBES_H

#include <stdbool.h>

#include "libcapmon.h"

#define KPROBES_DIR "/sys/kernel/debug/tracing"
#define KPROBE_EVENTS KPROBES_DIR"/kprobe_events"
#define KPROBES_LOG KPROBES_DIR"/trace"

bool kprobes_select_enabled(struct capmon *cm);
bool kprobe_exists(struct probe *p);
int kprobes_create(struct capmon *cm);
int kprobes_enable(struct capmon *cm);
void kprobes_disable(struct capmon *cm);
void kprobes_destroy(struct capmon *cm);

#endif /* _CAPMON_KPROBES_H */
