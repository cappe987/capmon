// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2020 Facebook
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#include <stdbool.h>

struct event {
	int pid;
	int ppid;
	char comm[TASK_COMM_LEN];
	int cap; /* Capability ID */
	bool has_cap; /* User has capability */
	unsigned long long timestamp;
};

#endif /* __BOOTSTRAP_H */
