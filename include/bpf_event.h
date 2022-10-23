// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2020 Facebook
#ifndef _CAPMON_BPF_EVENT_H_
#define _CAPMON_BPF_EVENT_H_

#include <stdbool.h>

#define TASK_COMM_LEN 16

struct event_proc_start {
	int pid;
	int ppid; 
	char comm[TASK_COMM_LEN];
};

struct event_cap_check {
	int pid;
	int ppid; 
	char comm[TASK_COMM_LEN];
	int cap; /* Capability ID */
	bool has_cap; /* User has capability */
};

#endif /* _CAPMON_BPF_EVENT_H_ */
