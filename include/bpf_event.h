// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2020 Facebook
#ifndef _CAPMON_BPF_EVENT_H_
#define _CAPMON_BPF_EVENT_H_

#define TASK_COMM_LEN 16

#include <stdbool.h>

struct event {
	int pid;
	int ppid;
	char comm[TASK_COMM_LEN];
	int cap; /* Capability ID */
	bool has_cap; /* User has capability */
	unsigned long long timestamp;
};

struct proc_exec {
	int pid;
	int ppid;
	//unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	//char filename[MAX_FILENAME_LEN];
	//bool exit_event;
};

#endif /* _CAPMON_BPF_EVENT_H_ */
