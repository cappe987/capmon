// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"

#include "bpf_event.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

int bpf_capable(struct user_namespace *ns, int cap, int err)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event_cap_check *e;
	pid_t pid;
	u64 ts;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->cap = cap;
	e->has_cap = !err; /* cap_capable returns err value. err=0 means has cap */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fexit/cap_capable")
int BPF_PROG(cap_capable_exit, const struct cred *cred,
	     struct user_namespace *ns,
	     int cap, unsigned int opts, int err)
{
	return bpf_capable(ns, cap, err);
}
