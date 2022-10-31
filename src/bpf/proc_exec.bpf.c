// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_event.h"

char LICENSE[] SEC("license") = "GPL";

/*struct {*/
	/*__uint(type, BPF_MAP_TYPE_HASH);*/
	/*__uint(max_entries, 8192);*/
	/*__type(key, pid_t);*/
	/*__type(value, u64);*/
/*} exec_start SEC(".maps");*/

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	/*unsigned fname_off;*/
	struct event_proc_start *e;
	pid_t pid;
	/*u64 ts;*/

	pid = bpf_get_current_pid_tgid() >> 32;
	/*ts = bpf_ktime_get_ns();*/
	/*bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);*/

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	/*e->exit_event = false;*/
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/*fname_off = ctx->__data_loc_filename & 0xFFFF;*/
	/*bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);*/

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}


