// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include <search.h>

#include <bpf/libbpf.h>
#include "libcapmon.h"
#include "capabilities.h"
#include "bpf_event.h"

#include "capable_std.skel.h"
#include "capable_all.skel.h"
#include "proc_exec.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	UNUSED(sig);
	exiting = true;
}

static int handle_cap_check(void *ctx, void *data, size_t data_sz)
{
	const struct event_cap_check *e = data;
	struct capmon *cm = ctx;
	UNUSED(data_sz);

	if (!filter_match_entry(cm, e))
		return 0;

	stats_add_cap(cm, e);

	printf("%-16s  %-7d  %-7d  %-22s %s\n",
	       e->comm,
	       e->pid,
	       e->ppid,
	       cap_to_str(e->cap),
	       e->has_cap ? "True" : "False");
	return 0;
}

static int handle_proc_start(void *ctx, void *data, size_t data_sz)
{
	const struct event_proc_start *e = data;
	struct capmon *cm = ctx;
	UNUSED(data_sz);
	UNUSED(cm);

	printf("Start %s\n", e->comm);
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

#define INIT_BPFOBJ(OBJ) \
int OBJ##_init(struct OBJ##_bpf **skel){\
	int err;\
\
	/* Load and verify BPF application */\
	*skel = OBJ##_bpf__open();\
	if (!skel) {\
		fprintf(stderr, "Failed to open and load BPF skeleton\n");\
		return 1;\
	}\
\
	/* Load & verify BPF programs */\
	err = OBJ##_bpf__load(*skel);\
	if (err) {\
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");\
		return err;\
	}\
\
	/* Attach tracepoints */\
	err = OBJ##_bpf__attach(*skel);\
	if (err) {\
		fprintf(stderr, "Failed to attach BPF skeleton\n");\
		return err;\
	}\
	return 0;\
}

INIT_BPFOBJ(capable_std)
INIT_BPFOBJ(capable_all)
INIT_BPFOBJ(proc_exec)

int run_monitor_mode(struct capmon *cm)
{
	struct ring_buffer *rb = NULL;
	struct proc_exec_bpf *skel_exec;
	struct capable_std_bpf *skel_std;
	struct capable_all_bpf *skel_all;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	proc_exec_init(&skel_exec);
	rb = ring_buffer__new(bpf_map__fd(skel_exec->maps.rb), handle_proc_start, cm, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	if (cm->cap_all){
		err = capable_all_init(&skel_all);
		if (err)
			goto cleanup;
		err = ring_buffer__add(rb, bpf_map__fd(skel_all->maps.rb), handle_cap_check, cm);
		if (err) {
			fprintf(stderr, "Failed to attach capable_all_bpf to ring buffer\n");
			goto cleanup;
		}

	} else {
		err = capable_std_init(&skel_std);
		if (err)
			goto cleanup;
		err = ring_buffer__add(rb, bpf_map__fd(skel_std->maps.rb), handle_cap_check, cm);
		if (err) {
			fprintf(stderr, "Failed to attach capable_std_bpf to ring buffer\n");
			goto cleanup;
		}
	}

	if (err)
		goto cleanup;

	/* Process events */
	printf("----------------------------------------------\n");
	printf("PROCESS         | PID    | PPID   | Capability\n");
	printf("----------------------------------------------\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	printf("\n");
	stats_print_summary(cm);

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	if (cm->cap_all)
		capable_all_bpf__destroy(skel_all);
	else
		capable_std_bpf__destroy(skel_std);

	return err < 0 ? -err : 0;
}
