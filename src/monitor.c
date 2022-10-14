// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include <bpf/libbpf.h>
#include "monitor.h"
#include "kprobes.h"
#include "capabilities.h"
#include "bpf_event.h"

#include "std_capable.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	UNUSED(sig);
	exiting = true;
}

static bool filter_match_entry(struct capmon *cm, const struct event *e)
{
	struct filter *f;
	bool pid_filter = false;
	bool pid_match = false;
	bool cap_filter = false;
	bool cap_match = false;
	bool comm_filter = false;
	bool comm_match = false;
	regmatch_t pmatch[1];
	size_t nmatch = 1;
	int res;

	for (f = cm->filters.lh_first; f != NULL; f = f->entries.le_next) {
		switch (f->type) {
		case FILTER_PID:
			pid_filter = true;
			if (e->pid == f->pid)
				pid_match = true;
			break;
		case FILTER_CAP:
			cap_filter = true;
			if (e->cap == f->cap)
				cap_match = true;
			break;
		case FILTER_COMM:
			comm_filter = true;
			res = regexec(&f->comm, e->comm, nmatch, pmatch, 0);
			if (res == 0)
				comm_match = true;
			break;
		}
	}
	/* If there is no filter of that type, return true for it. Else use match result */
	return (!pid_filter || pid_match) && (!cap_filter || cap_match) && (!comm_filter || comm_match);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct capmon *cm = ctx;

	UNUSED(data_sz);
	UNUSED(ctx);

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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

int run_monitor_mode(struct capmon *cm)
{
	struct ring_buffer *rb = NULL;
	struct std_capable_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = std_capable_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	/*skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;*/

	/* Load & verify BPF programs */
	err = std_capable_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = std_capable_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, cm, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

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
	std_capable_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
