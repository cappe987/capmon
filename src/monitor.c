// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#include <bpf/libbpf.h>
#include "libcapmon.h"
#include "capabilities.h"
#include "bpf_event.h"


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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

int run_monitor_mode(struct capmon *cm)
{
	struct ring_buffer *rb = NULL;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	err = skel_setup(cm, &rb, handle_cap_check, NULL);
	if (err)
		goto cleanup;

	/* Process events */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			ERR("error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	skel_destroy(cm, &rb);
	return err < 0 ? -err : 0;
}
