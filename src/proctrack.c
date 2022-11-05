// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdlib.h>
#include <errno.h>
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

	stats_add_cap(cm, e);

	return 0;
}


static int handle_proc_start(void *ctx, void *data, size_t data_sz)
{
	const struct event_proc_start *e = data;
	struct capmon *cm = ctx;
	pid_t *pid_p;
	void *found;
	UNUSED(data_sz);

	found = tfind(&e->pid, &cm->pid_tree, pid_cmp);

	if (found)
		return 0; /* Pid already accounted for */

	/* Pid not found, check if parent is found */
	found = tfind(&e->ppid, &cm->pid_tree, pid_cmp);

	if (found) {
		/* Parent found, keep track of child */
		pid_p = malloc(sizeof(pid_t));
		if (!pid_p) {
			ERR("failed to allocate memory\n");
			return -ENOMEM;
		}
		*pid_p = e->pid;
		tsearch(pid_p, &cm->pid_tree, pid_cmp);
	}
	return 0;
}

void proc_summary(struct capmon *cm)
{
	struct process_stats *ps;
	struct stats name_stats;
	LIST_INIT(&name_stats);
	bool has_cap;
	int cap;

	for (ps = cm->process_stats.lh_first; ps != NULL; ps = ps->entries.le_next) {
		if (!tfind(&ps->pid, &cm->pid_tree, pid_cmp))
			continue;
		stats_union_cap(&name_stats, SUMMARY_COMM, *ps);
	}

	for (ps = name_stats.lh_first; ps != NULL; ps = ps->entries.le_next) {
		printf("%s\n", ps->comm);
		for (cap = 0; cap <= CAP_LAST_CAP; cap++)
			if (test_bit(cap, ps->capabilities)) {
				has_cap = test_bit(cap, ps->has_capability);
				printf("\t%-22s %s\n", cap_to_str(cap), has_cap ? "true" : "false");
			}
		if (ps->entries.le_next)
			printf("\n");
	}
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/*https://stackoverflow.com/questions/22802902/how-to-get-pid-of-process-executed-with-system-command-in-c*/
pid_t system2(const char *command)
{
	pid_t pid;

	pid = fork();

	if (pid < 0) {
		return pid;
	} else if (pid == 0) {
		signal(SIGINT, SIG_DFL); /* Re-enable signals to child process */
		/*setsid();*/
		execl("/bin/sh", "sh", "-c", command, NULL);
		_exit(1);
	}

	return pid;
}

int run_proctrack_mode(struct capmon *cm)
{
	struct ring_buffer *rb = NULL;
	int err, status;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, sig_handler);

	err = skel_setup(cm, &rb, handle_cap_check, handle_proc_start);
	if (err)
		goto cleanup;

	pid_t *root_pid = malloc(sizeof(pid_t));
	if (!root_pid) {
		err = -ENOMEM;
		ERR("failed to allocate memory\n");
		goto cleanup;
	}

	*root_pid = system2(cm->proctrack_cmd);
	if (*root_pid < 0) {
		err = *root_pid;
		ERR("failed to create fork\n");
		goto cleanup;
	}

	tsearch(root_pid, &cm->pid_tree, pid_cmp);

	/* Process events */
	while (true) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		status = waitpid(*root_pid, NULL, WNOHANG);
		if (status != 0) /* Process exited, but we don't care how */
			break;
	}

cleanup:
	/* Clean up */
	skel_destroy(cm, &rb);
	return err < 0 ? -err : 0;
}
