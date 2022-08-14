// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include "monitor.h"
#include "kprobes.h"
#include "capabilities.h"

static bool keep_running;

static int parse_entry(char *line, int len, struct log_entry *entry)
{
	char *ptr;
	int comm_len;
/*
 * Sample line from /sys/log/debug/tracing/trace:
systemd-journal-525     [002] ...1. 16449.937047: capmon_ns: (ns_capable+0x0/0x50) cap=0x13 comm="systemd-journal"
*/
	if (len <= 37) /* Avoid out of bounds access */
		return -EINVAL;

	ptr = line + 17;
	entry->pid = atoi(ptr);

	ptr = line + 37;
	entry->time = atol(ptr);

	ptr = strstr(line, "cap=");
	if (!ptr)
		return -EINVAL;

	ptr += 6;
	entry->cap = strtol(ptr, NULL, 16);

	ptr = strstr(line, "comm=");
	if (!ptr)
		return -EINVAL;

	ptr += 6;
	for (comm_len = 0;
	     ptr[comm_len] != '"' && comm_len < COMM_NAME_LEN;
	     comm_len++) {
	}

	strncpy(entry->comm, ptr, comm_len);
	entry->comm[comm_len] = '\0';

	return 0;
}

static bool filter_match_entry(struct capmon *cm, struct log_entry *entry)
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
			if (entry->pid == f->pid)
				pid_match = true;
			break;
		case FILTER_CAP:
			cap_filter = true;
			if (entry->cap == f->cap)
				cap_match = true;
			break;
		case FILTER_COMM:
			comm_filter = true;
			res = regexec(&f->comm, entry->comm, nmatch, pmatch, 0);
			if (res == 0)
				comm_match = true;
			break;
		}
	}
	/* if there is no filter of that type, return true for it. Else use match result */
	return (!pid_filter || pid_match) && (!cap_filter || cap_match) && (!comm_filter || comm_match);
}

static void print_log_entry(struct log_entry *entry)
{
	printf("%-8ld  %-16s  %-7d  %-22s\n",
	       entry->time,
	       entry->comm,
	       entry->pid,
	       cap_to_str(entry->cap));
}

static int probe_monitor(struct capmon *cm)
{
	char linebuffer[BUFSIZE];
	struct log_entry entry;
	FILE *logfile;
	int pos, err, counter;
	struct timeval second;
	char ch;

	second.tv_sec = 0;
	second.tv_usec = 100000; /* Sleep 1ms */
	counter = 0;
	pos = 0;

	logfile = fopen(KPROBES_LOG, "r");
	if (!logfile)
		return errno;

	printf("-----------------------------------------------\n");
	printf("Time    | Process         | Pid    | Capability\n");
	printf("-----------------------------------------------\n");

	while (true) {
		while ((ch = getc(logfile)) != EOF && keep_running) {

			// TODO: Handle idx out of range in buffer?
			linebuffer[pos] = ch;
			pos++;
			if (ch == '\n') {
				linebuffer[pos] = '\0';
				err = parse_entry(linebuffer, pos, &entry);
				if (!err && filter_match_entry(cm, &entry)) {
					print_log_entry(&entry);
					stats_add_cap(cm, &entry);
				}
				pos = 0;
				counter++;
			}
		}

		if (!keep_running)
			break;

		if (ferror(logfile))
			break;

		clearerr(logfile);
		(void)fflush(stdout);

		if (select(0, NULL, NULL, NULL, &second) == -1)
			break;
	}
	fclose(logfile);
	printf("\n");

	if (cm->summary)
		stats_print_summary(cm);
	return errno;
}

static void sig_handler(int signo)
{
	UNUSED(signo);
	keep_running = false;
}

int run_monitor_mode(struct capmon *cm)
{
	int err = 0;

	if (!cm->in_background) {
		err = kprobes_start(cm);
		if (err)
			return 0;
	} else {
		printf("Attaching to active kprobe monitor\n");
	}

	keep_running = true;
	signal(SIGINT, sig_handler);

	probe_monitor(cm);

	if (!cm->in_background)
		kprobes_stop(cm);

	return 0;
}
