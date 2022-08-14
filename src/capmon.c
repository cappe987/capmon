// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <regex.h>

#include "debug.h"
#include "kprobes.h"
#include "capabilities.h"
#include "libcapmon.h"
#include "version.h"

#define BUFSIZE 1000

static bool keep_running;

int parse_entry(char *line, int len, struct log_entry *entry)
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

bool filter_match_entry(struct capmon *cm, struct log_entry *entry)
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

void print_log_entry(struct log_entry *entry)
{
	printf("%-8ld  %-16s  %-7d  %-22s\n",
	       entry->time,
	       entry->comm,
	       entry->pid,
	       cap_to_str(entry->cap));
}

int probe_monitor(struct capmon *cm)
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

void sig_handler(int signo)
{
	UNUSED(signo);
	keep_running = false;
}

int run_monitor_mode(struct capmon *cm)
{
	int err = 0;

	if (!cm->in_background) {
		err = kprobes_create(cm);
		if (err)
			goto out_destroy;

		err = kprobes_enable(cm);
		if (err)
			goto out_disable;
	} else {
		printf("Attaching to active kprobe monitor\n");
	}

	keep_running = true;
	signal(SIGINT, sig_handler);

	probe_monitor(cm);

	if (cm->in_background)
		goto out;

out_disable:
	kprobes_disable(cm);

out_destroy:
	kprobes_destroy(cm);

out:
	return err;
}

void usage(void)
{
	fputs("capmon - Linux Capabilities Monitor\n"
	      "\n"
	      "USAGE:\n"
	      "        capmon [OPTIONS] [PATTERNS]\n"
	      "\n"
	      "PATTERNS:\n"
	      "        Filter by process name. Supports POSIX-Extended Regular Expressions.\n"
	      "        (tip: use quotation marks to avoid the shell interpreting as globbing)\n"
	      "\n"
	      "OPTIONS:\n"
	      "        -p, --pid <PID>\n"
	      "            Filter output by process ID.\n"
	      "\n"
	      "        -c, --capability <CAP>\n"
	      "            Filter output by Capability. E.g., CAP_NET_RAW\n"
	      "\n"
	      "        -s, --summary <pid|name>\n"
	      "            Enable summary mode. Summary mode keeps track of all the capabilities\n"
	      "            either <pid> or <name> uses and prints a summary at the end when you stop\n"
	      "            capmon.\n"
	      "\n"
	      "        -a, --all\n"
	      "            Listen to ALL capability checks. By default it only listens to the functions\n"
	      "            `ns_capable` and `capable_wrt_inode_uidgid`. This listens directly to the\n"
	      "            `cap_capable` function.\n"
	      "\n"
	      "        --enable\n"
	      "            Enable monitoring in background. Start program without --enable or --disable\n"
	      "            to monitor.\n"
	      "\n"
	      "        --disable\n"
	      "            Disable monitoring in background.\n",
	      stderr);
}

enum run_mode {
	RUNMODE_NONE,
	RUNMODE_MONITOR,
	RUNMODE_ENA_BG,
	RUNMODE_DIS_BG
};

int parse_args(struct capmon *cm, enum run_mode *mode, int argc, char **argv)
{
	int ena_bg, dis_bg, err = 0;
	bool cap_all = false;
	char ch;

	struct option long_options[] = {
		{"enable",      no_argument, &ena_bg, 1   },
		{"disable",     no_argument, &dis_bg, 1   },
		{"version",     no_argument, NULL,            'v' },
		{ "help",       no_argument, NULL,            'h' },
		{ "all",        no_argument, NULL,            'a' },
		{ "pid",        no_argument, NULL,            'p' },
		{ "capability", no_argument, NULL,            'c' },
		{ "summary",    no_argument, NULL,            's' },
		{NULL,          0,           NULL,            0   }
	};

	while ((ch = getopt_long(argc, argv, "vhap:c:n:s:", long_options, NULL)) != -1) {

		switch (ch) {
		case 'v':
			VERSION();
			*mode = RUNMODE_NONE;
			goto out;
		case 'h':
			usage();
			*mode = RUNMODE_NONE;
			goto out;
		case 'a':
			cap_all = true;
			break;
		case 'p':
			err = filter_create(cm, FILTER_PID, optarg);
			if (err)
				goto out;
			break;
		case 'c':
			err = filter_create(cm, FILTER_CAP, optarg);
			if (err)
				goto out;
			break;
		case 's':
			if (cm->summary != SUMMARY_NONE) {
				ERR("summary mode already set\n");
				err = EINVAL;
				goto out;
			}
			if (strcmp(optarg, "pid") == 0) {
				cm->summary = SUMMARY_PID;
			} else if (strcmp(optarg, "name") == 0) {
				cm->summary = SUMMARY_COMM;
			} else {
				ERR("invalid summary mode\n");
				err = EINVAL;
				goto out;
			}
			break;
		case '?':
			goto out;
		}
	}

	for (; optind <= argc - 1; optind++) { /* Unmatched arguments are comm filters */
		err = filter_create(cm, FILTER_COMM, argv[optind]);
		if (err)
			goto out;
	}

	if (ena_bg && dis_bg) {
		ERR("cannot enable and disable at the same time\n");
		err = EINVAL;
		goto out;
	} else if (ena_bg) {
		*mode = RUNMODE_ENA_BG;
	} else if (dis_bg) {
		*mode = RUNMODE_DIS_BG;
	} else {
		*mode = RUNMODE_MONITOR;
	}

	if (!kprobes_select_enabled(cm)) {
		if (cap_all) {
			probe_select(cm, "capmon_all");
		} else {
			probe_select(cm, "capmon_ns");
			probe_select(cm, "capmon_inode");
		}
	}

out:
	return err;
}

int main(int argc, char **argv)
{
	struct capmon capmon;
	enum run_mode mode;
	int err = 0;

	capmon_init(&capmon);

	err = parse_args(&capmon, &mode, argc, argv);
	if (err)
		goto out;

	/*capmon_print(&capmon);*/

	/* TODO: proper error handling for background enable? */
	switch (mode) {
	case RUNMODE_NONE:
		goto out;
	case RUNMODE_MONITOR:
		err = run_monitor_mode(&capmon);
		if (err)
			goto out;
		break;
	case RUNMODE_ENA_BG:
		kprobes_create(&capmon);
		kprobes_enable(&capmon);
		break;
	case RUNMODE_DIS_BG:
		kprobes_disable(&capmon);
		kprobes_destroy(&capmon);
		break;
	}

out:
	capmon_destroy(&capmon);
	return err;
}
