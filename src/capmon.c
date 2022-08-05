// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>


#include "debug.h"
#include "kprobes.h"
#include "capabilities.h"
#include "libcapmon.h"
#include "version.h"

#define BUFSIZE 1000

static volatile bool keep_running;

int parse_entry(char *line, int len, struct log_entry *entry)
{
	char *ptr;
	int comm_len;
/*
 * Sample line from /sys/log/debug/tracing/trace:
systemd-journal-525     [002] ...1. 16449.937047: capmon_ns: (ns_capable+0x0/0x50) cap=0x13 comm="systemd-journal"
*/
	if (len <= 37) /* Avoid out of bounds access */
		return EINVAL;

	ptr = line + 17;
	entry->pid = atoi(ptr);

	ptr = line + 37;
	entry->time = atol(ptr);

	ptr = strstr(line, "cap=");
	if (!ptr) {
		return EINVAL;
	}

	ptr += 6;
	entry->cap = strtol(ptr, NULL, 16);

	ptr = strstr(line, "comm=");
	if (!ptr) {
		return EINVAL;
	}

	ptr += 6;
	for (comm_len = 0;
	     ptr[comm_len] != '"' && comm_len < COMM_NAME_LEN;
	     comm_len++) { }

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

	for (f = cm->filters.lh_first; f != NULL; f = f->entries.le_next) {
		switch(f->type) {
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
				if (strncmp(entry->comm, f->comm, COMM_NAME_LEN) == 0)
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

	while(true) {
		while ((ch = getc(logfile)) != EOF && keep_running)  {

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

		if (ferror(logfile)) {
			break;
		}
		clearerr(logfile);
		(void)fflush(stdout);

		if (select(0, NULL, NULL, NULL, &second) == -1)
			break;
	}
	fclose(logfile);
	printf("\n");

	if (cm->summary) {
		stats_print_summary(cm);
	}
	return errno;
}

void sig_handler(int signo)
{
	UNUSED(signo);
	keep_running = false;
}

int run_monitor_mode(struct capmon *cm)
{
	int err;

	err = kprobes_create(cm);
	if (err)
		goto out_destroy;

	err = kprobes_enable(cm);
	if (err)
		goto out_disable;

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

void print_help()
{
	PRINT_VERSION();

	printf("\nUSAGE:\n");
	printf("\t capmon [OPTIONS] [PATTERNS]\n");

	printf("\nPATTERNS:\n");
	printf("\tFilter output by process name.\n");

	printf("\nOPTIONS:\n");
	printf("\t-p, --pid <PID>\n");
	printf("\t    Filter output by process ID.\n");
	printf("\n");
	printf("\t-c, --capability <CAP>\n");
	printf("\t    Filter output by Capability. E.g., CAP_NET_RAW\n");
	printf("\n");
	printf("\t-s, --summary <pid|name>\n");
	printf("\
\t    Enable summary mode. Summary mode keeps track of all the capabilities\n\
\t    either <pid> or <name> uses and prints a summary at the end when you stop\n\
\t    capmon.\n");
	printf("\n");
	printf("\t-a, --all\n");
	printf("\
\t    Listen to ALL capability checks. By default it only listens to the functions\n\
\t    `ns_capable` and `capable_wrt_inode_uidgid`. This listens directly to the\n\
\t    `cap_capable` function.\n");
	printf("\n");
	printf("\t--enable\n");
	printf("\
\t    Enable monitoring in background. Start program without --enable or --disable\n\
\t    to monitor.\n");
	printf("\n");
	printf("\t--disable\n");
	printf("\
\t    Disable monitoring in background.\n");
}

int main(int argc, char **argv)
{
	int ena_background = 0;
	int dis_background = 0;
	int version = 0;
	bool cap_all = false;
	int err = 0;
	char ch;

	struct capmon capmon;

	capmon_init(&capmon);

	struct option long_options[] =
	{
		{"enable",      no_argument, &ena_background, 1   },
		{"disable",     no_argument, &dis_background, 1   },
		{"version",     no_argument, &version,        1   },
		{ "help",       no_argument, NULL,            'h' },
		{ "all",        no_argument, NULL,            'a' },
		{ "pid",        no_argument, NULL,            'p' },
		{ "capability", no_argument, NULL,            'c' },
		{ "summary",    no_argument, NULL,            's' },
		{NULL,          0,           NULL,            0   }
	};

	while ((ch = getopt_long(argc, argv, "ap:c:n:s:h", long_options, NULL)) != -1) {

		switch (ch) {
		case 'a':
			cap_all = true;
			break;
		case 'p':
			err = filter_create(&capmon, FILTER_PID, optarg);
			if (err)
				goto out;
			break;
		case 'c':
			err = filter_create(&capmon, FILTER_CAP, optarg);
			if (err)
				goto out;
			break;
		case 's':
			if (capmon.summary != SUMMARY_NONE) {
				ERR("sumary mode already set\n");
				err = EINVAL;
				goto out;
			}
			if (strcmp(optarg, "pid") == 0) {
				capmon.summary = SUMMARY_PID;
			} else if (strcmp(optarg, "name") == 0) {
				capmon.summary = SUMMARY_COMM;
			} else {
				ERR("invalid summary mode\n");
				err = EINVAL;
				goto out;
			}
			break;;
		case 'h':
			print_help();
			goto out;
		case '?':
			goto out;
	    }
	}

	if (version) {
		PRINT_VERSION();
		goto out;
	}

	for (; optind <= argc - 1; optind++) { /* Final unmatched argument is comm filter */
		err = filter_create(&capmon, FILTER_COMM, argv[optind]);
		if (err)
			goto out;
	}

	if (ena_background && dis_background) {
		ERR("cannot enable and disable at the same time\n");
		err = EINVAL;
		goto out;
	}

	if (kprobes_select_enabled(&capmon)) {
		printf("Attaching to active kprobe monitor\n");
	} else {
		if (cap_all) {
			probe_select(&capmon, "capmon_all");
		} else {
			probe_select(&capmon, "capmon_ns");
			probe_select(&capmon, "capmon_inode");
		}

	}

	/*capmon_print(&capmon);*/

	if (ena_background) { /* TODO: proper error handling for background enable */
		kprobes_create(&capmon);
		kprobes_enable(&capmon);
	} else if (dis_background) {
		kprobes_disable(&capmon);
		kprobes_destroy(&capmon);
	} else {
		run_monitor_mode(&capmon);
	}

	goto out;

out:
	capmon_destroy(&capmon);
	return err;
}
