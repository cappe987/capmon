// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "version.h"
#include "libcapmon.h"

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
	      ,stderr);
}

int parse_args(struct capmon *cm, int argc, char **argv)
{
	bool summary_mode_set = false;
	int err = 0, cmdlen = 0, arglen = 0;
	char ch;

	struct option long_options[] = {
		{"version",     no_argument, NULL,            'v' },
		{ "help",       no_argument, NULL,            'h' },
		{ "all",        no_argument, NULL,            'a' },
		{ "monitor",    no_argument, NULL,            'm' },
		{ "pid",        no_argument, NULL,            'p' },
		{ "capability", no_argument, NULL,            'c' },
		{ "summary",    no_argument, NULL,            's' },
		{NULL,          0,           NULL,            0   }
	};

	while ((ch = getopt_long(argc, argv, "vhamp:c:n:s:", long_options, NULL)) != -1) {

		switch (ch) {
		case 'v':
			VERSION();
			cm->run_mode = RUNMODE_NONE;
			goto out;
		case 'h':
			usage();
			cm->run_mode = RUNMODE_NONE;
			goto out;
		case 'a':
			cm->cap_all = true;
			break;
		case 'm':
			cm->run_mode = RUNMODE_MONITOR;
			if (!summary_mode_set)
				cm->summary = false;
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
			if (summary_mode_set) {
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
			summary_mode_set = true;
			break;
		case '?':
			err = EINVAL;
			goto out;
		}
	}

	if (cm->run_mode == RUNMODE_MONITOR) {
		for (; optind <= argc - 1; optind++) { /* Unmatched arguments are comm filters */
			err = filter_create(cm, FILTER_COMM, argv[optind]);
			if (err)
				goto out;
		}
	} else if (cm->run_mode == RUNMODE_PROCTRACK) {
		for (; optind <= argc - 1; optind++) {
			arglen = strlen(argv[optind]);
			if (cmdlen + arglen >= CMD_LEN-1) {
				ERR("input command too long\n");
				err = -EINVAL;
				goto out;
			}
			if (cmdlen > 0) {
				strcat(cm->proctrack_cmd, " ");
				cmdlen += 1;
			}
			strcat(cm->proctrack_cmd, argv[optind]);
			cmdlen += arglen;

		}
		if (cmdlen == 0) {
			ERR("no command provided\n");
			err = -EINVAL;
			goto out;
		}
	}

out:
	return err;
}

int main(int argc, char **argv)
{
	struct capmon capmon = { 0 };
	int err = 0;

	capmon_init(&capmon);

	err = parse_args(&capmon, argc, argv);
	if (err)
		goto out;

	/*capmon_print(&capmon);*/

	switch (capmon.run_mode) {
	case RUNMODE_NONE:
		goto out;
	case RUNMODE_MONITOR:
		printf("----------------------------------------------\n");
		printf("PROCESS         | PID    | PPID   | Capability\n");
		printf("----------------------------------------------\n");
		err = run_monitor_mode(&capmon);
		if (err)
			goto out;
		printf("\n");
		stats_print_summary(&capmon);
		break;

	case RUNMODE_PROCTRACK:
		err = run_proctrack_mode(&capmon);
		if (err)
			goto out;
		printf("\n");
		proc_summary(&capmon);
		break;
	}

out:
	capmon_destroy(&capmon);
	return err;
}
