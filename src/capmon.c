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
	int err = 0;
	char ch;

	struct option long_options[] = {
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
			cm->run_mode = RUNMODE_NONE;
			goto out;
		case 'h':
			usage();
			cm->run_mode = RUNMODE_NONE;
			goto out;
		case 'a':
			cm->cap_all = true;
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

out:
	return err;
}

int main(int argc, char **argv)
{
	struct capmon capmon;
	int err = 0;

	capmon_init(&capmon);

	err = parse_args(&capmon, argc, argv);
	if (err)
		goto out;

	/*capmon_print(&capmon);*/

	run_monitor_mode(&capmon);

out:
	capmon_destroy(&capmon);
	return err;
}
