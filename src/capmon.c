
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

#define BUFSIZE 1000
#define COMM_NAME_LEN 16
#define CAP_NAME_LEN 22

static volatile bool keep_running;

struct log_entry {
	char comm[COMM_NAME_LEN];
	long long time;
	int pid;
	int cap;
};

int parse_entry(char *line, int len, struct log_entry *entry)
{
	char *cap;
	char *comm;
	char *opts;
	int comm_len, err;

	cap = strstr(line, "cap=");
	if (!cap) {
		return EINVAL;
	}

	cap += 6;
	entry->cap = strtol(cap, NULL, 16);

	comm = strstr(line, "comm=");
	if (!comm) {
		return 3;
	}

	comm += 6;
	for (comm_len = 0;
	     comm[comm_len] != '"' && comm_len < COMM_NAME_LEN;
	     comm_len++) { }

	strncpy(entry->comm, comm, comm_len);
	entry->comm[comm_len] = '\0';

	return 0;
}

void print_log_entry(struct log_entry *entry)
{
	printf("Process=%-16s Cap=%-22s\n", entry->comm, cap_to_str(entry->cap));
}

int probe_monitor()
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

	while(true) {
		while ((ch = getc(logfile)) != EOF && keep_running)  {

			// TODO: Handle idx out of range in buffer?
			linebuffer[pos] = ch;	
			pos++;
			if (ch == '\n') {
				linebuffer[pos] = '\0';
				err = parse_entry(linebuffer, pos, &entry);
				if (!err)
					print_log_entry(&entry);
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
	return errno;
}

void sig_handler(int signo)
{
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

	printf("--- capmon monitor mode ---\n");
	probe_monitor();

out_disable:
	kprobes_disable(cm);

out_destroy:
	kprobes_destroy(cm);
	return err;
}

int main(int argc, char **argv)
{
	int ena_background = 0;
	int dis_background = 0;
	bool cap_all = false;
	int err = 0;
	char ch;

	struct capmon capmon;

	capmon_init(&capmon);

	struct option long_options[] =
	{
		{"enable", no_argument, &ena_background, 1},
		{"disable", no_argument, &dis_background, 1},
		{NULL, 0, NULL, 0}
	};

	while ((ch = getopt_long(argc, argv, "ap:c:n:s:", long_options, NULL)) != -1) {

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
		case 'n':
			err = filter_create(&capmon, FILTER_COMM, optarg);
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
			} else if (strcmp(optarg, "comm") == 0) {
				capmon.summary = SUMMARY_COMM;
			} else {
				ERR("invalid summary mode\n");
				err = EINVAL;
				goto out;
			}
			break;;
	    }
	}

	if (optind == argc - 1) { /* Final unmatched argument is comm filter */
		err = filter_create(&capmon, FILTER_COMM, argv[optind]);
		if (err)
			goto out;
	}

	if (ena_background && dis_background) {
		ERR("cannot enable and disable at the same time\n");
		err = EINVAL;
		goto out;
	}

	if (cap_all) {
		probe_select(&capmon, "capmon_all");
	} else {
		probe_select(&capmon, "capmon_ns");
		probe_select(&capmon, "capmon_inode");
	}

	capmon_print(&capmon);

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
