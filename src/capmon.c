
#include <stdio.h>
/*#include <stdint.h>*/
/*#include <stdbool.h>*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/queue.h>

#include <unistd.h>

#include "debug.h"
#include "kprobes.h"
#include "capabilities.h"

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

/*struct log_filters {*/
	/*regex_t regex;*/
	/*int pid;*/
	/*bool (*cap_filter)(int);*/
/*};*/




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

int probe_log()
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

	err = select_probe(cm, "capmon_ns");
	if (err)
		return err;

	err = select_probe(cm, "capmon_inode");
	if (err)
		return err;

	err = kprobes_create(cm);
	if (err)
		goto out_destroy;

	err = kprobes_enable(cm);
	if (err)
		goto out_disable;

	keep_running = true;
	signal(SIGINT, sig_handler);

	printf("--- capmon monitor mode ---\n");
	probe_log();


out_disable:
	kprobes_disable(cm);

out_destroy:
	kprobes_destroy(cm);
	return err;
}

int main(int argc, char **argv)
{
	int err;

	struct capmon capmon;

	init_probelists(&capmon);

	/* TODO: handle errors from probe functions? */
	if (argc == 1) {
		run_monitor_mode(&capmon);

	} else if (strcmp(argv[1], "ena") == 0) {
		/*dbg("Enable %s\n", PROBE_NS);*/

		/*probe_create(probes[0]);*/
		/*probe_create(probes[1]);*/
		/*if (err)*/
			/*// TODO: Error if probe already exists?*/
			/*return err;*/
		/*dbg("Created\n");*/

		/*err = probe_enable();*/
		/*if (err) {*/
			/*probe_destroy();*/
			/*return err;*/
		/*}*/
		/*dbg("Enabled\n");*/

	/*} else if (strcmp(argv[1], "dis") == 0) {*/
		/*dbg("Disable\n");*/
		/*err = probe_disable();*/
		/*if (err)*/
			/*printf("Error: %s\n", strerror(err));*/

		/*dbg("Disabled\n");*/
		/*err = probe_destroy();*/
		/*if (err) {*/
			/*printf("Error: %s\n", strerror(err));*/
			/*return err;*/
		/*}*/
		/*dbg("Deleted\n");*/
		/*return 0;*/

	} else if (strcmp(argv[1], "log") == 0) {
		probe_log();

	} else if (strcmp(argv[1], "clear") == 0) {
		system("echo 0 > /sys/kernel/debug/tracing/trace");
	} 

	return 0;
}
