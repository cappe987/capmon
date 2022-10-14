// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#ifndef _CAPMON_LIBCAPMON_H
#define _CAPMON_LIBCAPMON_H

#include <stdlib.h>
#include <linux/types.h>
#include <linux/capability.h>
#include <sys/queue.h>
#include <regex.h>

#include "bits.h"
#include "bpf_event.h"

#define ERR(str, ...) fprintf(stderr, "Error: "str, ##__VA_ARGS__)
#define UNUSED(x) (void)(x)
#define NAME_LEN 50
#define COMM_NAME_LEN 16
#define CAP_NAME_LEN 22
#define REGEX_LEN 200

struct probe {
	LIST_ENTRY(probe) entries;
	char name[NAME_LEN];
	char function[NAME_LEN];
	/* Index of the argument `int capability`, index starts at 1 */
	int cap_argnum;
};

enum filtertypes {
	FILTER_PID,
	FILTER_CAP,
	FILTER_COMM
};

enum summary_mode {
	SUMMARY_NONE,
	SUMMARY_PID,
	SUMMARY_COMM
};

struct filter {
	LIST_ENTRY(filter) entries;
	enum filtertypes type;
	union {
		int pid;
		int cap;
		regex_t comm;
	};
	char comm_pattern[REGEX_LEN];
};

struct log_entry {
	char comm[COMM_NAME_LEN];
	time_t time;
	int pid;
	int cap;
};

/* TODO: Replace with hash table later? */
struct process_stats {
	LIST_ENTRY(process_stats) entries;
	char comm[COMM_NAME_LEN];
	int pid;
	DECLARE_BITMAP(capabilities, CAP_LAST_CAP+1);
};

enum run_mode {
	RUNMODE_NONE,
	RUNMODE_MONITOR,
	RUNMODE_ENA_BG,
	RUNMODE_DIS_BG
};

struct capmon {
	LIST_HEAD(available_probes, probe) available_probes;
	LIST_HEAD(selected_probes, probe) selected_probes;
	LIST_HEAD(filters, filter) filters;
	LIST_HEAD(stats, process_stats) process_stats;
	enum summary_mode summary;
	bool in_background;
	enum run_mode run_mode;
	bool cap_all;
	//struct available_probes *headp2;
	//struct selected_probes *headp1;
};

int probe_select(struct capmon *cm, char *name);
int filter_create(struct capmon *cm, enum filtertypes type, char *optarg);
void stats_add_cap(struct capmon *cm, const struct event *e);
void stats_print_summary(struct capmon *cm);
void capmon_print(struct capmon *cm);
int capmon_init(struct capmon *cm);
void capmon_destroy(struct capmon *cm);

#endif /* _CAPMON_LIBCAPMON_H */
