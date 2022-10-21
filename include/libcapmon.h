// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#ifndef _CAPMON_LIBCAPMON_H_
#define _CAPMON_LIBCAPMON_H_

#include <stdlib.h>
#include <linux/types.h>
#include <linux/capability.h>
#include <sys/queue.h>
#include <regex.h>
#include <search.h>

#include "bits.h"
#include "bpf_event.h"

#define ERR(str, ...) fprintf(stderr, "Error: "str, ##__VA_ARGS__)
#define UNUSED(x) (void)(x)
#define NAME_LEN 50
#define COMM_NAME_LEN 16
#define CAP_NAME_LEN 22
#define REGEX_LEN 200

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

typedef void* tree;

struct capmon {
	LIST_HEAD(filters, filter) filters;
	LIST_HEAD(stats, process_stats) process_stats;
	tree pid_tree;
	enum summary_mode summary;
	bool in_background;
	enum run_mode run_mode;
	bool cap_all;
};

/* monitor.c */
int run_monitor_mode(struct capmon *cm);

/* libcapmon.c */
int filter_create(struct capmon *cm, enum filtertypes type, char *optarg);
bool filter_match_entry(struct capmon *cm, const struct event_cap_check *e);
void stats_add_cap(struct capmon *cm, const struct event_cap_check *e);
void stats_print_summary(struct capmon *cm);
int capmon_init(struct capmon *cm);
void capmon_destroy(struct capmon *cm);

#endif /* _CAPMON_LIBCAPMON_H_ */
