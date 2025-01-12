// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#ifndef _CAPMON_LIBCAPMON_H_
#define _CAPMON_LIBCAPMON_H_

#include <stdlib.h>
#include <linux/capability.h>
#include <sys/queue.h>
#include <regex.h>
#include <search.h>
#include <bpf/libbpf.h>

#include "bits.h"
#include "bpf_event.h"
#include "capable_std.skel.h"
#include "capable_all.skel.h"
#include "proc_exec.skel.h"

#define ERR(str, ...) fprintf(stderr, "capmon: "str, ##__VA_ARGS__)
#define NUM_CAPS (CAP_LAST_CAP+1)
#define UNUSED(x) (void)(x)
#define NAME_LEN 50
#define COMM_NAME_LEN 16
#define CAP_NAME_LEN 22
#define REGEX_LEN 200
#define CMD_LEN 1024

#define PASS_STR "\033[32m\033[1mPASS\033[0m"
#define FAIL_STR "\033[31m\033[1mFAIL\033[0m"

enum filtertypes {
	FILTER_PID,
	FILTER_CAP,
	FILTER_COMM
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
	DECLARE_BITMAP(capabilities, NUM_CAPS);
	DECLARE_BITMAP(has_capability, NUM_CAPS);
};

typedef void* tree;

enum summary_mode {
	SUMMARY_NONE,
	SUMMARY_PID,
	SUMMARY_COMM
};

enum run_mode {
	RUNMODE_NONE,
	RUNMODE_MONITOR,
	RUNMODE_PROCTRACK
};

struct skeletons {
	struct proc_exec_bpf *skel_exec;
	struct capable_std_bpf *skel_std;
	struct capable_all_bpf *skel_all;
};

LIST_HEAD(stats, process_stats);

struct capmon {
	LIST_HEAD(filters, filter) filters;
	char proctrack_cmd[CMD_LEN];
	struct stats process_stats;
	tree pid_tree;
	enum summary_mode summary;
	enum run_mode run_mode;
	struct skeletons skel;
	bool cap_all;
};

/* monitor.c */
int run_monitor_mode(struct capmon *cm);

/* proctrack.c */
void proc_summary(struct capmon *cm);
int run_proctrack_mode(struct capmon *cm);

/* libcapmon.c */
typedef int handler_t(void *ctx, void *data, size_t data_sz);

int  skel_setup(struct capmon *cm, struct ring_buffer **rb, handler_t cap_handler, handler_t proc_handler);
void skel_destroy(struct capmon *cm, struct ring_buffer **rb);
int  filter_create(struct capmon *cm, enum filtertypes type, char *optarg);
bool filter_match_entry(struct capmon *cm, const struct event_cap_check *e);
void stats_union_cap(struct stats *list, enum summary_mode mode, const struct process_stats p);
void stats_add_cap(struct capmon *cm, const struct event_cap_check *e);
void stats_print_summary(struct capmon *cm);
int  pid_cmp(const void *a, const void *b);
void capmon_print(struct capmon *cm);
int  capmon_init(struct capmon *cm);
void capmon_destroy(struct capmon *cm);

#define INIT_BPFOBJ(OBJ) \
static int OBJ##_init(struct OBJ##_bpf **skel){\
	int err;\
\
	if (skel == NULL) \
		return -EINVAL; \
	/* Load and verify BPF application */\
	*skel = OBJ##_bpf__open();\
	if (*skel == NULL) {\
		ERR("failed to open and load BPF skeleton\n");\
		return 1;\
	}\
\
	/* Load & verify BPF programs */\
	err = OBJ##_bpf__load(*skel);\
	if (err) {\
		ERR("failed to load and verify BPF skeleton\n");\
		return err;\
	}\
\
	/* Attach tracepoints */\
	err = OBJ##_bpf__attach(*skel);\
	if (err) {\
		ERR("failed to attach BPF skeleton\n");\
		return err;\
	}\
	return 0;\
}


#endif /* _CAPMON_LIBCAPMON_H_ */
