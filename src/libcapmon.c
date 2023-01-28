// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "capabilities.h"
#include "libcapmon.h"

INIT_BPFOBJ(capable_std)
INIT_BPFOBJ(capable_all)
INIT_BPFOBJ(proc_exec)

int skel_setup(struct capmon *cm, struct ring_buffer **rb, handler_t cap_handler, handler_t proc_handler)
{
	int err = 0;

	if (cm->cap_all){
		err = capable_all_init(&cm->skel.skel_all);
		if (err)
			return err;
		*rb = ring_buffer__new(bpf_map__fd(cm->skel.skel_all->maps.rb), cap_handler, cm, NULL);
	} else {
		err = capable_std_init(&cm->skel.skel_std);
		if (err)
			return err;
		*rb = ring_buffer__new(bpf_map__fd(cm->skel.skel_std->maps.rb), cap_handler, cm, NULL);
	}
	if (!*rb) {
		ERR("failed to create ring buffer\n");
		return -EBUSY;
	}

	if (cm->run_mode == RUNMODE_PROCTRACK) {
		proc_exec_init(&cm->skel.skel_exec);
		err = ring_buffer__add(*rb, bpf_map__fd(cm->skel.skel_exec->maps.rb), proc_handler, cm);
		if (err)
			ERR("failed to attach proc_exec to ring buffer\n");
	}
	return err;
}

void skel_destroy(struct capmon *cm, struct ring_buffer **rb)
{
	ring_buffer__free(*rb);
	if (cm->cap_all)
		capable_all_bpf__destroy(cm->skel.skel_all);
	else
		capable_std_bpf__destroy(cm->skel.skel_std);

	if (cm->run_mode == RUNMODE_PROCTRACK)
		proc_exec_bpf__destroy(cm->skel.skel_exec);
}

static void print_filters(struct capmon *cm)
{
	struct filter *f;

	printf("\n--- Filters ---\n");
	for (f = cm->filters.lh_first; f != NULL; f = f->entries.le_next) {
		switch (f->type) {
		case FILTER_PID:
			printf("Filter pid %d\n", f->pid);
			break;
		case FILTER_CAP:
			printf("Filter cap %s\n", cap_to_str(f->cap));
			break;
		case FILTER_COMM:
			printf("Filter comm \"%s\"\n", f->comm_pattern);
			break;
		}
	}
}

int filter_create(struct capmon *cm, enum filtertypes type, char *optarg)
{
	struct filter *filter;
	int err;

	filter = calloc(1, sizeof(struct filter));
	if (!filter) {
		ERR("failed to allocate memory\n");
		return -ENOMEM;
	}
	filter->type = type;

	switch (type) {
	case FILTER_PID:
		filter->pid = atoi(optarg);
		if (filter->pid <= 0) {
			ERR("filter pid - \"%s\" invalid argument\n", optarg);
			goto out_err;
		}
		break;
	case FILTER_CAP:
		filter->cap = str_to_cap(optarg);
		if (filter->cap < 0 || filter->cap > CAP_LAST_CAP) {
			ERR("filter cap - \"%s\" not a capability\n", optarg);
			goto out_err;
		}
		break;
	case FILTER_COMM:
		err = regcomp(&filter->comm, optarg, REG_EXTENDED);
		if (err != 0) {
			ERR("Invalid regex pattern, returning %d\n", err);
			goto out_regex_err;
		}
		#pragma GCC diagnostic ignored "-Wstringop-truncation"
		strncpy(filter->comm_pattern, optarg, REGEX_LEN);
		break;
	}

	LIST_INSERT_HEAD(&cm->filters, filter, entries);
	return 0;

out_regex_err:
	regfree(&filter->comm);
out_err:
	free(filter);
	return -EINVAL;
}

bool filter_match_entry(struct capmon *cm, const struct event_cap_check *e)
{
	bool pid_filter  = false;
	bool pid_match   = false;
	bool cap_filter  = false;
	bool cap_match   = false;
	bool comm_filter = false;
	bool comm_match  = false;
	regmatch_t pmatch[1];
	size_t nmatch = 1;
	struct filter *f;
	int res;

	for (f = cm->filters.lh_first; f != NULL; f = f->entries.le_next) {
		switch (f->type) {
		case FILTER_PID:
			pid_filter = true;
			if (e->pid == f->pid)
				pid_match = true;
			break;
		case FILTER_CAP:
			cap_filter = true;
			if (e->cap == f->cap)
				cap_match = true;
			break;
		case FILTER_COMM:
			comm_filter = true;
			res = regexec(&f->comm, e->comm, nmatch, pmatch, 0);
			if (res == 0)
				comm_match = true;
			break;
		}
	}
	/* If there is no filter of that type, return true for it. Else use match result */
	return (!pid_filter || pid_match) && (!cap_filter || cap_match) && (!comm_filter || comm_match);
}

struct process_stats event_to_stats(const struct event_cap_check *e)
{
	struct process_stats stat;

	stat.pid = e->pid;
	zero_bitmap(stat.capabilities, NUM_CAPS);
	zero_bitmap(stat.has_capability, NUM_CAPS);
	set_bit(e->cap, stat.capabilities);
	if (e->has_cap)
		set_bit(e->cap, stat.has_capability);
	strncpy(stat.comm, e->comm, COMM_NAME_LEN);
	return stat;
}

void stats_union_cap(struct stats *list, enum summary_mode mode, const struct process_stats ps)
{
	struct process_stats *iter;

	if (mode == SUMMARY_NONE)
		return;

	for (iter = list->lh_first; iter != NULL; iter = iter->entries.le_next) {
		if (mode == SUMMARY_COMM && strcmp(ps.comm, iter->comm) == 0) {
			union_bitmap(iter->capabilities, ps.capabilities, NUM_CAPS);
			return;
		} else if (mode == SUMMARY_PID && ps.pid == iter->pid) {
			union_bitmap(iter->capabilities, ps.capabilities, NUM_CAPS);
			return;
		}
	}

	/* New process comm/pid */

	/* TODO: propagate error */
	iter = calloc(1, sizeof(struct process_stats));
	if (!iter)
		return;

	if (mode == SUMMARY_PID)
		iter->pid = ps.pid;

	strncpy(iter->comm, ps.comm, COMM_NAME_LEN);
	union_bitmap(iter->capabilities, ps.capabilities, NUM_CAPS);
	union_bitmap(iter->has_capability, ps.has_capability, NUM_CAPS);
	LIST_INSERT_HEAD(list, iter, entries);
}

void stats_add_cap(struct capmon *cm, const struct event_cap_check *e)
{
	stats_union_cap(&cm->process_stats, cm->summary, event_to_stats(e));
}

void stats_print_summary(struct capmon *cm)
{
	struct process_stats *ps;
	int cap;

	for (ps = cm->process_stats.lh_first; ps != NULL; ps = ps->entries.le_next) {
		if (cm->summary == SUMMARY_PID)
			printf("%d - %s\n", ps->pid, ps->comm);
		else if (cm->summary == SUMMARY_COMM)
			printf("%s\n", ps->comm);

		for (cap = 0; cap <= CAP_LAST_CAP; cap++)
			if (test_bit(cap, ps->capabilities))
				printf("\t%s\n", cap_to_str(cap));
		if (ps->entries.le_next)
			printf("\n");
	}
}

int pid_cmp(const void *a, const void *b)
{
	return *(pid_t*)a - *(pid_t*)b;
}

void capmon_print(struct capmon *cm)
{
	printf("--- CAPMON ---\n");
	printf("Summary mode: %d\n", cm->summary);
	printf("Run mode: %d\n", cm->run_mode);
	printf("Cap_all: %d\n", cm->cap_all);
	print_filters(cm);

	printf("\n--------------\n");
}

int capmon_init(struct capmon *cm)
{
	LIST_INIT(&cm->filters);
	LIST_INIT(&cm->process_stats);
	cm->pid_tree = NULL;
	cm->summary  = SUMMARY_PID;
	cm->run_mode = RUNMODE_PROCTRACK;
	cm->cap_all  = false;
	return 0;
}

void capmon_destroy(struct capmon *cm)
{
	struct process_stats *ps;
	struct filter *f;

	while (cm->filters.lh_first != NULL) {
		f = cm->filters.lh_first;
		if (f->type == FILTER_COMM)
			regfree(&f->comm);
		LIST_REMOVE(cm->filters.lh_first, entries);
		free(f);
	}

	while (cm->process_stats.lh_first != NULL) {
		ps = cm->process_stats.lh_first;
		LIST_REMOVE(cm->process_stats.lh_first, entries);
		free(ps);
	}
}
