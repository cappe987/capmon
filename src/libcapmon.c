// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "capabilities.h"
#include "libcapmon.h"

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

void stats_add_cap(struct capmon *cm, const struct event_cap_check *e)
{
	struct process_stats *ps;

	if (cm->summary == SUMMARY_NONE)
		return;

	for (ps = cm->process_stats.lh_first; ps != NULL; ps = ps->entries.le_next) {
		if (cm->summary == SUMMARY_COMM && strcmp(e->comm, ps->comm) == 0) {
			set_bit(e->cap, ps->capabilities);
			return;
		} else if (cm->summary == SUMMARY_PID && e->pid == ps->pid) {
			set_bit(e->cap, ps->capabilities);
			return;
		}
	}

	/* New process comm/pid */

	/* TODO: propagate error */
	ps = calloc(1, sizeof(struct process_stats));
	if (!ps)
		return;

	if (cm->summary == SUMMARY_PID)
		ps->pid = e->pid;

	strncpy(ps->comm, e->comm, COMM_NAME_LEN);

	set_bit(e->cap, ps->capabilities);
	LIST_INSERT_HEAD(&cm->process_stats, ps, entries);
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

	cm->summary = SUMMARY_NONE;
	cm->in_background = false;
	cm->cap_all = false;

	return 0;
}

void capmon_destroy(struct capmon *cm)
{
	struct filter *f;
	struct process_stats *ps;

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
