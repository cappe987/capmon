// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "debug.h"
#include "capabilities.h"
#include "libcapmon.h"

static void print_probes(struct capmon *cm)
{
	struct probe *p;
	printf("\n--- Available probes ---\n");
	for (p = cm->available_probes.lh_first; p != NULL; p = p->entries.le_next)
		printf("Probe: %s\n", p->name);

	printf("\n--- Selected probes ---\n");
	for (p = cm->selected_probes.lh_first; p != NULL; p = p->entries.le_next)
		printf("Probe: %s\n", p->name);
}

static void print_filters(struct capmon *cm)
{
	struct filter *f;

	printf("\n--- Filters ---\n");
	for (f = cm->filters.lh_first; f != NULL; f = f->entries.le_next) {
		switch(f->type) {
			case FILTER_PID:
				printf("Filter pid %d\n", f->pid);
				break;
			case FILTER_CAP:
				printf("Filter cap %s\n", cap_to_str(f->cap));
				break;
			case FILTER_COMM:
				printf("Filter comm %s\n", f->comm);
				break;
		}
	}
}

static struct probe *init_probe_entry(char *name, char *function, int cap_argnum)
{
	struct probe *p = calloc(1, sizeof(struct probe));
	if (!p)
		return NULL;

	strncpy(p->name, name, NAME_LEN);
	strncpy(p->function, function, NAME_LEN);
	p->cap_argnum = cap_argnum;
	return p;
}

int probe_select(struct capmon *cm, char *name)
{
	struct probe *p, *p_copy;

	for (p = cm->available_probes.lh_first; p != NULL; p = p->entries.le_next) {
		DBG("Selecting... %s?\n", p->name);
		if (strncmp(name, p->name, NAME_LEN) == 0) {
			p_copy = init_probe_entry(p->name, p->function, p->cap_argnum);
			if (!p_copy)
				return ENOMEM;
			LIST_INSERT_HEAD(&cm->selected_probes, p_copy, entries);
			DBG("Found %s\n", p->name);
			return 0;
		}
	}
	fprintf(stderr, "Unable to find capmon probe \"%s\"\n", name);
	return ENOENT;
}

int filter_create(struct capmon *cm, enum filtertypes type, char *optarg)
{
	struct filter *filter;
	filter = calloc(1, sizeof(struct filter));
	if (!filter) {
		ERR("failed to allocate memory\n");
		return ENOMEM;
	}
	filter->type = type;
	
	switch(type) {
		case FILTER_PID:
			filter->pid = atoi(optarg);
			if (filter->pid <= 0) {
				ERR("filter pid - \"%s\" invalid argument\n", optarg);
				goto out_err;
			}
			break;
		case FILTER_CAP:
			filter->cap = str_to_cap(optarg);
			if (filter->cap < 0) {
				ERR("filter cap - \"%s\" not a capability\n", optarg);
				goto out_err;
			}
			break;
		case FILTER_COMM:
			strncpy(filter->comm, optarg, COMM_NAME_LEN);
			break;
	}

	LIST_INSERT_HEAD(&cm->filters, filter, entries);
	return 0;

out_err:
	free(filter);
	return EINVAL;
}

void stats_add_cap(struct capmon *cm, struct log_entry *entry)
{
	struct process_stats *ps;

	if (cm->summary == SUMMARY_NONE)
		return;

	for (ps = cm->process_stats.lh_first; ps != NULL; ps = ps->entries.le_next) {
		if (cm->summary == SUMMARY_COMM && strcmp(entry->comm, ps->comm) == 0) {
			set_bit(entry->cap, ps->capabilities);
			return;
		} else if (cm->summary == SUMMARY_PID && entry->pid == ps->pid) {
			set_bit(entry->cap, ps->capabilities);
			return;
		}
	}

	/* New process comm/pid */

	/* TODO: propagate error */
	ps = calloc(1, sizeof(struct process_stats));
	if (!ps) {
		return;
	}

	if (cm->summary == SUMMARY_PID)
		ps->pid = entry->pid;

	strncpy(ps->comm, entry->comm, COMM_NAME_LEN);

	set_bit(entry->cap, ps->capabilities);
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
	print_probes(cm);
	print_filters(cm);

	printf("\n--------------\n");
}

int capmon_init(struct capmon *cm)
{
	struct probe *p;

	LIST_INIT(&cm->available_probes);
	LIST_INIT(&cm->selected_probes);
	LIST_INIT(&cm->filters);
	LIST_INIT(&cm->process_stats);

	/* Add available probes */
	p = init_probe_entry("capmon_all", "cap_capable", 3);
	if (!p)
		return ENOMEM;
	LIST_INSERT_HEAD(&cm->available_probes, p, entries);

	p = init_probe_entry("capmon_inode", "capable_wrt_inode_uidgid", 3);
	if (!p)
		return ENOMEM;
	LIST_INSERT_HEAD(&cm->available_probes, p, entries);

	p = init_probe_entry("capmon_ns", "ns_capable", 2);
	if (!p)
		return ENOMEM;
	LIST_INSERT_HEAD(&cm->available_probes, p, entries);

	cm->summary = SUMMARY_NONE;
	cm->in_background = false;

	return 0;
}

void capmon_destroy(struct capmon *cm)
{
	struct probe *p;
	struct filter *f;
	struct process_stats *ps;

	while (cm->selected_probes.lh_first != NULL) {
		p = cm->selected_probes.lh_first;
		LIST_REMOVE(cm->selected_probes.lh_first, entries);
		free(p);
	}

	while (cm->available_probes.lh_first != NULL) {
		p = cm->available_probes.lh_first;
		LIST_REMOVE(cm->available_probes.lh_first, entries);
		free(p);
	}

	while (cm->filters.lh_first != NULL) {
		f = cm->filters.lh_first;
		LIST_REMOVE(cm->filters.lh_first, entries);
		free(f);
	}

	while (cm->process_stats.lh_first != NULL) {
		ps = cm->process_stats.lh_first;
		LIST_REMOVE(cm->process_stats.lh_first, entries);
		free(ps);
	}
}
