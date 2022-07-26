
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "kprobes.h"
#include "debug.h"

#define BUFLEN 100

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

int init_capmon(struct capmon *cm)
{
	struct probe *p;

	LIST_INIT(&cm->available_probes);
	LIST_INIT(&cm->selected_probes);

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

	return 0;
}

void destroy_capmon(struct capmon *cm)
{
	struct probe *p;

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
}

int select_probe(struct capmon *cm, char *name)
{
	struct probe *p, *p_copy;

	for (p = cm->available_probes.lh_first; p != NULL; p = p->entries.le_next) {
		dbg("Selecting... %s?\n", p->name);
		if (strncmp(name, p->name, NAME_LEN) == 0) {
			p_copy = init_probe_entry(p->name, p->function, p->cap_argnum);
			if (!p_copy)
				return ENOMEM;
			LIST_INSERT_HEAD(&cm->selected_probes, p_copy, entries);
			dbg("Found %s\n", p->name);
			return 0;
		}
	}
	fprintf(stderr, "Unable to find capmon probe \"%s\"\n", name);
	return ENOENT;
}

bool kprobe_exists(struct probe *p)
{
	char buffer[BUFLEN];
	bool res = false;
	FILE *f;

	f = fopen(KPROBES_DIR"/kprobe_profile", "r");

	while (fgets(buffer, BUFLEN, f)) {
		if (strstr(buffer, p->name)) {
			res = true;
			break;
		}
	}

	fclose(f);
	return res;
}

static int send_command(char *filename, char *cmd, bool append)
{
	FILE *f;

	if (append)
		/* Using "a" gives "Invalid argument" from `probe_create`. Why?
		 * Using "a+" works. Apparently "a+" is equivalent to shell
		 * redirect append `>>`?
		 */
		f = fopen(filename, "a+");
	else 
		f = fopen(filename, "w");

	dbg("SENDING COMMAND: %s to %s\n", cmd, filename);
	printf("Error: %s\n", strerror(errno));
	if (!f)
		return errno;
	fprintf(f, "%s\n", cmd);
	fclose(f);
	dbg("SENT COMMAND\n");
	return 0;
}

static int kprobe_set_ena(struct probe *p, bool ena)
{
	char path[BUFLEN];
	snprintf(path, BUFLEN, "%s/events/kprobes/%s/enable",
		 KPROBES_DIR,
		 p->name);

	if (ena)
		return send_command(path, "1", false);
	else
		return send_command(path, "0", false);
}

int kprobes_create(struct capmon *cm)
{
	struct probe *p;
	char cmd[BUFLEN];
	int err;

	for (p = cm->selected_probes.lh_first; p != NULL; p = p->entries.le_next) {
		dbg("Creating %s\n", p->name);
		/* Creating multiple probes requires appending to the file */
		snprintf(cmd, BUFLEN, "p:%s %s cap=$arg%d comm=$comm\n",
			 p->name,
			 p->function,
			 p->cap_argnum);
		err = send_command(KPROBE_EVENTS, cmd, true);
		if (err) {
			fprintf(stderr, "Unable to create kprobe \"%s\"\n", p->name);
			return err;
		}
	}
	return 0;
}

int kprobes_enable(struct capmon *cm)
{
	struct probe *p;
	int err;

	for (p = cm->selected_probes.lh_first; p != NULL; p = p->entries.le_next) {
		dbg("Enabling %s\n", p->name);
		/* Creating multiple probes requires appending to the file */
		err = kprobe_set_ena(p, true);
		if (err) {
			fprintf(stderr, "Unable to enable kprobe \"%s\"\n", p->name);
			return err;
		}
	}
	return 0;
}

void kprobes_disable(struct capmon *cm)
{
	struct probe *p;
	int err;

	for (p = cm->selected_probes.lh_first; p != NULL; p = p->entries.le_next) {
		dbg("Disabling %s\n", p->name);
		/* Creating multiple probes requires appending to the file */
		err = kprobe_set_ena(p, false);
		if (err)
			fprintf(stderr, "Unable to disable kprobe \"%s\"\n", p->name);
	}
}

void kprobes_destroy(struct capmon *cm)
{
	struct probe *p;
	char cmd[BUFLEN];
	int err;

	for (p = cm->selected_probes.lh_first; p != NULL; p = p->entries.le_next) {
		dbg("Destroying %s\n", p->name);
		snprintf(cmd, BUFLEN, "-:%s\n", p->name);
		err = send_command(KPROBE_EVENTS, cmd, true);
		if (err)
			fprintf(stderr, "Unable to destroy kprobe \"%s\"/n", p->name);
	}
}
