// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "kprobes.h"
#include "debug.h"

#define BUFLEN 150


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

	DBG("SENDING COMMAND: %s to %s\n", cmd, filename);
	DBG("Error: %s\n", strerror(errno));
	if (!f)
		return errno;
	fprintf(f, "%s\n", cmd);
	fclose(f);
	DBG("SENT COMMAND\n");
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
		DBG("Creating %s\n", p->name);
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
		DBG("Enabling %s\n", p->name);
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
		DBG("Disabling %s\n", p->name);
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
		DBG("Destroying %s\n", p->name);
		snprintf(cmd, BUFLEN, "-:%s\n", p->name);
		err = send_command(KPROBE_EVENTS, cmd, true);
		if (err)
			fprintf(stderr, "Unable to destroy kprobe \"%s\"\n", p->name);
	}
}
