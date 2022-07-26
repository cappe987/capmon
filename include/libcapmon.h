
#ifndef _LIBCAP_LIBCAPMON_H
#define _LIBCAP_LIBCAPMON_H

#include <sys/queue.h>

#define ERR(str, ...) fprintf(stderr, "Error: "str, ##__VA_ARGS__)
#define UNUSED(x) (void)(x)
#define NAME_LEN 50
#define COMM_NAME_LEN 16
#define CAP_NAME_LEN 22

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
		char comm[COMM_NAME_LEN];
	};
};

struct capmon {
	LIST_HEAD(available_probes, probe) available_probes;
	LIST_HEAD(selected_probes, probe) selected_probes;
	LIST_HEAD(filters, filter) filters;
	enum summary_mode summary;
	//struct available_probes *headp2;
	//struct selected_probes *headp1;
};

int probe_select(struct capmon *cm, char *name);
int filter_create(struct capmon *cm, enum filtertypes type, char *optarg);
void capmon_print(struct capmon *cm);
int capmon_init(struct capmon *cm);
void capmon_destroy(struct capmon *cm);

#endif /* _LIBCAP_LIBCAPMON_H */
