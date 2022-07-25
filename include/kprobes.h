
#include <stdbool.h>
#include <sys/queue.h>

#define KPROBES_DIR "/sys/kernel/debug/tracing"
#define KPROBE_EVENTS KPROBES_DIR"/kprobe_events"
#define KPROBES_LOG KPROBES_DIR"/trace"
#define NAME_LEN 50

struct probes {
	LIST_ENTRY(probes) entries;
	char name[NAME_LEN];
	char function[NAME_LEN];
	/* Index of the argument `int capability`, index starts at 1 */
	int cap_argnum;
};



struct capmon {
	LIST_HEAD(available_probes, probes) available_probes;
	LIST_HEAD(selected_probes, probes) selected_probes;
	struct available_probes *headp2;
	struct selected_probes *headp1;
};




int init_probelists(struct capmon *cm);
void destroy_probelists(struct capmon *cm);
int select_probe(struct capmon *cm, char *name);

bool kprobe_exists(struct probes *p);
int kprobes_create(struct capmon *cm);
int kprobes_enable(struct capmon *cm);
void kprobes_disable(struct capmon *cm);
void kprobes_destroy(struct capmon *cm);
