
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/capability.h>

#define PROBE "capdump"
#define ROOTPATH "/sys/kernel/debug/tracing"
#define EVENTS ROOTPATH"/kprobe_events"
#define PROBE_ENA ROOTPATH"/events/kprobes/"PROBE"/enable"
#define LOG ROOTPATH"/trace"

#define BUFSIZE 1000
#define COMM_NAME_LEN 16
#define CAP_NAME_LEN 22

const char *cap_to_str(__u16 cap)
{
	switch (cap) {
		case CAP_CHOWN: 		return "CAP_CHOWN";
		case CAP_DAC_OVERRIDE: 		return "CAP_DAC_OVERRIDE";
		case CAP_DAC_READ_SEARCH: 	return "CAP_DAC_READ_SEARCH";
		case CAP_FOWNER: 		return "CAP_FOWNER";
		case CAP_FSETID: 		return "CAP_FSETID";
		case CAP_KILL: 			return "CAP_KILL";
		case CAP_SETGID: 		return "CAP_SETGID";
		case CAP_SETUID: 		return "CAP_SETUID";
		case CAP_SETPCAP: 		return "CAP_SETPCAP";
		case CAP_LINUX_IMMUTABLE: 	return "CAP_LINUX_IMMUTABLE";
		case CAP_NET_BIND_SERVICE: 	return "CAP_NET_BIND_SERVICE";
		case CAP_NET_BROADCAST: 	return "CAP_NET_BROADCAST";
		case CAP_NET_ADMIN: 		return "CAP_NET_ADMIN";
		case CAP_NET_RAW: 		return "CAP_NET_RAW";
		case CAP_IPC_LOCK: 		return "CAP_IPC_LOCK";
		case CAP_IPC_OWNER: 		return "CAP_IPC_OWNER";
		case CAP_SYS_MODULE: 		return "CAP_SYS_MODULE";
		case CAP_SYS_RAWIO: 		return "CAP_SYS_RAWIO";
		case CAP_SYS_CHROOT: 		return "CAP_SYS_CHROOT";
		case CAP_SYS_PTRACE: 		return "CAP_SYS_PTRACE";
		case CAP_SYS_PACCT: 		return "CAP_SYS_PACCT";
		case CAP_SYS_ADMIN: 		return "CAP_SYS_ADMIN";
		case CAP_SYS_BOOT: 		return "CAP_SYS_BOOT";
		case CAP_SYS_NICE: 		return "CAP_SYS_NICE";
		case CAP_SYS_RESOURCE: 		return "CAP_SYS_RESOURCE";
		case CAP_SYS_TIME: 		return "CAP_SYS_TIME";
		case CAP_SYS_TTY_CONFIG: 	return "CAP_SYS_TTY_CONFIG";
		case CAP_MKNOD: 		return "CAP_MKNOD";
		case CAP_LEASE: 		return "CAP_LEASE";
		case CAP_AUDIT_WRITE: 		return "CAP_AUDIT_WRITE";
		case CAP_AUDIT_CONTROL: 	return "CAP_AUDIT_CONTROL";
		case CAP_SETFCAP: 		return "CAP_SETFCAP";
		case CAP_MAC_OVERRIDE: 		return "CAP_MAC_OVERRIDE";
		case CAP_MAC_ADMIN: 		return "CAP_MAC_ADMIN";
		case CAP_SYSLOG: 		return "CAP_SYSLOG";
		case CAP_WAKE_ALARM: 		return "CAP_WAKE_ALARM";
		case CAP_BLOCK_SUSPEND: 	return "CAP_BLOCK_SUSPEND";
		case CAP_AUDIT_READ: 		return "CAP_AUDIT_READ";
		case CAP_PERFMON: 		return "CAP_PERFMON";
		case CAP_BPF: 			return "CAP_BPF";
		case CAP_CHECKPOINT_RESTORE: 	return "CAP_CHECKPOINT_RESTORE";
		default: 			return "UNKNOWN CAP";
	}
}


int send_command(char *filename, char *string)
{
	FILE *f = fopen(filename, "w");
	printf("SENDING COMMAND\n");
	if (!f)
		return EBUSY;
	fprintf(f, "%s\n", string);
	fclose(f);
	printf("SENT COMMAND\n");
	return 0;
}

int probe_create()
{
	/*int err = send_command(EVENTS, "p:"PROBE" ns_capable cap=$arg2 comm=$comm\n");*/
	int err = send_command(EVENTS, "p:"PROBE" cap_capable cap=$arg3 comm=$comm\n");
	printf("%s\n", strerror(err));

	return err;
}

int probe_enable()
{
	return send_command(PROBE_ENA, "1");
}

int probe_disable()
{

	return send_command(PROBE_ENA, "0");
}

int probe_delete()
{
	/*system("echo -:capdump >> /sys/kernel/debug/tracing/kprobe_events");*/
	FILE *f = fopen(EVENTS, "w");
	if (!f)
		return EBUSY;
	fprintf(f, "-:%s\n", PROBE);
	fclose(f);
	return 0;
}

struct log_entry {
	char comm[COMM_NAME_LEN];
	__u32 pid;
	__u64 time;
	__u16 cap;
};

int parse_line(char *line, int len, struct log_entry *entry)
{
	char *cap;
	char *comm;
	int comm_len;

	cap = strstr(line, "cap=");
	if (!cap) {
		return EINVAL;
	}

	cap += 6;
	entry->cap = strtol(cap, NULL, 16);
	/*printf("CAP: %s\n", cap_to_str(entry->cap));*/

	comm = strstr(cap, "comm=");
	if (!comm) {
		return EINVAL;
	}

	comm += 6;
	for (comm_len = 0;
	     comm[comm_len] != '"' && comm_len < COMM_NAME_LEN;
	     comm_len++) { }

	strncpy(entry->comm, comm, comm_len);
	entry->comm[comm_len] = '\0';

	/*printf("COMM: %s\n", entry->comm);*/


	return 0;
}

void print_log_entry(struct log_entry *entry)
{
	printf("Process=%-16s Cap=%-22s\n", entry->comm, cap_to_str(entry->cap));
}

int probe_log()
{
	/*system("cat "LOG" | grep "PROBE);*/
	char linebuffer[BUFSIZE];
	struct log_entry entry;
	FILE *logfile;
	int pos, err, counter;
	struct timeval second;
	char ch;

	pos = 0;
	counter = 0;

	logfile = fopen(LOG, "r");
	if (!logfile)
		return errno;

	for (;;) {
		while ((ch = getc(logfile)) != EOF)  {
			/*if (putchar(ch) == EOF)*/
				/*perror("Output error");*/

			linebuffer[pos] = ch;	
			pos++;
			if (ch == '\n') {
				linebuffer[pos] = '\0';
				err = parse_line(linebuffer, pos, &entry);
				if (!err)
					print_log_entry(&entry);
				pos = 0;
				counter++;
			}
		}

		if (ferror(logfile)) {
			printf("Input error: %s", strerror(errno));
			return errno;
		}
		(void)fflush(stdout);
		/*sleep(1); // Or use select*/
		second.tv_sec = 0;
		second.tv_usec = 100000;
		if (select(0, NULL, NULL, NULL, &second) == -1)
			printf("Select: %s", strerror(errno));
		clearerr(logfile);
	}

	fclose(logfile);
}

int main(int argc, char **argv)
{
	int err;
	struct log_entry entry;


	/*char *test = "         chronyd-879     [001] ..... 22849.242966: capdump: (cap_capable+0x0/0x70) cap=0x19 comm=\"chronyd\"";*/

	/*parse_line(test, strlen(test), &entry);*/
	/*return 0;*/
	
	if (strcmp(argv[1], "ena") == 0) {
		printf("Enable %s\n", PROBE);

		err = probe_create();
		if (err)
			// Error if probe already exists?
			return err;
		printf("Created\n");

		err = probe_enable();
		if (err) {
			probe_delete();
			return err;
		}
		printf("Enabled\n");

	} else if (strcmp(argv[1], "dis") == 0) {
		printf("Disable\n");
		err = probe_disable();
		if (err)
			printf("Error: %s\n", strerror(err));

		printf("Disabled\n");
		err = probe_delete();
		if (err) {
			printf("Error: %s\n", strerror(err));
			return err;
		}
		printf("Deleted\n");
		return 0;

	} else if (strcmp(argv[1], "log") == 0) {
		probe_log();

	} else if (strcmp(argv[1], "clear") == 0) {
		system("echo 0 > /sys/kernel/debug/tracing/trace");

	} else {
		printf("Invalid argument\n");
	}

	return 0;
}
