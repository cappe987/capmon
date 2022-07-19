
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/capability.h>

#include <unistd.h>

#define PROBE_NS "capdump_ns"
#define PROBE_INODE "capdump_inode"
#define ROOTPATH "/sys/kernel/debug/tracing"
#define EVENTS ROOTPATH"/kprobe_events"
#define PROBE_NS_ENA ROOTPATH"/events/kprobes/"PROBE_NS"/enable"
#define PROBE_INODE_ENA ROOTPATH"/events/kprobes/"PROBE_INODE"/enable"
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


int send_command(char *filename, char *string, bool append)
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

	printf("SENDING COMMAND\n");
	if (!f)
		return errno;
	fprintf(f, "%s\n", string);
	fclose(f);
	printf("SENT COMMAND\n");
	return 0;
}

// TODO: For all probe functions, handle errors correctly

int probe_create()
{
	/* Creating multiple probes requires appending to the file */
	int err;
	err = send_command(EVENTS, "p:"PROBE_NS" ns_capable cap=$arg2 comm=$comm\n", false);
	err = send_command(EVENTS, "p:"PROBE_INODE" capable_wrt_inode_uidgid cap=$arg3 comm=$comm\n", true);
	return err;
}

int probe_enable()
{
	send_command(PROBE_NS_ENA, "1", false);
	return send_command(PROBE_INODE_ENA, "1", false);
}

int probe_disable()
{

	send_command(PROBE_NS_ENA, "0", false);
	return send_command(PROBE_INODE_ENA, "0", false);
}

int probe_delete()
{
	send_command(EVENTS, "-:"PROBE_NS, false);
	return send_command(EVENTS, "-:"PROBE_INODE, false);
}

struct log_entry {
	char comm[COMM_NAME_LEN];
	long long time;
	int pid;
	int cap;
};


int parse_entry(char *line, int len, struct log_entry *entry)
{
	char *cap;
	char *comm;
	char *opts;
	int comm_len, err;

	cap = strstr(line, "cap=");
	if (!cap) {
		return EINVAL;
	}

	cap += 6;
	entry->cap = strtol(cap, NULL, 16);

	comm = strstr(line, "comm=");
	if (!comm) {
		return 3;
	}

	comm += 6;
	for (comm_len = 0;
	     comm[comm_len] != '"' && comm_len < COMM_NAME_LEN;
	     comm_len++) { }

	strncpy(entry->comm, comm, comm_len);
	entry->comm[comm_len] = '\0';

	return 0;
}

void print_log_entry(struct log_entry *entry)
{
	printf("Process=%-16s Cap=%-22s\n", entry->comm, cap_to_str(entry->cap));
}

int probe_log()
{
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

	while(true) {
		while ((ch = getc(logfile)) != EOF)  {

			// TODO: Handle idx out of range in buffer?
			linebuffer[pos] = ch;	
			pos++;
			if (ch == '\n') {
				linebuffer[pos] = '\0';
				err = parse_entry(linebuffer, pos, &entry);
				if (!err)
					print_log_entry(&entry);
				pos = 0;
				counter++;
			}
		}

		if (ferror(logfile)) {
			printf("Error: %s", strerror(errno));
			return errno;
		}
		(void)fflush(stdout);
		second.tv_sec = 0;
		second.tv_usec = 100000; /* Sleep 1ms */
		if (select(0, NULL, NULL, NULL, &second) == -1)
			printf("Error: %s", strerror(errno));
		clearerr(logfile);
	}

	fclose(logfile);
}

int main(int argc, char **argv)
{
	int err;
	struct log_entry entry;
	
	if (strcmp(argv[1], "ena") == 0) {
		printf("Enable %s\n", PROBE_NS);

		err = probe_create();
		if (err)
			// TODO: Error if probe already exists?
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
