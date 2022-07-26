
#include <string.h>
#include <linux/capability.h>
#include <errno.h>


#include "capabilities.h"

const char *cap_to_str(int cap)
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

int str_to_cap(char *cap)
{
	if (strcmp(cap, "CAP_CHOWN"             ) == 0) return CAP_CHOWN;
	if (strcmp(cap, "CAP_DAC_OVERRIDE"      ) == 0) return CAP_DAC_OVERRIDE;
	if (strcmp(cap, "CAP_DAC_READ_SEARCH"   ) == 0) return CAP_DAC_READ_SEARCH;
	if (strcmp(cap, "CAP_FOWNER"            ) == 0) return CAP_FOWNER;
	if (strcmp(cap, "CAP_FSETID"            ) == 0) return CAP_FSETID;
	if (strcmp(cap, "CAP_KILL"              ) == 0) return CAP_KILL;
	if (strcmp(cap, "CAP_SETGID"            ) == 0) return CAP_SETGID;
	if (strcmp(cap, "CAP_SETUID"            ) == 0) return CAP_SETUID;
	if (strcmp(cap, "CAP_SETPCAP"           ) == 0) return CAP_SETPCAP;
	if (strcmp(cap, "CAP_LINUX_IMMUTABLE"   ) == 0) return CAP_LINUX_IMMUTABLE;
	if (strcmp(cap, "CAP_NET_BIND_SERVICE"  ) == 0) return CAP_NET_BIND_SERVICE;
	if (strcmp(cap, "CAP_NET_BROADCAST"     ) == 0) return CAP_NET_BROADCAST;
	if (strcmp(cap, "CAP_NET_ADMIN"         ) == 0) return CAP_NET_ADMIN;
	if (strcmp(cap, "CAP_NET_RAW"           ) == 0) return CAP_NET_RAW;
	if (strcmp(cap, "CAP_IPC_LOCK"          ) == 0) return CAP_IPC_LOCK;
	if (strcmp(cap, "CAP_IPC_OWNER"         ) == 0) return CAP_IPC_OWNER;
	if (strcmp(cap, "CAP_SYS_MODULE"        ) == 0) return CAP_SYS_MODULE;
	if (strcmp(cap, "CAP_SYS_RAWIO"         ) == 0) return CAP_SYS_RAWIO;
	if (strcmp(cap, "CAP_SYS_CHROOT"        ) == 0) return CAP_SYS_CHROOT;
	if (strcmp(cap, "CAP_SYS_PTRACE"        ) == 0) return CAP_SYS_PTRACE;
	if (strcmp(cap, "CAP_SYS_PACCT"         ) == 0) return CAP_SYS_PACCT;
	if (strcmp(cap, "CAP_SYS_ADMIN"         ) == 0) return CAP_SYS_ADMIN;
	if (strcmp(cap, "CAP_SYS_BOOT"          ) == 0) return CAP_SYS_BOOT;
	if (strcmp(cap, "CAP_SYS_NICE"          ) == 0) return CAP_SYS_NICE;
	if (strcmp(cap, "CAP_SYS_RESOURCE"      ) == 0) return CAP_SYS_RESOURCE;
	if (strcmp(cap, "CAP_SYS_TIME"          ) == 0) return CAP_SYS_TIME;
	if (strcmp(cap, "CAP_SYS_TTY_CONFIG"    ) == 0) return CAP_SYS_TTY_CONFIG;
	if (strcmp(cap, "CAP_MKNOD"             ) == 0) return CAP_MKNOD;
	if (strcmp(cap, "CAP_LEASE"             ) == 0) return CAP_LEASE;
	if (strcmp(cap, "CAP_AUDIT_WRITE"       ) == 0) return CAP_AUDIT_WRITE;
	if (strcmp(cap, "CAP_AUDIT_CONTROL"     ) == 0) return CAP_AUDIT_CONTROL;
	if (strcmp(cap, "CAP_SETFCAP"           ) == 0) return CAP_SETFCAP;
	if (strcmp(cap, "CAP_MAC_OVERRIDE"      ) == 0) return CAP_MAC_OVERRIDE;
	if (strcmp(cap, "CAP_MAC_ADMIN"         ) == 0) return CAP_MAC_ADMIN;
	if (strcmp(cap, "CAP_SYSLOG"            ) == 0) return CAP_SYSLOG;
	if (strcmp(cap, "CAP_WAKE_ALARM"        ) == 0) return CAP_WAKE_ALARM;
	if (strcmp(cap, "CAP_BLOCK_SUSPEND"     ) == 0) return CAP_BLOCK_SUSPEND;
	if (strcmp(cap, "CAP_AUDIT_READ"        ) == 0) return CAP_AUDIT_READ;
	if (strcmp(cap, "CAP_PERFMON"           ) == 0) return CAP_PERFMON;
	if (strcmp(cap, "CAP_BPF"               ) == 0)	return CAP_BPF;
	if (strcmp(cap, "CAP_CHECKPOINT_RESTORE") == 0) return CAP_CHECKPOINT_RESTORE;

	return -EINVAL;
}
