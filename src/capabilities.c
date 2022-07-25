
#include <linux/capability.h>

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

