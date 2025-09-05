/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SYSTEM_H
#define __SYSTEM_H

#include "compat/linux/types.h"

enum system_event_type {
	SYS_SETUID = 1,
	SYS_SETGID = 2,
	SYS_PTRACE = 3,
	SYS_CAPSET = 4,
	SYS_SCHED_SWITCH = 5,
};

struct system_event {
	__u64 timestamp_ns;
	__u32 event_type;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 gid;
	char comm[16];
	__u32 target_pid; // For ptrace
	__u32 new_uid;    // For setuid
	__u32 new_gid;    // For setgid
	__u32 cpu_id;
	__u32 priority;
};

#endif /* __SYSTEM_H */
