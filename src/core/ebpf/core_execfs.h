/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EB_GUARD_EXECFS_H
#define EB_GUARD_EXECFS_H

#include "compat/linux/types.h"

enum event_type {
	EV_EXEC = 1,
	EV_OPEN = 2,
	EV_CONNECT = 3,
	EV_ACCEPT = 4,
	EV_SETUID = 5,
	EV_PTRACE = 6,
};

#define MAX_COMM 16
#define MAX_FILENAME 256

struct event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 event_type;
	char comm[MAX_COMM];
	char filename[MAX_FILENAME];
};

#endif /* EB_GUARD_EXECFS_H */


