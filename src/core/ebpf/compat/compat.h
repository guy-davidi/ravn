#ifndef EB_GUARD_BPF_COMPAT_H
#define EB_GUARD_BPF_COMPAT_H

#include "linux/types.h"

/* Minimal types for helpers */
typedef __u32 __wsum;

/* Minimal ringbuf map type (from uapi/linux/bpf.h) */
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

/* Socket address family */
#ifndef AF_INET
#define AF_INET 2
#endif

/* Socket structures */
struct in_addr {
	unsigned int s_addr;
};

struct sockaddr {
	unsigned short sa_family;
	char sa_data[14];
};

struct sockaddr_in {
	unsigned short sin_family;
	unsigned short sin_port;
	struct in_addr sin_addr;
	unsigned char sin_zero[8];
};

/* Minimal tracepoint context struct for sys_enter */
struct trace_event_raw_sys_enter {
	unsigned long long _unused;
	long id;
	unsigned long args[6];
};

/* Tracepoint struct for sched_switch */
struct trace_event_raw_sched_switch {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	char prev_comm[16];
	int prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	int next_pid;
	int next_tgid;
	int next_prio;
};

#endif


