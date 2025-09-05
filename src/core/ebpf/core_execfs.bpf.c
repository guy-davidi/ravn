// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025

#include "compat/linux/types.h"
#include "compat/compat.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "core_execfs.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16MB ring buffer
} events SEC(".maps");

static __always_inline __u64 get_time_ns(void) {
	return bpf_ktime_get_ns();
}

static __always_inline void fill_ids(struct event *e) {
	__u32 pid = bpf_get_current_pid_tgid() & 0xffffffff;
	// Skip events from ravn itself to reduce noise
	if (pid == 0) return; // Skip if we can't get PID
	
	e->pid = pid;
	e->tgid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->gid = (__u32)(bpf_get_current_uid_gid() >> 32);
	e->ppid = 0; // CO-RE task_struct read disabled for portability in MVP
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline int submit_filename_event(enum event_type type, const char *filename) {
	struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->timestamp_ns = get_time_ns();
	e->event_type = type;
	fill_ids(e);
	if (filename) {
		bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Trace execve sys_enter
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
	const char *filename = (const char *)ctx->args[0];
	return submit_filename_event(EV_EXEC, filename);
}

// Trace openat sys_enter
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
	const char *filename = (const char *)ctx->args[1];
	return submit_filename_event(EV_OPEN, filename);
}


