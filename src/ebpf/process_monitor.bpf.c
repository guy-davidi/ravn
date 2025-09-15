/*
 * RAVN Process Monitor - eBPF Program (Simplified)
 *
 * This eBPF program provides basic process monitoring capabilities.
 * Enhanced functionality will be added in future iterations.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ravn_events.h"

/*
 * Ring buffer for process events
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} process_events SEC(".maps");

/*
 * Helper function to get current timestamp
 */
static __always_inline __u64 get_timestamp(void) {
	return bpf_ktime_get_ns();
}

/*
 * Helper function to get process name
 */
static __always_inline void get_process_name(char* comm) {
	bpf_get_current_comm(comm, 16);
}

/*
 * Helper function to send process event
 */
static __always_inline int send_process_event(__u32 event_type, __u32 ppid, 
					     __u32 uid, __u32 gid, __s64 ret) {
	struct process_event* event = bpf_ringbuf_reserve(&process_events, 
							 sizeof(struct process_event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp = get_timestamp();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	event->ppid = ppid;
	event->event_type = event_type;
	event->uid = uid;
	event->gid = gid;
	event->euid = uid;
	event->egid = gid;
	event->suid = uid;
	event->sgid = gid;
	event->capabilities = 0;
	event->ret = ret;

	get_process_name(event->comm);
	
	/* Initialize arrays to zero for now - simplified */
	event->parent_comm[0] = 0;
	event->filename[0] = 0;
	event->working_dir[0] = 0;
	event->command_line[0] = 0;
	event->stack_trace[0] = 0;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

/*
 * Monitor process execution (simplified)
 */
SEC("kprobe/__x64_sys_execve")
int trace_execve(struct pt_regs* ctx) {
	send_process_event(PROC_EVENT_EXEC, 0, 0, 0, 0);
	return 0;
}

/*
 * Monitor process exit (simplified)
 */
SEC("kprobe/__x64_sys_exit")
int trace_exit(struct pt_regs* ctx) {
	send_process_event(PROC_EVENT_EXIT, 0, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";