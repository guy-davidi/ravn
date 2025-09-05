/* SPDX-License-Identifier: GPL-2.0 */
#include "compat/linux/types.h"
#include "compat/compat.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "core_network.h"

char LICENSE[] SEC("license") = "GPL";

/* Network monitoring ring buffer */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16MB ring buffer
} network_events SEC(".maps");

/* Simplified network monitoring - avoiding complex memory access */

/* Monitor network connections - simplified */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
	struct network_event *e;
	__u64 current_time = bpf_ktime_get_ns();
	
	__u32 pid = bpf_get_current_pid_tgid() & 0xffffffff;
	if (pid == 0) return 0;
	
	e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e) return 0;
	
	e->event_type = NET_CONNECT;
	e->timestamp_ns = current_time;
	// No severity field in network_event
	
	e->pid = pid;
	e->tgid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->gid = (__u32)(bpf_get_current_uid_gid() >> 32);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	
	/* Simplified - just report any connect attempt */
	e->dport = 0; // Unknown port due to verifier restrictions
	e->bytes = 0;
	e->protocol = 1; // TCP
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}

/* Monitor ping attempts - simplified */
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_ping_attempts(struct trace_event_raw_sys_enter *ctx) {
	struct network_event *e;
	__u64 current_time = bpf_ktime_get_ns();
	__u64 len = ctx->args[2]; // message length
	
	/* Check for small packets that might be ping */
	if (len <= 64) {
		__u32 pid = bpf_get_current_pid_tgid() & 0xffffffff;
		if (pid == 0) return 0;
		
		e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
		if (!e) return 0;
		
		e->event_type = NET_SEND;
		e->timestamp_ns = current_time;
		
		e->pid = pid;
		e->tgid = bpf_get_current_pid_tgid() >> 32;
		e->uid = (__u32)bpf_get_current_uid_gid();
		e->gid = (__u32)(bpf_get_current_uid_gid() >> 32);
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		
		e->bytes = len;
		e->protocol = 2; // UDP
		bpf_ringbuf_submit(e, 0);
	}
	
	return 0;
}

/* Socket monitoring handled by update-checker.bpf.c - removed duplicate */