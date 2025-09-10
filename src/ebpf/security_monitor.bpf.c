/*
 * RAVN Security Monitor - Simplified eBPF Program for WSL2
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// Event structure for security events
struct security_event {
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 event_type;
	__u32 severity;
	__u32 uid;
	__u32 gid;
	char comm[16];
	char message[256];
};

// Ring buffer map
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} security_events SEC(".maps");

// Simple test function that generates security events
SEC("kprobe/security_inode_create")
int trace_security_event(struct pt_regs* ctx __attribute__((unused))) {
	struct security_event* event;

	// Reserve space in ring buffer
	event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	// Fill event data
	event->timestamp = bpf_ktime_get_ns();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	event->event_type = 1; // File creation
	event->severity = 2;   // Medium
	event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	event->gid = bpf_get_current_uid_gid() >> 32;

	// Get process name
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// Simple message
	__builtin_memcpy(event->message, "File creation detected", 22);

	// Submit event
	bpf_ringbuf_submit(event, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";