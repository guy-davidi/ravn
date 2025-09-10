/*
 * RAVN File Monitor - Simplified eBPF Program for WSL2
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// Event structure for file events (must match user-space structure)
struct file_event {
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 event_type;
	__u32 fd;
	__u32 flags;
	__u32 mode;
	__u64 size;
	__s64 ret;
	char comm[16];
	char filename[256];
	char target_filename[256];
};

// Ring buffer map
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

// Simple test function that generates file events
SEC("kprobe/vfs_open")
int trace_file_event(struct pt_regs* ctx) {
	struct file_event* event;

	// Reserve space in ring buffer
	event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	// Fill event data
	event->timestamp = bpf_ktime_get_ns();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	event->event_type = 1; // File open
	event->fd = 0;	       // File descriptor (will be set by kernel)
	event->flags = 0;      // O_RDONLY
	event->mode = 0644;    // Default mode
	event->size = 0;       // No data size for open
	event->ret = 0;	       // Return value (will be set by kernel)

	// Get process name
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// Simple filename
	__builtin_memcpy(event->filename, "/tmp/ravn_test", 14);

	// Initialize target filename (empty for open operations)
	__builtin_memset(event->target_filename, 0, sizeof(event->target_filename));

	// Submit event
	bpf_ringbuf_submit(event, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";