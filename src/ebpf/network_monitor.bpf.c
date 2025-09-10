/*
 * RAVN Network Monitor - Simplified eBPF Program for WSL2
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// Event structure for network events
struct network_event {
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	__u32 event_type;
	__u16 family;
	__u16 type;
	__u16 protocol;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u32 bytes_sent;
	__u32 bytes_received;
	char comm[16];
};

// Ring buffer map
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

// Rate-limited network event generation
static __u64 last_event_time = 0;
static const __u64 EVENT_INTERVAL_NS = 1000000000; // 1 second

// Simple test function that generates network events (rate limited)
SEC("kprobe/tcp_sendmsg")
int trace_network_send(struct pt_regs* ctx __attribute__((unused))) {
	__u64 current_time = bpf_ktime_get_ns();

	// Rate limit: only generate one event per second
	if (current_time - last_event_time < EVENT_INTERVAL_NS) {
		return 0;
	}
	last_event_time = current_time;

	struct network_event* event;

	// Reserve space in ring buffer
	event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	// Fill event data
	event->timestamp = current_time;
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	event->event_type = 1;	    // Network send
	event->family = 2;	    // AF_INET
	event->type = 1;	    // SOCK_STREAM
	event->protocol = 6;	    // TCP
	event->src_ip = 0x7F000001; // 127.0.0.1
	event->dst_ip = 0x7F000001; // 127.0.0.1
	event->src_port = 12345;
	event->dst_port = 80;
	event->bytes_sent = 1024;
	event->bytes_received = 0;

	// Get process name
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// Submit event
	bpf_ringbuf_submit(event, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";