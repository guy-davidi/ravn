/*
 * RAVN Syscall Monitor - Simplified eBPF Program for WSL2
 *
 * This is a simplified eBPF program that demonstrates ring buffer functionality
 * without complex tracepoint dependencies that may not work in WSL2.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// Event structure for syscall events
struct syscall_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 event_type;
    __u32 syscall_nr;
    __s64 retval;
    char comm[16];
    char filename[256];
};

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} syscall_events SEC(".maps");

// Simple test function that generates events
SEC("kprobe/do_sys_openat2")
int trace_syscall_enter(struct pt_regs *ctx) {
    struct syscall_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = 257; // openat syscall number
    event->syscall_nr = 257; // openat syscall number
    event->retval = 0;
    
    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Simple filename (for demo purposes)
    __builtin_memcpy(event->filename, "/tmp/test", 9);
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char _license[] SEC("license") = "GPL";