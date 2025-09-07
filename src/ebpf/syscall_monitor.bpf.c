// RAVN Syscall Monitor eBPF Program
// Monitors system calls for security analysis

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Event structure for syscall events
struct syscall_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 syscall_nr;
    __s64 ret;
    char comm[16];
    char filename[256];
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} syscall_events SEC(".maps");

// Syscall numbers we're interested in
#define SYS_EXECVE 59
#define SYS_OPEN 2
#define SYS_OPENAT 257
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_MMAP 9
#define SYS_MPROTECT 10
#define SYS_CLOSE 3
#define SYS_UNLINK 87
#define SYS_RENAME 82

// Helper function to get filename from syscall arguments
static int get_filename_from_args(struct pt_regs *ctx, char *filename, int syscall_nr) {
    const char *pathname = NULL;
    
    switch (syscall_nr) {
        case SYS_OPEN:
        case SYS_OPENAT:
            if (syscall_nr == SYS_OPEN) {
                pathname = (const char *)PT_REGS_PARM1(ctx);
            } else {
                pathname = (const char *)PT_REGS_PARM2(ctx);
            }
            break;
        case SYS_UNLINK:
        case SYS_RENAME:
            pathname = (const char *)PT_REGS_PARM1(ctx);
            break;
        default:
            return 0;
    }
    
    if (pathname) {
        bpf_probe_read_user_str(filename, sizeof(filename), pathname);
        return 1;
    }
    return 0;
}

// Trace syscall entry
SEC("tp/syscalls/sys_enter_*")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event *event;
    __u32 syscall_nr = ctx->id;
    
    // Only monitor specific syscalls
    if (syscall_nr != SYS_EXECVE && syscall_nr != SYS_OPEN && syscall_nr != SYS_OPENAT &&
        syscall_nr != SYS_READ && syscall_nr != SYS_WRITE && syscall_nr != SYS_MMAP &&
        syscall_nr != SYS_MPROTECT && syscall_nr != SYS_CLOSE && syscall_nr != SYS_UNLINK &&
        syscall_nr != SYS_RENAME) {
        return 0;
    }
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->syscall_nr = syscall_nr;
    event->ret = 0; // Will be filled in exit handler
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get filename for relevant syscalls
    get_filename_from_args((struct pt_regs *)ctx, event->filename, syscall_nr);
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace syscall exit
SEC("tp/syscalls/sys_exit_*")
int trace_syscall_exit(struct trace_event_raw_sys_exit *ctx) {
    // For now, we'll handle the return value in the enter handler
    // In a more sophisticated implementation, we could correlate enter/exit events
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
