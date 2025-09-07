// RAVN File I/O Monitor eBPF Program
// Monitors file operations for security analysis

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Event structure for file events
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

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

// File event types
#define FILE_EVENT_OPEN 1
#define FILE_EVENT_READ 2
#define FILE_EVENT_WRITE 3
#define FILE_EVENT_CLOSE 4
#define FILE_EVENT_UNLINK 5
#define FILE_EVENT_RENAME 6
#define FILE_EVENT_MKDIR 7
#define FILE_EVENT_RMDIR 8
#define FILE_EVENT_CHMOD 9
#define FILE_EVENT_CHOWN 10

// Syscall numbers
#define SYS_OPEN 2
#define SYS_OPENAT 257
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_UNLINK 87
#define SYS_RENAME 82
#define SYS_MKDIR 83
#define SYS_RMDIR 84
#define SYS_CHMOD 90
#define SYS_CHOWN 92

// File access flags
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 64
#define O_EXCL 128
#define O_TRUNC 512
#define O_APPEND 1024

// Helper function to get filename from syscall arguments
static int get_filename_from_args(struct pt_regs *ctx, char *filename, int syscall_nr) {
    const char *pathname = NULL;
    
    switch (syscall_nr) {
        case SYS_OPEN:
            pathname = (const char *)PT_REGS_PARM1(ctx);
            break;
        case SYS_OPENAT:
            pathname = (const char *)PT_REGS_PARM2(ctx);
            break;
        case SYS_UNLINK:
        case SYS_RENAME:
        case SYS_MKDIR:
        case SYS_RMDIR:
        case SYS_CHMOD:
        case SYS_CHOWN:
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

// Trace open syscall
SEC("tp/syscalls/sys_enter_open")
int trace_open_enter(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *pathname = (const char *)PT_REGS_PARM1(ctx);
    __u32 flags = (__u32)PT_REGS_PARM2(ctx);
    __u32 mode = (__u32)PT_REGS_PARM3(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = FILE_EVENT_OPEN;
    event->flags = flags;
    event->mode = mode;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get filename
    get_filename_from_args((struct pt_regs *)ctx, event->filename, SYS_OPEN);
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace openat syscall
SEC("tp/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    __u32 flags = (__u32)PT_REGS_PARM3(ctx);
    __u32 mode = (__u32)PT_REGS_PARM4(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = FILE_EVENT_OPEN;
    event->flags = flags;
    event->mode = mode;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get filename
    get_filename_from_args((struct pt_regs *)ctx, event->filename, SYS_OPENAT);
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace read syscall
SEC("tp/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    __u32 fd = (__u32)PT_REGS_PARM1(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = FILE_EVENT_READ;
    event->fd = fd;
    event->size = count;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace write syscall
SEC("tp/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    __u32 fd = (__u32)PT_REGS_PARM1(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = FILE_EVENT_WRITE;
    event->fd = fd;
    event->size = count;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace close syscall
SEC("tp/syscalls/sys_enter_close")
int trace_close_enter(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    __u32 fd = (__u32)PT_REGS_PARM1(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = FILE_EVENT_CLOSE;
    event->fd = fd;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace unlink syscall
SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink_enter(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *pathname = (const char *)PT_REGS_PARM1(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = FILE_EVENT_UNLINK;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get filename
    get_filename_from_args((struct pt_regs *)ctx, event->filename, SYS_UNLINK);
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace rename syscall
SEC("tp/syscalls/sys_enter_rename")
int trace_rename_enter(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    const char *oldpath = (const char *)PT_REGS_PARM1(ctx);
    const char *newpath = (const char *)PT_REGS_PARM2(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = FILE_EVENT_RENAME;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get filenames
    get_filename_from_args((struct pt_regs *)ctx, event->filename, SYS_RENAME);
    if (newpath) {
        bpf_probe_read_user_str(event->target_filename, sizeof(event->target_filename), newpath);
    }
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
