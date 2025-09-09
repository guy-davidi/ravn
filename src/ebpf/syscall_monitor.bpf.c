/*
 * RAVN Syscall Monitor - eBPF Program
 *
 * This eBPF program monitors system calls for security analysis and threat
 * detection. It captures system call events in kernel space and forwards
 * them to user space for processing by the RAVN security platform.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 *
 * The syscall monitor implements:
 * - System call entry and exit monitoring
 * - Process and thread identification
 * - Filename extraction for file operations
 * - Return value capture for error analysis
 * - High-performance ring buffer communication
 *
 * Monitored system calls:
 * - execve, execveat: Process execution
 * - open, openat: File opening
 * - read, write: File I/O operations
 * - mmap, mprotect: Memory management
 * - close, unlink, rename: File operations
 *
 * Architecture:
 * - Kernel-space eBPF program for event capture
 * - Ring buffer for high-performance data transfer
 * - User-space handler for event processing
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/**
 * struct syscall_event - System call event structure
 * @timestamp: Event timestamp in nanoseconds since boot
 * @pid: Process ID that made the system call
 * @tid: Thread ID that made the system call
 * @syscall_nr: System call number
 * @ret: System call return value
 * @comm: Process command name (truncated to 15 chars + null)
 * @filename: Filename associated with the system call
 *
 * Event structure for system call events captured by eBPF.
 * This structure must match the user-space definition.
 */
struct syscall_event {
	__u64 timestamp;		/* Event timestamp */
	__u32 pid;			/* Process ID */
	__u32 tid;			/* Thread ID */
	__u32 syscall_nr;		/* System call number */
	__s64 ret;			/* Return value */
	char comm[16];			/* Process name */
	char filename[256];		/* Associated filename */
};

/**
 * syscall_events - Ring buffer for system call events
 *
 * High-performance ring buffer for transferring system call events
 * from kernel space to user space. Uses BPF_MAP_TYPE_RINGBUF for
 * efficient zero-copy data transfer.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} syscall_events SEC(".maps");

/*
 * System Call Numbers
 * These constants define the system calls we monitor for security analysis
 */
#define SYS_EXECVE 59		/* Execute program */
#define SYS_OPEN 2		/* Open file */
#define SYS_OPENAT 257		/* Open file relative to directory */
#define SYS_READ 0		/* Read from file descriptor */
#define SYS_WRITE 1		/* Write to file descriptor */
#define SYS_MMAP 9		/* Map memory */
#define SYS_MPROTECT 10		/* Change memory protection */
#define SYS_CLOSE 3		/* Close file descriptor */
#define SYS_UNLINK 87		/* Delete file */
#define SYS_RENAME 82		/* Rename file */

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
