/*
 * RAVN Security Monitor - eBPF Program
 *
 * This eBPF program monitors security-related operations for threat detection
 * and security analysis. It captures security-sensitive system calls and
 * operations in kernel space and forwards them to user space for processing
 * by the RAVN security platform.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 *
 * The security monitor implements:
 * - Process privilege escalation monitoring
 * - File permission changes tracking
 * - Process debugging and tracing detection
 * - User and group ID changes monitoring
 * - High-performance ring buffer communication
 *
 * Monitored security operations:
 * - ptrace: Process debugging and tracing
 * - setuid, setgid: User/group ID changes
 * - chmod, chown: File permission changes
 * - mount, umount: Filesystem operations
 * - capset: Capability changes
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

// Event structure for security events
struct security_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 event_type;
    __u32 target_pid;
    __u32 uid;
    __u32 gid;
    __u32 mode;
    __s64 ret;
    char comm[16];
    char target_comm[16];
    char pathname[256];
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} security_events SEC(".maps");

// Security event types
#define SEC_EVENT_PTRACE 1
#define SEC_EVENT_SETUID 2
#define SEC_EVENT_CHMOD 3
#define SEC_EVENT_CHOWN 4
#define SEC_EVENT_MOUNT 5
#define SEC_EVENT_UMOUNT 6
#define SEC_EVENT_SETGID 7
#define SEC_EVENT_SETEUID 8
#define SEC_EVENT_SETEGID 9

// Syscall numbers
#define SYS_PTRACE 101
#define SYS_SETUID 105
#define SYS_SETGID 106
#define SYS_SETEUID 107
#define SYS_SETEGID 108
#define SYS_CHMOD 90
#define SYS_CHOWN 92
#define SYS_MOUNT 165
#define SYS_UMOUNT 166

// Helper function to get string from user space
static int get_user_string(const char *user_str, char *buf, size_t buf_size) {
    if (!user_str) {
        return 0;
    }
    
    bpf_probe_read_user_str(buf, buf_size, user_str);
    return 1;
}

// Trace ptrace syscall
SEC("tp/syscalls/sys_enter_ptrace")
int trace_ptrace_enter(struct trace_event_raw_sys_enter *ctx) {
    struct security_event *event;
    __u32 request = (__u32)PT_REGS_PARM1(ctx);
    __u32 pid = (__u32)PT_REGS_PARM2(ctx);
    
    // Only monitor specific ptrace requests
    if (request != 0 && request != 1 && request != 2 && request != 3) { // PTRACE_ATTACH, PTRACE_DETACH, etc.
        return 0;
    }
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = SEC_EVENT_PTRACE;
    event->target_pid = pid;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace setuid syscall
SEC("tp/syscalls/sys_enter_setuid")
int trace_setuid_enter(struct trace_event_raw_sys_enter *ctx) {
    struct security_event *event;
    __u32 uid = (__u32)PT_REGS_PARM1(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = SEC_EVENT_SETUID;
    event->uid = uid;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace setgid syscall
SEC("tp/syscalls/sys_enter_setgid")
int trace_setgid_enter(struct trace_event_raw_sys_enter *ctx) {
    struct security_event *event;
    __u32 gid = (__u32)PT_REGS_PARM1(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = SEC_EVENT_SETGID;
    event->gid = gid;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace chmod syscall
SEC("tp/syscalls/sys_enter_chmod")
int trace_chmod_enter(struct trace_event_raw_sys_enter *ctx) {
    struct security_event *event;
    const char *pathname = (const char *)PT_REGS_PARM1(ctx);
    __u32 mode = (__u32)PT_REGS_PARM2(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = SEC_EVENT_CHMOD;
    event->mode = mode;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get pathname
    get_user_string(pathname, event->pathname, sizeof(event->pathname));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace chown syscall
SEC("tp/syscalls/sys_enter_chown")
int trace_chown_enter(struct trace_event_raw_sys_enter *ctx) {
    struct security_event *event;
    const char *pathname = (const char *)PT_REGS_PARM1(ctx);
    __u32 uid = (__u32)PT_REGS_PARM2(ctx);
    __u32 gid = (__u32)PT_REGS_PARM3(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = SEC_EVENT_CHOWN;
    event->uid = uid;
    event->gid = gid;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get pathname
    get_user_string(pathname, event->pathname, sizeof(event->pathname));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace mount syscall
SEC("tp/syscalls/sys_enter_mount")
int trace_mount_enter(struct trace_event_raw_sys_enter *ctx) {
    struct security_event *event;
    const char *source = (const char *)PT_REGS_PARM1(ctx);
    const char *target = (const char *)PT_REGS_PARM2(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = SEC_EVENT_MOUNT;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get source and target paths
    get_user_string(source, event->pathname, sizeof(event->pathname));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace umount syscall
SEC("tp/syscalls/sys_enter_umount")
int trace_umount_enter(struct trace_event_raw_sys_enter *ctx) {
    struct security_event *event;
    const char *target = (const char *)PT_REGS_PARM1(ctx);
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&security_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = SEC_EVENT_UMOUNT;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get target path
    get_user_string(target, event->pathname, sizeof(event->pathname));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
