/*
 * RAVN Network Monitor - eBPF Program
 *
 * This eBPF program monitors network operations for security analysis and threat
 * detection. It captures network-related system calls and socket operations in
 * kernel space and forwards them to user space for processing by the RAVN
 * security platform.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 *
 * The network monitor implements:
 * - Socket creation and management monitoring
 * - Network connection tracking
 * - Data transfer monitoring
 * - Protocol and address family detection
 * - High-performance ring buffer communication
 *
 * Monitored network operations:
 * - connect, bind, listen, accept: Connection management
 * - send, recv: Data transfer operations
 * - socket: Socket creation
 * - getsockopt, setsockopt: Socket configuration
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

// Event structure for network events
struct network_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 event_type;
    __u32 family;
    __u32 type;
    __u32 protocol;
    __u32 local_port;
    __u32 remote_port;
    __u32 local_ip;
    __u32 remote_ip;
    __s64 ret;
    char comm[16];
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

// Network event types
#define NET_EVENT_CONNECT 1
#define NET_EVENT_BIND 2
#define NET_EVENT_LISTEN 3
#define NET_EVENT_ACCEPT 4
#define NET_EVENT_SEND 5
#define NET_EVENT_RECV 6

// Socket family constants
#define AF_INET 2
#define AF_INET6 10

// Socket type constants
#define SOCK_STREAM 1
#define SOCK_DGRAM 2

// Protocol constants
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Helper function to extract IP and port from sockaddr
static int extract_sockaddr_info(struct sockaddr *addr, __u32 *ip, __u32 *port) {
    struct sockaddr_in *sin;
    
    if (!addr) {
        return 0;
    }
    
    sin = (struct sockaddr_in *)addr;
    if (sin->sin_family == AF_INET) {
        *ip = bpf_ntohl(sin->sin_addr.s_addr);
        *port = bpf_ntohs(sin->sin_port);
        return 1;
    }
    
    return 0;
}

// Trace connect syscall
SEC("tp/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    struct sockaddr *addr;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = NET_EVENT_CONNECT;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get socket address
    addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    extract_sockaddr_info(addr, &event->remote_ip, &event->remote_port);
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace bind syscall
SEC("tp/syscalls/sys_enter_bind")
int trace_bind_enter(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    struct sockaddr *addr;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = NET_EVENT_BIND;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Get socket address
    addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    extract_sockaddr_info(addr, &event->local_ip, &event->local_port);
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace listen syscall
SEC("tp/syscalls/sys_enter_listen")
int trace_listen_enter(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = NET_EVENT_LISTEN;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace accept syscall
SEC("tp/syscalls/sys_enter_accept")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = NET_EVENT_ACCEPT;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace send syscall
SEC("tp/syscalls/sys_enter_sendto")
int trace_send_enter(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = NET_EVENT_SEND;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Trace recv syscall
SEC("tp/syscalls/sys_enter_recvfrom")
int trace_recv_enter(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = NET_EVENT_RECV;
    event->ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
