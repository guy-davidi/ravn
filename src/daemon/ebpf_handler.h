// RAVN eBPF Handler Header
// Defines structures and functions for eBPF event handling

#ifndef RAVN_EBPF_HANDLER_H
#define RAVN_EBPF_HANDLER_H

#include <stdint.h>
#include <time.h>
#include <bpf/libbpf.h>

// Event structures (must match eBPF programs)
struct syscall_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t tid;
    uint32_t syscall_nr;
    int64_t ret;
    char comm[16];
    char filename[256];
};

struct network_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t tid;
    uint32_t event_type;
    uint32_t family;
    uint32_t type;
    uint32_t protocol;
    uint32_t local_port;
    uint32_t remote_port;
    uint32_t local_ip;
    uint32_t remote_ip;
    int64_t ret;
    char comm[16];
};

struct security_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t tid;
    uint32_t event_type;
    uint32_t target_pid;
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;
    int64_t ret;
    char comm[16];
    char target_comm[16];
    char pathname[256];
};

struct file_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t tid;
    uint32_t event_type;
    uint32_t fd;
    uint32_t flags;
    uint32_t mode;
    uint64_t size;
    int64_t ret;
    char comm[16];
    char filename[256];
    char target_filename[256];
};

// Generic event structure for Redis
struct ravn_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t tid;
    uint32_t event_type;
    uint32_t event_category; // 1=syscall, 2=network, 3=security, 4=file
    char comm[16];
    char data[1024]; // JSON data for specific event details
};

// eBPF handler functions
int init_ebpf_handlers(void);
void cleanup_ebpf_handlers(void);
int ebpf_handler_start_monitoring(void);
void ebpf_handler_stop_monitoring(void);

// Event processing functions
int process_syscall_event(const struct syscall_event *event);
int process_network_event(const struct network_event *event);
int process_security_event(const struct security_event *event);
int process_file_event(const struct file_event *event);

// Utility functions
const char* get_syscall_name(uint32_t syscall_nr);
const char* get_network_event_name(uint32_t event_type);
const char* get_security_event_name(uint32_t event_type);
const char* get_file_event_name(uint32_t event_type);
char* event_to_json(const struct ravn_event *event);

#endif // RAVN_EBPF_HANDLER_H
