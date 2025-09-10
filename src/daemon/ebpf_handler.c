// RAVN eBPF Handler Implementation
// Real eBPF-based system monitoring with ring buffer collection

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ebpf_handler.h"
#include "../utils/logger.h"

// Global variables for eBPF programs and ring buffers
static struct bpf_object *syscall_obj = NULL;
static struct bpf_object *network_obj = NULL;
static struct bpf_object *security_obj = NULL;
static struct bpf_object *file_obj = NULL;

static struct ring_buffer *syscall_rb = NULL;
static struct ring_buffer *network_rb = NULL;
static struct ring_buffer *security_rb = NULL;
static struct ring_buffer *file_rb = NULL;

static int monitoring_active = 0;
static pthread_t monitoring_thread;

// External Redis connection (set by main.c)
extern void* global_redis_conn_ptr;

// Forward declarations for Redis functions
int redis_send_event(void* conn, const struct ravn_event *event);
char* redis_get_last_error(void);

// Ring buffer event handlers
static int handle_syscall_event(void *ctx, void *data, size_t data_sz) {
    const struct syscall_event *event = (const struct syscall_event *)data;
    
    if (data_sz < sizeof(*event)) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Invalid syscall event size: %zu", data_sz);
        return 0;
    }
    
    // Convert to generic ravn_event
    struct ravn_event ravn_event = {
        .timestamp = event->timestamp,
        .pid = event->pid,
        .tid = event->tid,
        .event_type = event->syscall_nr,
        .event_category = 1, // Syscall category
        .comm = {0}
    };
    
    strncpy(ravn_event.comm, event->comm, sizeof(ravn_event.comm) - 1);
    
    // Create JSON data
    snprintf(ravn_event.data, sizeof(ravn_event.data),
        "{\"syscall\":\"%s\",\"filename\":\"%s\",\"ret\":%ld,\"real_ebpf\":true}",
        get_syscall_name(event->syscall_nr), event->filename, event->ret);
    
    // Send to Redis
    if (global_redis_conn_ptr) {
        int result = redis_send_event(global_redis_conn_ptr, &ravn_event);
        if (result != 0) {
            LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to send syscall event: %s", redis_get_last_error());
        }
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "Syscall event: PID=%u, Syscall=%s, File=%s", 
           event->pid, get_syscall_name(event->syscall_nr), event->filename);
    
    return 0;
}

static int handle_network_event(void *ctx, void *data, size_t data_sz) {
    const struct network_event *event = (const struct network_event *)data;
    
    if (data_sz < sizeof(*event)) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Invalid network event size: %zu", data_sz);
        return 0;
    }
    
    // Convert to generic ravn_event
    struct ravn_event ravn_event = {
        .timestamp = event->timestamp,
        .pid = event->pid,
        .tid = event->tid,
        .event_type = event->event_type,
        .event_category = 2, // Network category
        .comm = {0}
    };
    
    strncpy(ravn_event.comm, event->comm, sizeof(ravn_event.comm) - 1);
    
    // Create JSON data
    snprintf(ravn_event.data, sizeof(ravn_event.data),
        "{\"event_type\":\"%s\",\"family\":%u,\"type\":%u,\"protocol\":%u,\"src_ip\":\"%u.%u.%u.%u\",\"dst_ip\":\"%u.%u.%u.%u\",\"src_port\":%u,\"dst_port\":%u,\"bytes_sent\":%u,\"bytes_received\":%u,\"real_ebpf\":true}",
        get_network_event_name(event->event_type), event->family, event->type, 
        event->protocol, 
        (event->src_ip >> 24) & 0xFF, (event->src_ip >> 16) & 0xFF, (event->src_ip >> 8) & 0xFF, event->src_ip & 0xFF,
        (event->dst_ip >> 24) & 0xFF, (event->dst_ip >> 16) & 0xFF, (event->dst_ip >> 8) & 0xFF, event->dst_ip & 0xFF,
        event->src_port, event->dst_port, event->bytes_sent, event->bytes_received);
    
    // Send to Redis
    if (global_redis_conn_ptr) {
        int result = redis_send_event(global_redis_conn_ptr, &ravn_event);
        if (result != 0) {
            LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to send network event: %s", redis_get_last_error());
        }
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "Network event: PID=%u, Type=%s, Src=%u.%u.%u.%u:%u, Dst=%u.%u.%u.%u:%u, Sent=%u, Recv=%u", 
           event->pid, get_network_event_name(event->event_type), 
           (event->src_ip >> 24) & 0xFF, (event->src_ip >> 16) & 0xFF, (event->src_ip >> 8) & 0xFF, event->src_ip & 0xFF, event->src_port,
           (event->dst_ip >> 24) & 0xFF, (event->dst_ip >> 16) & 0xFF, (event->dst_ip >> 8) & 0xFF, event->dst_ip & 0xFF, event->dst_port,
           event->bytes_sent, event->bytes_received);
    
    return 0;
}

static int handle_security_event(void *ctx, void *data, size_t data_sz) {
    const struct security_event *event = (const struct security_event *)data;
    
    if (data_sz < sizeof(*event)) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Invalid security event size: %zu", data_sz);
        return 0;
    }
    
    // Convert to generic ravn_event
    struct ravn_event ravn_event = {
        .timestamp = event->timestamp,
        .pid = event->pid,
        .tid = event->tid,
        .event_type = event->event_type,
        .event_category = 3, // Security category
        .comm = {0}
    };
    
    strncpy(ravn_event.comm, event->comm, sizeof(ravn_event.comm) - 1);
    
    // Create JSON data
    snprintf(ravn_event.data, sizeof(ravn_event.data),
        "{\"event_type\":\"%s\",\"target_pid\":%u,\"uid\":%u,\"gid\":%u,\"mode\":%u,\"pathname\":\"%s\",\"real_ebpf\":true}",
        get_security_event_name(event->event_type), event->target_pid, 
        event->uid, event->gid, event->mode, event->pathname);
    
    // Send to Redis
    if (global_redis_conn_ptr) {
        int result = redis_send_event(global_redis_conn_ptr, &ravn_event);
        if (result != 0) {
            LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to send security event: %s", redis_get_last_error());
        }
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "Security event: PID=%u, Type=%s, Target=%u, Path=%s", 
           event->pid, get_security_event_name(event->event_type), event->target_pid, event->pathname);
    
    return 0;
}

static int handle_file_event(void *ctx, void *data, size_t data_sz) {
    const struct file_event *event = (const struct file_event *)data;
    
    if (data_sz < sizeof(*event)) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Invalid file event size: %zu", data_sz);
        return 0;
    }
    
    // Convert to generic ravn_event
    struct ravn_event ravn_event = {
        .timestamp = event->timestamp,
        .pid = event->pid,
        .tid = event->tid,
        .event_type = event->event_type,
        .event_category = 4, // File category
        .comm = {0}
    };
    
    strncpy(ravn_event.comm, event->comm, sizeof(ravn_event.comm) - 1);
    
    // Create JSON data
    snprintf(ravn_event.data, sizeof(ravn_event.data),
        "{\"event_type\":\"%s\",\"fd\":%u,\"flags\":%u,\"mode\":%u,\"size\":%lu,\"filename\":\"%s\",\"target_filename\":\"%s\",\"real_ebpf\":true}",
        get_file_event_name(event->event_type), event->fd, event->flags, 
        event->mode, event->size, event->filename, event->target_filename);
    
    // Send to Redis
    if (global_redis_conn_ptr) {
        int result = redis_send_event(global_redis_conn_ptr, &ravn_event);
        if (result != 0) {
            LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to send file event: %s", redis_get_last_error());
        }
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "File event: PID=%u, Type=%s, FD=%u, File=%s", 
           event->pid, get_file_event_name(event->event_type), event->fd, event->filename);
    
    return 0;
}

// Ring buffer polling thread
static void* ring_buffer_poll_thread(void *arg) {
    (void)arg;
    
    LOG_INFO_MODULE("eBPF-HANDLER", "Ring buffer polling thread started");
    
    while (monitoring_active) {
        int err;
        
        // Poll all ring buffers with 1 second timeout
        err = ring_buffer__poll(syscall_rb, 1000);
        if (err < 0 && err != -EINTR) {
            LOG_ERROR_MODULE("eBPF-HANDLER", "Error polling syscall ring buffer: %s", strerror(-err));
        }
        
        err = ring_buffer__poll(network_rb, 1000);
        if (err < 0 && err != -EINTR) {
            LOG_ERROR_MODULE("eBPF-HANDLER", "Error polling network ring buffer: %s", strerror(-err));
        }
        
        err = ring_buffer__poll(security_rb, 1000);
        if (err < 0 && err != -EINTR) {
            LOG_ERROR_MODULE("eBPF-HANDLER", "Error polling security ring buffer: %s", strerror(-err));
        }
        
        err = ring_buffer__poll(file_rb, 1000);
        if (err < 0 && err != -EINTR) {
            LOG_ERROR_MODULE("eBPF-HANDLER", "Error polling file ring buffer: %s", strerror(-err));
        }
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "Ring buffer polling thread stopped");
    return NULL;
}

// Load and attach eBPF programs
static int load_ebpf_programs(void) {
    int err;
    
    // Load syscall monitor
    syscall_obj = bpf_object__open_file("artifacts/syscall_monitor.bpf.o", NULL);
    if (libbpf_get_error(syscall_obj)) {
        char err_buf[256];
        libbpf_strerror(libbpf_get_error(syscall_obj), err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to open syscall monitor: %s", err_buf);
        return -1;
    }
    
    err = bpf_object__load(syscall_obj);
    if (err) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to load syscall monitor: %s", err_buf);
        return -1;
    }
    
    // Load network monitor
    network_obj = bpf_object__open_file("artifacts/network_monitor.bpf.o", NULL);
    if (libbpf_get_error(network_obj)) {
        char err_buf[256];
        libbpf_strerror(libbpf_get_error(network_obj), err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to open network monitor: %s", err_buf);
        return -1;
    }
    
    err = bpf_object__load(network_obj);
    if (err) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to load network monitor: %s", err_buf);
        return -1;
    }
    
    // Load security monitor
    security_obj = bpf_object__open_file("artifacts/security_monitor.bpf.o", NULL);
    if (libbpf_get_error(security_obj)) {
        char err_buf[256];
        libbpf_strerror(libbpf_get_error(security_obj), err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to open security monitor: %s", err_buf);
        return -1;
    }
    
    err = bpf_object__load(security_obj);
    if (err) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to load security monitor: %s", err_buf);
        return -1;
    }
    
    // Load file monitor
    file_obj = bpf_object__open_file("artifacts/file_monitor.bpf.o", NULL);
    if (libbpf_get_error(file_obj)) {
        char err_buf[256];
        libbpf_strerror(libbpf_get_error(file_obj), err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to open file monitor: %s", err_buf);
        return -1;
    }
    
    err = bpf_object__load(file_obj);
    if (err) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to load file monitor: %s", err_buf);
        return -1;
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "All eBPF programs loaded successfully");
    return 0;
}

// Attach eBPF programs to kernel hooks
static int attach_ebpf_programs(void) {
    // Attach syscall programs
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, syscall_obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            char err_buf[256];
            libbpf_strerror(libbpf_get_error(link), err_buf, sizeof(err_buf));
            LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to attach program %s: %s", 
                   bpf_program__name(prog), err_buf);
            return -1;
        }
    }
    
    // Attach network programs
    bpf_object__for_each_program(prog, network_obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            char err_buf[256];
            libbpf_strerror(libbpf_get_error(link), err_buf, sizeof(err_buf));
            LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to attach program %s: %s", 
                   bpf_program__name(prog), err_buf);
            return -1;
        }
    }
    
    // Attach security programs
    bpf_object__for_each_program(prog, security_obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            char err_buf[256];
            libbpf_strerror(libbpf_get_error(link), err_buf, sizeof(err_buf));
            LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to attach program %s: %s", 
                   bpf_program__name(prog), err_buf);
            return -1;
        }
    }
    
    // Attach file programs
    bpf_object__for_each_program(prog, file_obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            char err_buf[256];
            libbpf_strerror(libbpf_get_error(link), err_buf, sizeof(err_buf));
            LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to attach program %s: %s", 
                   bpf_program__name(prog), err_buf);
            return -1;
        }
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "All eBPF programs attached successfully");
    return 0;
}

// Create ring buffers
static int create_ring_buffers(void) {
    struct bpf_map *map;
    
    // Create syscall ring buffer
    map = bpf_object__find_map_by_name(syscall_obj, "syscall_events");
    if (!map) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to find syscall_events map");
        return -1;
    }
    
    syscall_rb = ring_buffer__new(bpf_map__fd(map), handle_syscall_event, NULL, NULL);
    if (libbpf_get_error(syscall_rb)) {
        char err_buf[256];
        libbpf_strerror(libbpf_get_error(syscall_rb), err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to create syscall ring buffer: %s", err_buf);
        return -1;
    }
    
    // Create network ring buffer
    map = bpf_object__find_map_by_name(network_obj, "network_events");
    if (!map) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to find network_events map");
        return -1;
    }
    
    network_rb = ring_buffer__new(bpf_map__fd(map), handle_network_event, NULL, NULL);
    if (libbpf_get_error(network_rb)) {
        char err_buf[256];
        libbpf_strerror(libbpf_get_error(network_rb), err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to create network ring buffer: %s", err_buf);
        return -1;
    }
    
    // Create security ring buffer
    map = bpf_object__find_map_by_name(security_obj, "security_events");
    if (!map) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to find security_events map");
        return -1;
    }
    
    security_rb = ring_buffer__new(bpf_map__fd(map), handle_security_event, NULL, NULL);
    if (libbpf_get_error(security_rb)) {
        char err_buf[256];
        libbpf_strerror(libbpf_get_error(security_rb), err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to create security ring buffer: %s", err_buf);
        return -1;
    }
    
    // Create file ring buffer
    map = bpf_object__find_map_by_name(file_obj, "file_events");
    if (!map) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to find file_events map");
        return -1;
    }
    
    file_rb = ring_buffer__new(bpf_map__fd(map), handle_file_event, NULL, NULL);
    if (libbpf_get_error(file_rb)) {
        char err_buf[256];
        libbpf_strerror(libbpf_get_error(file_rb), err_buf, sizeof(err_buf));
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to create file ring buffer: %s", err_buf);
        return -1;
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "All ring buffers created successfully");
    return 0;
}

// Initialize eBPF handlers with real ring buffer monitoring
int init_ebpf_handlers(void) {
    LOG_INFO_MODULE("eBPF-HANDLER", "Initializing real eBPF ring buffer monitoring");
    
    // Load eBPF programs
    if (load_ebpf_programs() != 0) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to load eBPF programs");
        return -1;
    }
    
    // Attach eBPF programs
    if (attach_ebpf_programs() != 0) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to attach eBPF programs");
        return -1;
    }
    
    // Create ring buffers
    if (create_ring_buffers() != 0) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to create ring buffers");
        return -1;
    }
    
    monitoring_active = 1;
    
    // Start ring buffer polling thread
    if (pthread_create(&monitoring_thread, NULL, ring_buffer_poll_thread, NULL) != 0) {
        LOG_ERROR_MODULE("eBPF-HANDLER", "Failed to create ring buffer polling thread");
        return -1;
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "Real eBPF ring buffer monitoring started");
    return 0;
}

// Cleanup eBPF handlers
void cleanup_ebpf_handlers(void) {
    LOG_INFO_MODULE("eBPF-HANDLER", "Stopping eBPF ring buffer monitoring...");
    
    monitoring_active = 0;
    
    // Wait for polling thread to finish
    if (monitoring_thread) {
        pthread_join(monitoring_thread, NULL);
    }
    
    // Cleanup ring buffers
    if (syscall_rb) {
        ring_buffer__free(syscall_rb);
        syscall_rb = NULL;
    }
    
    if (network_rb) {
        ring_buffer__free(network_rb);
        network_rb = NULL;
    }
    
    if (security_rb) {
        ring_buffer__free(security_rb);
        security_rb = NULL;
    }
    
    if (file_rb) {
        ring_buffer__free(file_rb);
        file_rb = NULL;
    }
    
    // Cleanup eBPF objects
    if (syscall_obj) {
        bpf_object__close(syscall_obj);
        syscall_obj = NULL;
    }
    
    if (network_obj) {
        bpf_object__close(network_obj);
        network_obj = NULL;
    }
    
    if (security_obj) {
        bpf_object__close(security_obj);
        security_obj = NULL;
    }
    
    if (file_obj) {
        bpf_object__close(file_obj);
        file_obj = NULL;
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "eBPF ring buffer monitoring stopped and cleaned up");
}

// Start monitoring (simplified for POC)
int ebpf_handler_start_monitoring(void) {
    LOG_INFO_MODULE("eBPF-HANDLER", "eBPF monitoring started (simplified mode)");
    return 0;
}

// Stop monitoring
void ebpf_handler_stop_monitoring(void) {
    LOG_INFO_MODULE("eBPF-HANDLER", "eBPF monitoring stopped");
}

// Process syscall event
int process_syscall_event(const struct syscall_event *event) {
    if (!event) {
        return -1;
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "Syscall event: PID=%d, Syscall=%s, Ret=%ld", 
           event->pid, get_syscall_name(event->syscall_nr), event->ret);
    return 0;
}

// Process network event
int process_network_event(const struct network_event *event) {
    if (!event) {
        return -1;
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "Network event: PID=%d, Type=%s, Src=%u.%u.%u.%u:%u, Dst=%u.%u.%u.%u:%u", 
           event->pid, get_network_event_name(event->event_type), 
           (event->src_ip >> 24) & 0xFF, (event->src_ip >> 16) & 0xFF, (event->src_ip >> 8) & 0xFF, event->src_ip & 0xFF, event->src_port,
           (event->dst_ip >> 24) & 0xFF, (event->dst_ip >> 16) & 0xFF, (event->dst_ip >> 8) & 0xFF, event->dst_ip & 0xFF, event->dst_port);
    return 0;
}

// Process security event
int process_security_event(const struct security_event *event) {
    if (!event) {
        return -1;
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "Security event: PID=%d, Type=%s, Ret=%ld", 
           event->pid, get_security_event_name(event->event_type), event->ret);
    return 0;
}

// Process file event
int process_file_event(const struct file_event *event) {
    if (!event) {
        return -1;
    }
    
    LOG_INFO_MODULE("eBPF-HANDLER", "File event: PID=%d, Type=%s, Ret=%ld", 
           event->pid, get_file_event_name(event->event_type), event->ret);
    return 0;
}

// Get syscall name
const char* get_syscall_name(uint32_t syscall_nr) {
    switch (syscall_nr) {
        case SYS_READ: return "read";
        case SYS_WRITE: return "write";
        case SYS_OPEN: return "open";
        case SYS_CLOSE: return "close";
        case SYS_STAT: return "stat";
        case SYS_FSTAT: return "fstat";
        case SYS_LSTAT: return "lstat";
        case SYS_POLL: return "poll";
        case SYS_LSEEK: return "lseek";
        case SYS_MMAP: return "mmap";
        case SYS_MPROTECT: return "mprotect";
        case SYS_MUNMAP: return "munmap";
        case SYS_BRK: return "brk";
        case SYS_RT_SIGACTION: return "rt_sigaction";
        case SYS_RT_SIGPROCMASK: return "rt_sigprocmask";
        case SYS_RT_SIGRETURN: return "rt_sigreturn";
        case SYS_IOCTL: return "ioctl";
        case SYS_PREAD64: return "pread64";
        case SYS_PWRITE64: return "pwrite64";
        case SYS_READV: return "readv";
        case SYS_WRITEV: return "writev";
        case SYS_ACCESS: return "access";
        case SYS_PIPE: return "pipe";
        case SYS_SELECT: return "select";
        case SYS_SCHED_YIELD: return "sched_yield";
        case SYS_MREMAP: return "mremap";
        case SYS_MSYNC: return "msync";
        case SYS_MINCORE: return "mincore";
        case SYS_MADVISE: return "madvise";
        case SYS_SHMGET: return "shmget";
        case SYS_SHMAT: return "shmat";
        case SYS_SHMCTL: return "shmctl";
        case SYS_DUP: return "dup";
        case SYS_DUP2: return "dup2";
        case SYS_PAUSE: return "pause";
        case SYS_NANOSLEEP: return "nanosleep";
        case SYS_GETITIMER: return "getitimer";
        case SYS_ALARM: return "alarm";
        case SYS_SETITIMER: return "setitimer";
        case SYS_GETPID: return "getpid";
        case SYS_SENDFILE: return "sendfile";
        case SYS_SOCKET: return "socket";
        case SYS_CONNECT: return "connect";
        case SYS_ACCEPT: return "accept";
        case SYS_SENDTO: return "sendto";
        case SYS_RECVFROM: return "recvfrom";
        case SYS_SENDMSG: return "sendmsg";
        case SYS_RECVMSG: return "recvmsg";
        case SYS_SHUTDOWN: return "shutdown";
        case SYS_BIND: return "bind";
        case SYS_LISTEN: return "listen";
        case SYS_GETSOCKNAME: return "getsockname";
        case SYS_GETPEERNAME: return "getpeername";
        case SYS_SOCKETPAIR: return "socketpair";
        case SYS_SETSOCKOPT: return "setsockopt";
        case SYS_GETSOCKOPT: return "getsockopt";
        case SYS_CLONE: return "clone";
        case SYS_FORK: return "fork";
        case SYS_VFORK: return "vfork";
        case SYS_EXECVE: return "execve";
        case SYS_EXIT: return "exit";
        case SYS_WAIT4: return "wait4";
        case SYS_KILL: return "kill";
        case SYS_UNAME: return "uname";
        case SYS_SEMGET: return "semget";
        case SYS_SEMOP: return "semop";
        case SYS_SEMCTL: return "semctl";
        case SYS_SHDT: return "shmdt";
        case SYS_MSGGET: return "msgget";
        case SYS_MSGSND: return "msgsnd";
        case SYS_MSGRCV: return "msgrcv";
        case SYS_MSGCTL: return "msgctl";
        case SYS_FCNTL: return "fcntl";
        case SYS_FLOCK: return "flock";
        case SYS_FSYNC: return "fsync";
        case SYS_FDATASYNC: return "fdatasync";
        case SYS_TRUNCATE: return "truncate";
        case SYS_FTRUNCATE: return "ftruncate";
        case SYS_GETDENTS: return "getdents";
        case SYS_GETCWD: return "getcwd";
        case SYS_CHDIR: return "chdir";
        case SYS_FCHDIR: return "fchdir";
        case SYS_RENAME: return "rename";
        case SYS_MKDIR: return "mkdir";
        case SYS_RMDIR: return "rmdir";
        case SYS_CREAT: return "creat";
        case SYS_LINK: return "link";
        case SYS_UNLINK: return "unlink";
        case SYS_SYMLINK: return "symlink";
        case SYS_READLINK: return "readlink";
        case SYS_CHMOD: return "chmod";
        case SYS_FCHMOD: return "fchmod";
        case SYS_CHOWN: return "chown";
        case SYS_FCHOWN: return "fchown";
        case SYS_LCHOWN: return "lchown";
        case SYS_UMASK: return "umask";
        case SYS_GETTIMEOFDAY: return "gettimeofday";
        case SYS_GETRLIMIT: return "getrlimit";
        case SYS_GETRUSAGE: return "getrusage";
        case SYS_SYSINFO: return "sysinfo";
        default: return "unknown";
    }
}

// Get network event name
const char* get_network_event_name(uint32_t event_type) {
    switch (event_type) {
        case NET_EVENT_SOCKET_CREATE: return "socket_create";
        case NET_EVENT_SOCKET_BIND: return "socket_bind";
        case NET_EVENT_SOCKET_CONNECT: return "socket_connect";
        case NET_EVENT_SOCKET_LISTEN: return "socket_listen";
        case NET_EVENT_SOCKET_ACCEPT: return "socket_accept";
        case NET_EVENT_SOCKET_SEND: return "socket_send";
        case NET_EVENT_SOCKET_RECV: return "socket_recv";
        case NET_EVENT_SOCKET_CLOSE: return "socket_close";
        default: return "unknown";
    }
}

// Get security event name
const char* get_security_event_name(uint32_t event_type) {
    switch (event_type) {
        case SEC_EVENT_CAPSET: return "capset";
        case SEC_EVENT_PRCTL: return "prctl";
        case SEC_EVENT_SETUID: return "setuid";
        case SEC_EVENT_SETGID: return "setgid";
        case SEC_EVENT_SETRESUID: return "setresuid";
        case SEC_EVENT_SETRESGID: return "setresgid";
        case SEC_EVENT_SETEUID: return "setfsuid";
        case SEC_EVENT_SETEGID: return "setfsgid";
        case SEC_EVENT_SETREUID: return "setreuid";
        case SEC_EVENT_SETREGID: return "setregid";
        default: return "unknown";
    }
}

// Get file event name
const char* get_file_event_name(uint32_t event_type) {
    switch (event_type) {
        case FILE_EVENT_OPEN: return "file_open";
        case FILE_EVENT_READ: return "file_read";
        case FILE_EVENT_WRITE: return "file_write";
        case FILE_EVENT_CLOSE: return "file_close";
        case FILE_EVENT_CREATE: return "file_create";
        case FILE_EVENT_DELETE: return "file_delete";
        case FILE_EVENT_RENAME: return "file_rename";
        case FILE_EVENT_CHMOD: return "file_chmod";
        case FILE_EVENT_CHOWN: return "file_chown";
        case FILE_EVENT_TRUNCATE: return "file_truncate";
        default: return "unknown";
    }
}

// Convert event to JSON
char* event_to_json(const struct ravn_event *event) {
    if (!event) {
        return NULL;
    }
    
    static char json_buffer[2048];
    snprintf(json_buffer, sizeof(json_buffer),
        "{\"timestamp\":%lu,\"pid\":%u,\"tid\":%u,\"event_type\":%u,\"event_category\":%u,\"comm\":\"%s\",\"data\":\"%s\"}",
        event->timestamp, event->pid, event->tid, event->event_type, 
        event->event_category, event->comm, event->data);
    
    return json_buffer;
}