/*
 * RAVN eBPF Handler - Header File
 *
 * This header defines the eBPF event handling interface for the RAVN security
 * platform, providing kernel-space event capture and user-space processing
 * for comprehensive system monitoring and security analysis.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 *
 * The eBPF handler implements:
 * - System call monitoring and analysis
 * - Network activity tracking
 * - Security event detection
 * - File I/O monitoring
 * - Real-time event processing and forwarding
 *
 * Architecture:
 * - Kernel-space eBPF programs for event capture
 * - User-space handlers for event processing
 * - Ring buffer communication between kernel and user space
 * - JSON serialization for Redis storage
 */

#ifndef RAVN_EBPF_HANDLER_H
#define RAVN_EBPF_HANDLER_H

#include <stdint.h>
#include <time.h>
#include <bpf/libbpf.h>

/*
 * Event Structures (must match eBPF programs)
 * These structures define the data format for events captured by eBPF programs
 * and processed by user-space handlers.
 */

/**
 * struct syscall_event - System call event structure
 * @timestamp: Event timestamp in nanoseconds since epoch
 * @pid: Process ID that made the system call
 * @tid: Thread ID that made the system call
 * @syscall_nr: System call number
 * @ret: System call return value
 * @comm: Process command name (truncated to 15 chars + null)
 * @filename: Filename associated with the system call
 *
 * Represents a system call event captured by eBPF syscall monitor.
 */
struct syscall_event {
	uint64_t timestamp;		/* Event timestamp */
	uint32_t pid;			/* Process ID */
	uint32_t tid;			/* Thread ID */
	uint32_t syscall_nr;		/* System call number */
	int64_t ret;			/* Return value */
	char comm[16];			/* Process name */
	char filename[256];		/* Associated filename */
};

/**
 * struct network_event - Network event structure
 * @timestamp: Event timestamp in nanoseconds since epoch
 * @pid: Process ID that made the network call
 * @tid: Thread ID that made the network call
 * @event_type: Type of network event (connect, bind, etc.)
 * @family: Address family (AF_INET, AF_INET6, etc.)
 * @type: Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
 * @protocol: Protocol (IPPROTO_TCP, IPPROTO_UDP, etc.)
 * @local_port: Local port number
 * @remote_port: Remote port number
 * @local_ip: Local IP address
 * @remote_ip: Remote IP address
 * @ret: System call return value
 * @comm: Process command name
 *
 * Represents a network event captured by eBPF network monitor.
 */
struct network_event {
	uint64_t timestamp;		/* Event timestamp */
	uint32_t pid;			/* Process ID */
	uint32_t tid;			/* Thread ID */
	uint32_t event_type;		/* Network event type */
	uint32_t family;		/* Address family */
	uint32_t type;			/* Socket type */
	uint32_t protocol;		/* Protocol */
	uint32_t local_port;		/* Local port */
	uint32_t remote_port;		/* Remote port */
	uint32_t local_ip;		/* Local IP address */
	uint32_t remote_ip;		/* Remote IP address */
	int64_t ret;			/* Return value */
	char comm[16];			/* Process name */
};

/**
 * struct security_event - Security event structure
 * @timestamp: Event timestamp in nanoseconds since epoch
 * @pid: Process ID that triggered the security event
 * @tid: Thread ID that triggered the security event
 * @event_type: Type of security event (ptrace, setuid, etc.)
 * @target_pid: Target process ID (for ptrace, etc.)
 * @uid: User ID
 * @gid: Group ID
 * @mode: File mode or permission bits
 * @ret: System call return value
 * @comm: Process command name
 * @target_comm: Target process command name
 * @pathname: Path associated with the security event
 *
 * Represents a security event captured by eBPF security monitor.
 */
struct security_event {
	uint64_t timestamp;		/* Event timestamp */
	uint32_t pid;			/* Process ID */
	uint32_t tid;			/* Thread ID */
	uint32_t event_type;		/* Security event type */
	uint32_t target_pid;		/* Target process ID */
	uint32_t uid;			/* User ID */
	uint32_t gid;			/* Group ID */
	uint32_t mode;			/* Mode/permissions */
	int64_t ret;			/* Return value */
	char comm[16];			/* Process name */
	char target_comm[16];		/* Target process name */
	char pathname[256];		/* Associated path */
};

/**
 * struct file_event - File I/O event structure
 * @timestamp: Event timestamp in nanoseconds since epoch
 * @pid: Process ID that performed the file operation
 * @tid: Thread ID that performed the file operation
 * @event_type: Type of file event (open, read, write, etc.)
 * @fd: File descriptor
 * @flags: File open flags
 * @mode: File mode
 * @size: Data size (for read/write operations)
 * @ret: System call return value
 * @comm: Process command name
 * @filename: Source filename
 * @target_filename: Target filename (for rename operations)
 *
 * Represents a file I/O event captured by eBPF file monitor.
 */
struct file_event {
	uint64_t timestamp;		/* Event timestamp */
	uint32_t pid;			/* Process ID */
	uint32_t tid;			/* Thread ID */
	uint32_t event_type;		/* File event type */
	uint32_t fd;			/* File descriptor */
	uint32_t flags;			/* File flags */
	uint32_t mode;			/* File mode */
	uint64_t size;			/* Data size */
	int64_t ret;			/* Return value */
	char comm[16];			/* Process name */
	char filename[256];		/* Source filename */
	char target_filename[256];	/* Target filename */
};

/**
 * struct ravn_event - Generic event structure for Redis storage
 * @timestamp: Event timestamp in nanoseconds since epoch
 * @pid: Process ID
 * @tid: Thread ID
 * @event_type: Specific event type within category
 * @event_category: Event category (1=syscall, 2=network, 3=security, 4=file)
 * @comm: Process command name
 * @data: JSON serialized event data
 *
 * Generic event structure used for Redis storage and AI processing.
 * Contains common fields and JSON-serialized specific event data.
 */
struct ravn_event {
	uint64_t timestamp;		/* Event timestamp */
	uint32_t pid;			/* Process ID */
	uint32_t tid;			/* Thread ID */
	uint32_t event_type;		/* Event type */
	uint32_t event_category;	/* Event category */
	char comm[16];			/* Process name */
	char data[1024];		/* JSON event data */
};

/*
 * eBPF Handler Core Functions
 */

/**
 * init_ebpf_handlers - Initialize eBPF event handlers
 *
 * Initializes all eBPF programs and their associated handlers for
 * system call, network, security, and file monitoring.
 *
 * Return: 0 on success, -1 on failure
 */
int init_ebpf_handlers(void);

/**
 * cleanup_ebpf_handlers - Cleanup eBPF event handlers
 *
 * Performs cleanup of all eBPF programs and associated resources.
 * This function is safe to call multiple times.
 */
void cleanup_ebpf_handlers(void);

/**
 * ebpf_handler_start_monitoring - Start eBPF monitoring
 *
 * Starts the eBPF monitoring system and begins event collection.
 *
 * Return: 0 on success, -1 on failure
 */
int ebpf_handler_start_monitoring(void);

/**
 * ebpf_handler_stop_monitoring - Stop eBPF monitoring
 *
 * Stops the eBPF monitoring system and event collection.
 */
void ebpf_handler_stop_monitoring(void);

/*
 * Event Processing Functions
 */

/**
 * process_syscall_event - Process system call event
 * @event: System call event to process
 *
 * Processes a system call event, converts it to generic format,
 * and forwards it to Redis for storage and AI analysis.
 *
 * Return: 0 on success, -1 on failure
 */
int process_syscall_event(const struct syscall_event *event);

/**
 * process_network_event - Process network event
 * @event: Network event to process
 *
 * Processes a network event, converts it to generic format,
 * and forwards it to Redis for storage and AI analysis.
 *
 * Return: 0 on success, -1 on failure
 */
int process_network_event(const struct network_event *event);

/**
 * process_security_event - Process security event
 * @event: Security event to process
 *
 * Processes a security event, converts it to generic format,
 * and forwards it to Redis for storage and AI analysis.
 *
 * Return: 0 on success, -1 on failure
 */
int process_security_event(const struct security_event *event);

/**
 * process_file_event - Process file I/O event
 * @event: File event to process
 *
 * Processes a file I/O event, converts it to generic format,
 * and forwards it to Redis for storage and AI analysis.
 *
 * Return: 0 on success, -1 on failure
 */
int process_file_event(const struct file_event *event);

/*
 * Utility Functions
 */

/**
 * get_syscall_name - Get system call name from number
 * @syscall_nr: System call number
 *
 * Returns the human-readable name for a system call number.
 *
 * Return: System call name string, "UNKNOWN" if not found
 */
const char *get_syscall_name(uint32_t syscall_nr);

/**
 * get_network_event_name - Get network event name from type
 * @event_type: Network event type
 *
 * Returns the human-readable name for a network event type.
 *
 * Return: Network event name string, "UNKNOWN" if not found
 */
const char *get_network_event_name(uint32_t event_type);

/**
 * get_security_event_name - Get security event name from type
 * @event_type: Security event type
 *
 * Returns the human-readable name for a security event type.
 *
 * Return: Security event name string, "UNKNOWN" if not found
 */
const char *get_security_event_name(uint32_t event_type);

/**
 * get_file_event_name - Get file event name from type
 * @event_type: File event type
 *
 * Returns the human-readable name for a file event type.
 *
 * Return: File event name string, "UNKNOWN" if not found
 */
const char *get_file_event_name(uint32_t event_type);

/**
 * event_to_json - Convert event to JSON string
 * @event: Event structure to convert
 *
 * Converts a generic event structure to JSON format for storage
 * and transmission.
 *
 * Return: JSON string (caller must free), NULL on failure
 */
char *event_to_json(const struct ravn_event *event);

#endif // RAVN_EBPF_HANDLER_H
