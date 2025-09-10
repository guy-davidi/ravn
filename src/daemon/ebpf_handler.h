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
 * System Call Number Enums - Comprehensive Linux system call definitions
 * These enums make system call handling more readable and maintainable
 */

/**
 * enum syscall_number - Linux system call numbers
 * Based on x86_64 Linux system call table
 */
enum syscall_number {
	SYS_READ = 0,			/* Read from file descriptor */
	SYS_WRITE = 1,			/* Write to file descriptor */
	SYS_OPEN = 2,			/* Open file */
	SYS_CLOSE = 3,			/* Close file descriptor */
	SYS_STAT = 4,			/* Get file status */
	SYS_FSTAT = 5,			/* Get file status by file descriptor */
	SYS_LSTAT = 6,			/* Get file status (no follow symlinks) */
	SYS_POLL = 7,			/* Wait for events on file descriptors */
	SYS_LSEEK = 8,			/* Reposition file offset */
	SYS_MMAP = 9,			/* Map files or devices into memory */
	SYS_MPROTECT = 10,		/* Set protection on memory region */
	SYS_MUNMAP = 11,		/* Unmap memory region */
	SYS_BRK = 12,			/* Change data segment size */
	SYS_RT_SIGACTION = 13,		/* Change signal action */
	SYS_RT_SIGPROCMASK = 14,	/* Examine and change blocked signals */
	SYS_RT_SIGRETURN = 15,		/* Return from signal handler */
	SYS_IOCTL = 16,			/* Control device */
	SYS_PREAD64 = 17,		/* Read from file at offset */
	SYS_PWRITE64 = 18,		/* Write to file at offset */
	SYS_READV = 19,			/* Read data into multiple buffers */
	SYS_WRITEV = 20,		/* Write data from multiple buffers */
	SYS_ACCESS = 21,		/* Check user permissions for file */
	SYS_PIPE = 22,			/* Create pipe */
	SYS_SELECT = 23,		/* Synchronous I/O multiplexing */
	SYS_SCHED_YIELD = 24,		/* Yield processor */
	SYS_MREMAP = 25,		/* Remap memory region */
	SYS_MSYNC = 26,			/* Synchronize memory with storage */
	SYS_MINCORE = 27,		/* Check if pages are in memory */
	SYS_MADVISE = 28,		/* Give advice about memory usage */
	SYS_SHMGET = 29,		/* Get shared memory segment */
	SYS_SHMAT = 30,			/* Attach shared memory segment */
	SYS_SHMCTL = 31,		/* Shared memory control operations */
	SYS_DUP = 32,			/* Duplicate file descriptor */
	SYS_DUP2 = 33,			/* Duplicate file descriptor */
	SYS_PAUSE = 34,			/* Suspend process until signal */
	SYS_NANOSLEEP = 35,		/* High-resolution sleep */
	SYS_GETITIMER = 36,		/* Get value of interval timer */
	SYS_ALARM = 37,			/* Set alarm clock for delivery of signal */
	SYS_SETITIMER = 38,		/* Set value of interval timer */
	SYS_GETPID = 39,		/* Get process identification */
	SYS_SENDFILE = 40,		/* Transfer data between file descriptors */
	SYS_SOCKET = 41,		/* Create endpoint for communication */
	SYS_CONNECT = 42,		/* Initiate connection on socket */
	SYS_ACCEPT = 43,		/* Accept connection on socket */
	SYS_SENDTO = 44,		/* Send message on socket */
	SYS_RECVFROM = 45,		/* Receive message from socket */
	SYS_SENDMSG = 46,		/* Send message on socket */
	SYS_RECVMSG = 47,		/* Receive message from socket */
	SYS_SHUTDOWN = 48,		/* Shut down part of full-duplex connection */
	SYS_BIND = 49,			/* Bind name to socket */
	SYS_LISTEN = 50,		/* Listen for connections on socket */
	SYS_GETSOCKNAME = 51,		/* Get socket name */
	SYS_GETPEERNAME = 52,		/* Get name of connected peer socket */
	SYS_SOCKETPAIR = 53,		/* Create pair of connected sockets */
	SYS_SETSOCKOPT = 54,		/* Set options on sockets */
	SYS_GETSOCKOPT = 55,		/* Get options on sockets */
	SYS_CLONE = 56,			/* Create child process */
	SYS_FORK = 57,			/* Create child process */
	SYS_VFORK = 58,			/* Create child process and block parent */
	SYS_EXECVE = 59,		/* Execute program */
	SYS_EXIT = 60,			/* Terminate calling process */
	SYS_WAIT4 = 61,			/* Wait for process to change state */
	SYS_KILL = 62,			/* Send signal to process */
	SYS_UNAME = 63,			/* Get name and information about current kernel */
	SYS_SEMGET = 64,		/* Get semaphore set identifier */
	SYS_SEMOP = 65,			/* Semaphore operations */
	SYS_SEMCTL = 66,		/* Semaphore control operations */
	SYS_SHDT = 67,			/* Detach shared memory segment */
	SYS_MSGGET = 68,		/* Get message queue identifier */
	SYS_MSGSND = 69,		/* Send message to message queue */
	SYS_MSGRCV = 70,		/* Receive message from message queue */
	SYS_MSGCTL = 71,		/* Message control operations */
	SYS_FCNTL = 72,			/* Manipulate file descriptor */
	SYS_FLOCK = 73,			/* Apply or remove advisory lock on open file */
	SYS_FSYNC = 74,			/* Synchronize file's in-core state with storage */
	SYS_FDATASYNC = 75,		/* Synchronize file's in-core data with storage */
	SYS_TRUNCATE = 76,		/* Truncate file to specified length */
	SYS_FTRUNCATE = 77,		/* Truncate file to specified length */
	SYS_GETDENTS = 78,		/* Get directory entries */
	SYS_GETCWD = 79,		/* Get current working directory */
	SYS_CHDIR = 80,			/* Change working directory */
	SYS_FCHDIR = 81,		/* Change working directory */
	SYS_RENAME = 82,		/* Change name or location of file */
	SYS_MKDIR = 83,			/* Create directory */
	SYS_RMDIR = 84,			/* Remove directory */
	SYS_CREAT = 85,			/* Create new or rewrite existing file */
	SYS_LINK = 86,			/* Make new name for file */
	SYS_UNLINK = 87,		/* Delete name and possibly file */
	SYS_SYMLINK = 88,		/* Make symbolic link */
	SYS_READLINK = 89,		/* Read value of symbolic link */
	SYS_CHMOD = 90,			/* Change permissions of file */
	SYS_FCHMOD = 91,		/* Change permissions of file */
	SYS_CHOWN = 92,			/* Change ownership of file */
	SYS_FCHOWN = 93,		/* Change ownership of file */
	SYS_LCHOWN = 94,		/* Change ownership of file */
	SYS_UMASK = 95,			/* Set file mode creation mask */
	SYS_GETTIMEOFDAY = 96,		/* Get time */
	SYS_GETRLIMIT = 97,		/* Get resource limits */
	SYS_GETRUSAGE = 98,		/* Get resource usage */
	SYS_SYSINFO = 99,		/* Return system information */
	SYS_OPENAT = 257,		/* Open file relative to directory file descriptor */
	SYS_MKDIRAT = 258,		/* Create directory relative to directory file descriptor */
	SYS_MKNODAT = 259,		/* Create special or ordinary file relative to directory */
	SYS_FCHOWNAT = 260,		/* Change ownership of file relative to directory */
	SYS_FUTIMESAT = 261,		/* Change timestamps of file relative to directory */
	SYS_NEWFSTATAT = 262,		/* Get file status relative to directory */
	SYS_UNLINKAT = 263,		/* Remove directory entry relative to directory */
	SYS_RENAMEAT = 264,		/* Rename file relative to directory */
	SYS_LINKAT = 265,		/* Make new name for file relative to directory */
	SYS_SYMLINKAT = 266,		/* Make symbolic link relative to directory */
	SYS_READLINKAT = 267,		/* Read value of symbolic link relative to directory */
	SYS_FCHMODAT = 268,		/* Change permissions of file relative to directory */
	SYS_FACCESSAT = 269,		/* Check user permissions for file relative to directory */
	SYS_PSELECT6 = 270,		/* Synchronous I/O multiplexing with timeout */
	SYS_PPOLL = 271,		/* Wait for events on file descriptors with timeout */
	SYS_UNSHARE = 272,		/* Unshare parts of process context */
	SYS_SET_ROBUST_LIST = 273,	/* Set list of robust futexes */
	SYS_GET_ROBUST_LIST = 274,	/* Get list of robust futexes */
	SYS_SPLICE = 275,		/* Move data between file descriptors */
	SYS_TEE = 276,			/* Duplicate pipe content */
	SYS_SYNC_FILE_RANGE = 277,	/* Sync file segment with disk */
	SYS_VMSPLICE = 278,		/* Move user pages to pipe */
	SYS_MOVE_PAGES = 279,		/* Move pages in virtual address space */
	SYS_UTIMENSAT = 280,		/* Change file timestamps with nanosecond precision */
	SYS_EPOLL_PWAIT = 281,		/* Wait for events on epoll file descriptor */
	SYS_SIGNALFD = 282,		/* Create file descriptor for accepting signals */
	SYS_TIMERFD_CREATE = 283,	/* Create timer that delivers timer expiration notifications */
	SYS_EVENTFD = 284,		/* Create file descriptor for event notification */
	SYS_FALLOCATE = 285,		/* Manipulate file space */
	SYS_TIMERFD_SETTIME = 286,	/* Arm or disarm timer created by timerfd_create */
	SYS_TIMERFD_GETTIME = 287,	/* Get current time of timer created by timerfd_create */
	SYS_ACCEPT4 = 288,		/* Accept connection on socket */
	SYS_SIGNALFD4 = 289,		/* Create file descriptor for accepting signals */
	SYS_EVENTFD2 = 290,		/* Create file descriptor for event notification */
	SYS_EPOLL_CREATE1 = 291,	/* Create epoll file descriptor */
	SYS_DUP3 = 292,			/* Duplicate file descriptor */
	SYS_PIPE2 = 293,		/* Create pipe */
	SYS_INOTIFY_INIT1 = 294,	/* Initialize inotify instance */
	SYS_PREADV = 295,		/* Read data into multiple buffers at offset */
	SYS_PWRITEV = 296,		/* Write data from multiple buffers at offset */
	SYS_RT_TGSIGQUEUEINFO = 297,	/* Send signal to thread */
	SYS_PERF_EVENT_OPEN = 298,	/* Set up performance monitoring */
	SYS_RECVMMSG = 299,		/* Receive multiple messages on socket */
	SYS_FANOTIFY_INIT = 300,	/* Create and initialize fanotify group */
	SYS_FANOTIFY_MARK = 301,	/* Add, remove, or modify fanotify mark */
	SYS_PRLIMIT64 = 302,		/* Get/set resource limits */
	SYS_NAME_TO_HANDLE_AT = 303,	/* Obtain handle for pathname */
	SYS_OPEN_BY_HANDLE_AT = 304,	/* Open file via handle */
	SYS_CLOCK_ADJTIME = 305,	/* Tune kernel clock */
	SYS_SYNCFS = 306,		/* Commit filesystem caches to disk */
	SYS_SENDMMSG = 307,		/* Send multiple messages on socket */
	SYS_SETNS = 308,		/* Associate thread with namespace */
	SYS_GETCPU = 309,		/* Determine CPU and NUMA node */
	SYS_PROCESS_VM_READV = 310,	/* Transfer data between process address spaces */
	SYS_PROCESS_VM_WRITEV = 311,	/* Transfer data between process address spaces */
	SYS_KCMP = 312,			/* Compare two processes to determine if they share kernel resources */
	SYS_FINIT_MODULE = 313,		/* Load kernel module from file descriptor */
	SYS_SCHED_SETATTR = 314,	/* Set scheduling policy and attributes */
	SYS_SCHED_GETATTR = 315,	/* Get scheduling policy and attributes */
	SYS_RENAMEAT2 = 316,		/* Rename file relative to directory */
	SYS_SECCOMP = 317,		/* Operate on Secure Computing state */
	SYS_GETRANDOM = 318,		/* Obtain series of random bytes */
	SYS_MEMFD_CREATE = 319,		/* Create anonymous file */
	SYS_KEXEC_FILE_LOAD = 320,	/* Load new kernel for later execution */
	SYS_BPF = 321,			/* Perform command on extended BPF map/program */
	SYS_EXECVEAT = 322,		/* Execute program relative to directory */
	SYS_USERFAULTFD = 323,		/* Create file descriptor for handling page faults */
	SYS_MEMBARRIER = 324,		/* Issue memory barriers on a set of threads */
	SYS_MLOCK2 = 325,		/* Lock memory pages */
	SYS_COPY_FILE_RANGE = 326,	/* Copy data range between files */
	SYS_PREADV2 = 327,		/* Read data into multiple buffers at offset */
	SYS_PWRITEV2 = 328,		/* Write data from multiple buffers at offset */
	SYS_PKEY_MPROTECT = 329,	/* Set protection on memory pages */
	SYS_PKEY_ALLOC = 330,		/* Allocate protection key */
	SYS_PKEY_FREE = 331,		/* Free protection key */
	SYS_STATX = 332,		/* Get file status (extended) */
	SYS_IO_PGETEVENTS = 333,	/* Read asynchronous I/O events from completion queue */
	SYS_RSEQ = 334,			/* Restartable sequences */
	SYS_PIDFD_SEND_SIGNAL = 424,	/* Send signal to process via file descriptor */
	SYS_IO_URING_SETUP = 425,	/* Set up io_uring instance */
	SYS_IO_URING_ENTER = 426,	/* Submit/complete asynchronous I/O */
	SYS_IO_URING_REGISTER = 427,	/* Register files or user buffers for asynchronous I/O */
	SYS_OPEN_TREE = 428,		/* Open directory in different mount namespace */
	SYS_MOVE_MOUNT = 429,		/* Move mount from one place to another */
	SYS_FSOPEN = 430,		/* Open filesystem context */
	SYS_FSCONFIG = 431,		/* Configure filesystem context */
	SYS_FSMOUNT = 432,		/* Attach filesystem context to superblock */
	SYS_FSPICK = 433,		/* Pick superblock for filesystem context */
	SYS_PIDFD_OPEN = 434,		/* Open process file descriptor */
	SYS_CLONE3 = 435,		/* Create child process */
	SYS_CLOSE_RANGE = 436,		/* Close range of file descriptors */
	SYS_OPENAT2 = 437,		/* Open file relative to directory file descriptor */
	SYS_PIDFD_GETFD = 438,		/* Get file descriptor from another process */
	SYS_FACCESSAT2 = 439,		/* Check user permissions for file relative to directory */
	SYS_PROCESS_MADVISE = 440,	/* Give advice about memory usage of another process */
	SYS_EPOLL_PWAIT2 = 441,		/* Wait for events on epoll file descriptor */
	SYS_MOUNT_SETATTR = 442,	/* Change mount attributes */
	SYS_QUOTACTL_FD = 443,		/* Manipulate disk quotas */
	SYS_LANDLOCK_CREATE_RULESET = 444, /* Create Landlock ruleset */
	SYS_LANDLOCK_ADD_RULE = 445,	/* Add rule to Landlock ruleset */
	SYS_LANDLOCK_RESTRICT_SELF = 446, /* Enforce Landlock ruleset on current thread */
	SYS_MEMFD_SECRET = 447,		/* Create secret anonymous file */
	SYS_PROCESS_MRELEASE = 448,	/* Release memory pages of another process */
	SYS_FUTEX_WAITV = 449,		/* Wait on futexes */
	SYS_SET_MEMPOLICY_HOME_NODE = 450 /* Set home node for memory policy */
};

/**
 * enum network_event_type - Network event types for eBPF monitoring
 */
enum network_event_type {
	NET_EVENT_SOCKET_CREATE = 1,	/* Socket creation */
	NET_EVENT_SOCKET_BIND = 2,	/* Socket bind operation */
	NET_EVENT_SOCKET_CONNECT = 3,	/* Socket connect operation */
	NET_EVENT_SOCKET_LISTEN = 4,	/* Socket listen operation */
	NET_EVENT_SOCKET_ACCEPT = 5,	/* Socket accept operation */
	NET_EVENT_SOCKET_SEND = 6,	/* Socket send operation */
	NET_EVENT_SOCKET_RECV = 7,	/* Socket receive operation */
	NET_EVENT_SOCKET_CLOSE = 8	/* Socket close operation */
};

/**
 * enum security_event_type - Security event types for eBPF monitoring
 */
enum security_event_type {
	SEC_EVENT_CAPSET = 1,		/* Capability set operation */
	SEC_EVENT_PRCTL = 2,		/* Process control operation */
	SEC_EVENT_SETUID = 3,		/* Set user ID operation */
	SEC_EVENT_SETGID = 4,		/* Set group ID operation */
	SEC_EVENT_SETRESUID = 5,	/* Set real, effective, and saved user ID */
	SEC_EVENT_SETRESGID = 6,	/* Set real, effective, and saved group ID */
	SEC_EVENT_SETEUID = 7,		/* Set effective user ID */
	SEC_EVENT_SETEGID = 8,		/* Set effective group ID */
	SEC_EVENT_SETREUID = 9,		/* Set real and effective user ID */
	SEC_EVENT_SETREGID = 10		/* Set real and effective group ID */
};

/**
 * enum file_event_type - File event types for eBPF monitoring
 */
enum file_event_type {
	FILE_EVENT_OPEN = 1,		/* File open operation */
	FILE_EVENT_READ = 2,		/* File read operation */
	FILE_EVENT_WRITE = 3,		/* File write operation */
	FILE_EVENT_CLOSE = 4,		/* File close operation */
	FILE_EVENT_CREATE = 5,		/* File creation */
	FILE_EVENT_DELETE = 6,		/* File deletion */
	FILE_EVENT_RENAME = 7,		/* File rename operation */
	FILE_EVENT_CHMOD = 8,		/* File permission change */
	FILE_EVENT_CHOWN = 9,		/* File ownership change */
	FILE_EVENT_TRUNCATE = 10	/* File truncation */
};

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
 * @src_ip: Source IP address
 * @dst_ip: Destination IP address
 * @src_port: Source port number
 * @dst_port: Destination port number
 * @bytes_sent: Number of bytes sent
 * @bytes_received: Number of bytes received
 * @comm: Process command name
 *
 * Represents a network event captured by eBPF network monitor.
 * This structure must match the eBPF program structure exactly.
 */
struct network_event {
	uint64_t timestamp;		/* Event timestamp */
	uint32_t pid;			/* Process ID */
	uint32_t tid;			/* Thread ID */
	uint32_t event_type;		/* Network event type */
	uint16_t family;		/* Address family */
	uint16_t type;			/* Socket type */
	uint16_t protocol;		/* Protocol */
	uint32_t src_ip;		/* Source IP address */
	uint32_t dst_ip;		/* Destination IP address */
	uint16_t src_port;		/* Source port */
	uint16_t dst_port;		/* Destination port */
	uint32_t bytes_sent;		/* Bytes sent */
	uint32_t bytes_received;	/* Bytes received */
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
