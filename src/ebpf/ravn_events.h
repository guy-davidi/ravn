/*
 * RAVN Event Definitions - Shared between eBPF and User-space
 *
 * This header contains all event type enums and structures that are shared
 * between eBPF programs and user-space code. This ensures consistency and
 * avoids duplication.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 */

#ifndef RAVN_EVENTS_H
#define RAVN_EVENTS_H

/* eBPF-compatible types for both kernel and user space */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

/*
 * Memory Event Types
 */
enum memory_event_type {
	MEM_EVENT_ALLOC = 1,        /* Memory allocation */
	MEM_EVENT_FREE = 2,         /* Memory deallocation */
	MEM_EVENT_MMAP = 3,         /* Memory mapping */
	MEM_EVENT_MUNMAP = 4,       /* Memory unmapping */
	MEM_EVENT_MPROTECT = 5,     /* Memory protection change */
	MEM_EVENT_ACCESS = 6,       /* Memory access */
	MEM_EVENT_CORRUPTION = 7,   /* Memory corruption attempt */
	MEM_EVENT_HEAP_SPRAY = 8,   /* Heap spray detection */
	MEM_EVENT_STACK_OVERFLOW = 9, /* Stack overflow attempt */
	MEM_EVENT_PERMISSION_CHANGE = 10 /* Memory permission change */
};

/*
 * Process Event Types
 */
enum process_event_type {
	PROC_EVENT_SPAWN = 1,           /* Process creation */
	PROC_EVENT_EXIT = 2,            /* Process termination */
	PROC_EVENT_EXEC = 3,            /* Process execution */
	PROC_EVENT_FORK = 4,            /* Process fork */
	PROC_EVENT_CLONE = 5,           /* Process clone */
	PROC_EVENT_VFORK = 6,           /* Process vfork */
	PROC_EVENT_SETUID = 7,          /* User ID change */
	PROC_EVENT_SETGID = 8,          /* Group ID change */
	PROC_EVENT_SETRESUID = 9,       /* Real/effective/saved UID change */
	PROC_EVENT_SETRESGID = 10,      /* Real/effective/saved GID change */
	PROC_EVENT_CAPSET = 11,         /* Capability set change */
	PROC_EVENT_PRCTL = 12,          /* Process control */
	PROC_EVENT_SIGNAL = 13,         /* Signal handling */
	PROC_EVENT_WORKING_DIR = 14,    /* Working directory change */
	PROC_EVENT_ENV_CHANGE = 15,     /* Environment variable change */
	PROC_EVENT_PRIORITY_CHANGE = 16, /* Priority change */
	PROC_EVENT_AFFINITY_CHANGE = 17, /* CPU affinity change */
	PROC_EVENT_NAMESPACE_CHANGE = 18, /* Namespace change */
	PROC_EVENT_IPC_OPERATION = 19,  /* IPC operation */
	PROC_EVENT_SESSION_CHANGE = 20  /* Session change */
};

/*
 * Kernel Event Types
 */
enum kernel_event_type {
	KERNEL_MODULE_LOAD = 1,        /* Module loading */
	KERNEL_MODULE_UNLOAD = 2,      /* Module unloading */
	KERNEL_FUNCTION_CALL = 3,      /* Kernel function call */
	KERNEL_MEMORY_OP = 4,          /* Kernel memory operation */
	KERNEL_SECURITY_VIOLATION = 5, /* Security violation */
	KERNEL_PERFORMANCE_EVENT = 6,  /* Performance event */
	KERNEL_DEBUG_EVENT = 7,        /* Debug event */
	KERNEL_INTERRUPT = 8,          /* Interrupt handling */
	KERNEL_SCHEDULER_EVENT = 9,    /* Scheduler event */
	KERNEL_IO_EVENT = 10,          /* I/O event */
	KERNEL_NETWORK_EVENT = 11,     /* Network event */
	KERNEL_FILESYSTEM_EVENT = 12,  /* Filesystem event */
	KERNEL_DEVICE_EVENT = 13,      /* Device event */
	KERNEL_TIMER_EVENT = 14,       /* Timer event */
	KERNEL_SIGNAL_EVENT = 15       /* Signal event */
};

/*
 * Performance Event Types
 */
enum performance_event_type {
	PERF_CPU_USAGE = 1,           /* CPU usage event */
	PERF_MEMORY_USAGE = 2,        /* Memory usage event */
	PERF_DISK_IO = 3,             /* Disk I/O event */
	PERF_NETWORK_IO = 4,          /* Network I/O event */
	PERF_SYSTEM_LOAD = 5,         /* System load event */
	PERF_RESOURCE_CONTENTION = 6, /* Resource contention event */
	PERF_CACHE_MISS = 7,          /* Cache miss event */
	PERF_INTERRUPT = 8,           /* Interrupt event */
	PERF_CONTEXT_SWITCH = 9,      /* Context switch event */
	PERF_PAGE_FAULT = 10,         /* Page fault event */
	PERF_SYSCALL_OVERHEAD = 11,   /* System call overhead event */
	PERF_MEMORY_PRESSURE = 12,    /* Memory pressure event */
	PERF_IO_WAIT = 13,            /* I/O wait event */
	PERF_CPU_FREQUENCY = 14,      /* CPU frequency event */
	PERF_THERMAL_EVENT = 15       /* Thermal event */
};

/*
 * Event Structures (shared between eBPF and user-space)
 */

/**
 * struct memory_event - Memory event structure
 */
struct memory_event {
	__u64 timestamp;   /* Event timestamp */
	__u32 pid;	      /* Process ID */
	__u32 tid;	      /* Thread ID */
	__u32 event_type;  /* Memory event type */
	__u64 address;     /* Memory address */
	__u64 size;	      /* Memory size */
	__u32 permissions; /* Memory permissions */
	__u32 flags;	      /* Allocation flags */
	__s64 ret;	      /* Return value */
	char comm[16];	      /* Process name */
	char filename[256];   /* Associated filename */
	__u64 stack_trace[8]; /* Stack trace */
};

/**
 * struct process_event - Process event structure
 */
struct process_event {
	__u64 timestamp;	   /* Event timestamp */
	__u32 pid;		   /* Process ID */
	__u32 tid;		   /* Thread ID */
	__u32 ppid;		   /* Parent process ID */
	__u32 event_type;	   /* Process event type */
	__u32 uid;		   /* User ID */
	__u32 gid;		   /* Group ID */
	__u32 euid;		   /* Effective user ID */
	__u32 egid;		   /* Effective group ID */
	__u32 suid;		   /* Saved user ID */
	__u32 sgid;		   /* Saved group ID */
	__u32 capabilities;	   /* Process capabilities */
	__s64 ret;		   /* Return value */
	char comm[16];		   /* Process name */
	char parent_comm[16];	   /* Parent process name */
	char filename[256];	   /* Executable filename */
	char working_dir[256];	   /* Working directory */
	char command_line[512];	   /* Command line arguments */
	__u64 stack_trace[8];   /* Stack trace */
};

/**
 * struct kernel_event - Kernel event structure
 */
struct kernel_event {
	__u64 timestamp;	   /* Event timestamp */
	__u32 pid;		   /* Process ID */
	__u32 tid;		   /* Thread ID */
	__u32 event_type;	   /* Kernel event type */
	__u32 cpu_id;	   /* CPU ID */
	__u64 address;	   /* Memory address */
	__u64 size;		   /* Size */
	__u32 flags;		   /* Event flags */
	__s64 ret;		   /* Return value */
	char comm[16];		   /* Process name */
	char module_name[64];	   /* Module name */
	char function_name[64];    /* Function name */
	char filename[256];	   /* Filename */
	__u64 stack_trace[8];   /* Stack trace */
	__u64 registers[8];	   /* CPU registers */
};

/**
 * struct performance_event - Performance event structure
 */
struct performance_event {
	__u64 timestamp;	   /* Event timestamp */
	__u32 pid;		   /* Process ID */
	__u32 tid;		   /* Thread ID */
	__u32 event_type;	   /* Performance event type */
	__u32 cpu_id;	   /* CPU ID */
	__u64 value;		   /* Performance value */
	__u64 threshold;	   /* Threshold value */
	__u32 flags;		   /* Event flags */
	__s64 ret;		   /* Return value */
	char comm[16];		   /* Process name */
	char device_name[64];	   /* Device name */
	char metric_name[64];	   /* Metric name */
	__u64 stack_trace[8];   /* Stack trace */
	__u64 performance_data[8]; /* Performance data */
};

#endif // RAVN_EVENTS_H
