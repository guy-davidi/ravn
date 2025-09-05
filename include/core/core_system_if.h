/* SPDX-License-Identifier: GPL-2.0 */
/*
 * eBPF System Program Interface
 * 
 * This file defines the interface for the eBPF system program that monitors
 * system-level events, privilege changes, and system call activities.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#ifndef _ravn_CORE_SYSTEM_IF_H
#define _ravn_CORE_SYSTEM_IF_H

#include <stdint.h>

/**
 * System event types
 */
enum core_system_event_type {
	CORE_SYSTEM_EVENT_SETUID = 1,
	CORE_SYSTEM_EVENT_SETGID = 2,
	CORE_SYSTEM_EVENT_PTRACE = 3,
	CORE_SYSTEM_EVENT_CAPSET = 4,
	CORE_SYSTEM_EVENT_SCHED_SWITCH = 5,
	CORE_SYSTEM_EVENT_SYSCALL = 6,
	CORE_SYSTEM_EVENT_SIGNAL = 7,
	CORE_SYSTEM_EVENT_EXIT = 8,
};

/**
 * struct core_system_event - System event structure
 * @timestamp_ns: Event timestamp in nanoseconds
 * @event_type: Type of system event
 * @pid: Process ID
 * @tgid: Thread group ID
 * @uid: User ID
 * @gid: Group ID
 * @comm: Process command name
 * @target_pid: Target process ID (for ptrace)
 * @new_uid: New user ID (for setuid)
 * @new_gid: New group ID (for setgid)
 * @cpu_id: CPU ID
 * @priority: Process priority
 * @syscall_number: System call number
 * @signal_number: Signal number
 * @exit_code: Exit code
 */
struct core_system_event {
	uint64_t timestamp_ns;
	uint32_t event_type;
	uint32_t pid;
	uint32_t tgid;
	uint32_t uid;
	uint32_t gid;
	char comm[16];
	uint32_t target_pid;
	uint32_t new_uid;
	uint32_t new_gid;
	uint32_t cpu_id;
	uint32_t priority;
	uint32_t syscall_number;
	uint32_t signal_number;
	uint32_t exit_code;
};

/**
 * Core system program configuration
 */
struct core_system_config {
	int monitor_setuid;
	int monitor_setgid;
	int monitor_ptrace;
	int monitor_capset;
	int monitor_sched_switch;
	int monitor_syscalls;
	int monitor_signals;
	int monitor_exits;
	uint32_t syscall_filter;
	uint32_t signal_filter;
};

/**
 * core_system_program_load() - Load system eBPF program
 * @config: Program configuration
 *
 * Load the system eBPF program with the given configuration.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_system_program_load(const struct core_system_config *config);

/**
 * core_system_program_attach() - Attach system eBPF program
 *
 * Attach the system eBPF program to kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_system_program_attach(void);

/**
 * core_system_program_detach() - Detach system eBPF program
 *
 * Detach the system eBPF program from kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_system_program_detach(void);

/**
 * core_system_get_ring_buffer() - Get system ring buffer
 *
 * Get the ring buffer for system events.
 *
 * Return: Pointer to ring buffer on success, NULL on failure
 */
void *core_system_get_ring_buffer(void);

#endif /* _ravn_CORE_SYSTEM_IF_H */
