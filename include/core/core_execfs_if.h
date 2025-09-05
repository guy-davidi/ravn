/* SPDX-License-Identifier: GPL-2.0 */
/*
 * eBPF ExecFS Program Interface
 * 
 * This file defines the interface for the eBPF execfs program that monitors
 * process execution and file system access events.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#ifndef _ravn_CORE_EXECFS_IF_H
#define _ravn_CORE_EXECFS_IF_H

#include <stdint.h>

/**
 * Event types for execfs monitoring
 */
enum core_execfs_event_type {
	CORE_EXECFS_EVENT_EXEC = 1,
	CORE_EXECFS_EVENT_OPEN = 2,
	CORE_EXECFS_EVENT_CREATE = 3,
	CORE_EXECFS_EVENT_DELETE = 4,
	CORE_EXECFS_EVENT_MODIFY = 5,
};

/**
 * struct core_execfs_event - ExecFS event structure
 * @timestamp_ns: Event timestamp in nanoseconds
 * @event_type: Type of event
 * @pid: Process ID
 * @tgid: Thread group ID
 * @ppid: Parent process ID
 * @uid: User ID
 * @gid: Group ID
 * @comm: Process command name
 * @filename: Associated filename
 */
struct core_execfs_event {
	uint64_t timestamp_ns;
	uint32_t event_type;
	uint32_t pid;
	uint32_t tgid;
	uint32_t ppid;
	uint32_t uid;
	uint32_t gid;
	char comm[16];
	char filename[256];
};

/**
 * Core execfs program configuration
 */
struct core_execfs_config {
	int monitor_exec;
	int monitor_open;
	int monitor_create;
	int monitor_delete;
	int monitor_modify;
	uint32_t max_filename_length;
};

/**
 * core_execfs_program_load() - Load execfs eBPF program
 * @config: Program configuration
 *
 * Load the execfs eBPF program with the given configuration.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_execfs_program_load(const struct core_execfs_config *config);

/**
 * core_execfs_program_attach() - Attach execfs eBPF program
 *
 * Attach the execfs eBPF program to kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_execfs_program_attach(void);

/**
 * core_execfs_program_detach() - Detach execfs eBPF program
 *
 * Detach the execfs eBPF program from kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_execfs_program_detach(void);

/**
 * core_execfs_get_ring_buffer() - Get execfs ring buffer
 *
 * Get the ring buffer for execfs events.
 *
 * Return: Pointer to ring buffer on success, NULL on failure
 */
void *core_execfs_get_ring_buffer(void);

#endif /* _ravn_CORE_EXECFS_IF_H */
