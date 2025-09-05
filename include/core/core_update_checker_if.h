/* SPDX-License-Identifier: GPL-2.0 */
/*
 * eBPF Update Checker Program Interface
 * 
 * This file defines the interface for the eBPF update checker program that monitors
 * system updates, package management activities, and update-related security events.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#ifndef _ravn_CORE_UPDATE_CHECKER_IF_H
#define _ravn_CORE_UPDATE_CHECKER_IF_H

#include <stdint.h>

/**
 * Update event types
 */
enum core_update_event_type {
	CORE_UPDATE_EVENT_PACKAGE_MANAGER = 1,
	CORE_UPDATE_EVENT_SYSTEM_UPDATE = 2,
	CORE_UPDATE_EVENT_FIREWALL_UPDATE = 3,
	CORE_UPDATE_EVENT_KERNEL_UPDATE = 4,
	CORE_UPDATE_EVENT_FIRMWARE_UPDATE = 5,
	CORE_UPDATE_EVENT_THIRD_PARTY_UPDATE = 6,
	CORE_UPDATE_EVENT_SECURITY_UPDATE = 7,
	CORE_UPDATE_EVENT_AUTOMATIC_UPDATE = 8,
	CORE_UPDATE_EVENT_MANUAL_UPDATE = 9,
};

/**
 * Update status
 */
enum core_update_status {
	CORE_UPDATE_STATUS_PENDING = 1,
	CORE_UPDATE_STATUS_IN_PROGRESS = 2,
	CORE_UPDATE_STATUS_COMPLETED = 3,
	CORE_UPDATE_STATUS_FAILED = 4,
	CORE_UPDATE_STATUS_ROLLBACK = 5,
};

/**
 * struct core_update_event - Update event structure
 * @timestamp_ns: Event timestamp in nanoseconds
 * @event_type: Type of update event
 * @status: Update status
 * @pid: Process ID
 * @tgid: Thread group ID
 * @uid: User ID
 * @gid: Group ID
 * @comm: Process command name
 * @process_path: Full path to process
 * @package_name: Package name
 * @old_version: Old version string
 * @new_version: New version string
 * @update_source: Update source
 * @update_size: Update size in bytes
 * @security_update: Whether this is a security update
 * @critical_update: Whether this is a critical update
 * @hostname: System hostname
 * @os_version: Operating system version
 * @kernel_version: Kernel version
 * @system_uptime: System uptime in seconds
 * @src_ip: Source IP address
 * @dst_ip: Destination IP address
 * @src_port: Source port
 * @dst_port: Destination port
 * @protocol: Network protocol
 * @command_line: Command line arguments
 * @parent_pid: Parent process ID
 * @session_id: Session ID
 * @exit_code: Exit code
 * @duration_ms: Duration in milliseconds
 */
struct core_update_event {
	uint64_t timestamp_ns;
	uint32_t event_type;
	uint32_t status;
	uint32_t pid;
	uint32_t tgid;
	uint32_t uid;
	uint32_t gid;
	char comm[16];
	char process_path[256];
	char package_name[128];
	char old_version[32];
	char new_version[32];
	char update_source[64];
	uint32_t update_size;
	uint32_t security_update;
	uint32_t critical_update;
	char hostname[64];
	char os_version[64];
	char kernel_version[32];
	uint32_t system_uptime;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	char command_line[512];
	uint32_t parent_pid;
	uint32_t session_id;
	uint32_t exit_code;
	uint32_t duration_ms;
};

/**
 * Core update checker program configuration
 */
struct core_update_checker_config {
	int monitor_package_manager;
	int monitor_system_updates;
	int monitor_firewall_updates;
	int monitor_kernel_updates;
	int monitor_firmware_updates;
	int monitor_third_party_updates;
	int monitor_security_updates;
	int monitor_automatic_updates;
	int monitor_manual_updates;
	uint32_t update_timeout_seconds;
	uint32_t critical_update_threshold;
};

/**
 * core_update_checker_program_load() - Load update checker eBPF program
 * @config: Program configuration
 *
 * Load the update checker eBPF program with the given configuration.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_update_checker_program_load(const struct core_update_checker_config *config);

/**
 * core_update_checker_program_attach() - Attach update checker eBPF program
 *
 * Attach the update checker eBPF program to kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_update_checker_program_attach(void);

/**
 * core_update_checker_program_detach() - Detach update checker eBPF program
 *
 * Detach the update checker eBPF program from kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_update_checker_program_detach(void);

/**
 * core_update_checker_get_ring_buffer() - Get update checker ring buffer
 *
 * Get the ring buffer for update events.
 *
 * Return: Pointer to ring buffer on success, NULL on failure
 */
void *core_update_checker_get_ring_buffer(void);

#endif /* _ravn_CORE_UPDATE_CHECKER_IF_H */
