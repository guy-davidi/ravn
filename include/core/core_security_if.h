/* SPDX-License-Identifier: GPL-2.0 */
/*
 * eBPF Security Program Interface
 * 
 * This file defines the interface for the eBPF security program that monitors
 * security-related events, privilege escalations, and suspicious activities.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#ifndef _ravn_CORE_SECURITY_IF_H
#define _ravn_CORE_SECURITY_IF_H

#include <stdint.h>

/**
 * Security event types
 */
enum core_security_event_type {
	CORE_SECURITY_EVENT_PRIVILEGE_ESCALATION = 1,
	CORE_SECURITY_EVENT_SUSPICIOUS_PROCESS = 2,
	CORE_SECURITY_EVENT_MALWARE_DETECTION = 3,
	CORE_SECURITY_EVENT_NETWORK_ANOMALY = 4,
	CORE_SECURITY_EVENT_FILE_INTEGRITY = 5,
	CORE_SECURITY_EVENT_MEMORY_ANOMALY = 6,
	CORE_SECURITY_EVENT_KERNEL_EXPLOIT = 7,
	CORE_SECURITY_EVENT_DDOS_ATTACK = 8,
	CORE_SECURITY_EVENT_LATERAL_MOVEMENT = 9,
	CORE_SECURITY_EVENT_DATA_EXFILTRATION = 10,
	CORE_SECURITY_EVENT_C2_COMMUNICATION = 11,
	CORE_SECURITY_EVENT_VULNERABILITY_EXPLOIT = 12,
};

/**
 * Security severity levels
 */
enum core_security_severity {
	CORE_SECURITY_SEVERITY_LOW = 1,
	CORE_SECURITY_SEVERITY_MEDIUM = 2,
	CORE_SECURITY_SEVERITY_HIGH = 3,
	CORE_SECURITY_SEVERITY_CRITICAL = 4,
};

/**
 * struct core_security_event - Security event structure
 * @timestamp_ns: Event timestamp in nanoseconds
 * @event_type: Type of security event
 * @severity: Event severity level
 * @pid: Process ID
 * @tgid: Thread group ID
 * @uid: User ID
 * @gid: Group ID
 * @comm: Process command name
 * @process_path: Full path to process
 * @src_ip: Source IP address
 * @dst_ip: Destination IP address
 * @src_port: Source port
 * @dst_port: Destination port
 * @protocol: Network protocol
 * @bytes_transferred: Number of bytes transferred
 * @filename: Associated filename
 * @file_inode: File inode number
 * @file_mode: File mode
 * @attack_count: Number of attack attempts
 * @time_window_sec: Time window in seconds
 * @confidence_score: Confidence score (0-100)
 * @user_agent: User agent string
 * @command_line: Command line arguments
 * @parent_pid: Parent process ID
 * @session_id: Session ID
 * @memory_usage: Memory usage in bytes
 * @cpu_usage: CPU usage percentage
 * @file_descriptors: Number of file descriptors
 */
struct core_security_event {
	uint64_t timestamp_ns;
	uint32_t event_type;
	uint32_t severity;
	uint32_t pid;
	uint32_t tgid;
	uint32_t uid;
	uint32_t gid;
	char comm[16];
	char process_path[256];
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint32_t bytes_transferred;
	char filename[256];
	uint32_t file_inode;
	uint32_t file_mode;
	uint32_t attack_count;
	uint32_t time_window_sec;
	uint32_t confidence_score;
	char user_agent[128];
	char command_line[512];
	uint32_t parent_pid;
	uint32_t session_id;
	uint64_t memory_usage;
	uint32_t cpu_usage;
	uint32_t file_descriptors;
};

/**
 * Core security program configuration
 */
struct core_security_config {
	int monitor_privilege_escalation;
	int monitor_suspicious_processes;
	int monitor_malware;
	int monitor_network_anomalies;
	int monitor_file_integrity;
	int monitor_memory_anomalies;
	int monitor_kernel_exploits;
	int monitor_ddos_attacks;
	int monitor_lateral_movement;
	int monitor_data_exfiltration;
	int monitor_c2_communication;
	int monitor_vulnerability_exploits;
	uint32_t confidence_threshold;
	uint32_t time_window_seconds;
};

/**
 * core_security_program_load() - Load security eBPF program
 * @config: Program configuration
 *
 * Load the security eBPF program with the given configuration.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_security_program_load(const struct core_security_config *config);

/**
 * core_security_program_attach() - Attach security eBPF program
 *
 * Attach the security eBPF program to kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_security_program_attach(void);

/**
 * core_security_program_detach() - Detach security eBPF program
 *
 * Detach the security eBPF program from kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_security_program_detach(void);

/**
 * core_security_get_ring_buffer() - Get security ring buffer
 *
 * Get the ring buffer for security events.
 *
 * Return: Pointer to ring buffer on success, NULL on failure
 */
void *core_security_get_ring_buffer(void);

#endif /* _ravn_CORE_SECURITY_IF_H */
