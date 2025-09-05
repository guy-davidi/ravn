/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SECURITY_H
#define __SECURITY_H

#include "compat/linux/types.h"

/* Security event types */
enum security_event_type {
	SEC_PING_SWEEP = 1,
	SEC_PORT_SCAN = 2,
	SEC_BRUTE_FORCE = 3,
	SEC_PRIVILEGE_ESCALATION = 4,
	SEC_SUSPICIOUS_PROCESS = 5,
	SEC_MALWARE_DETECTION = 6,
	SEC_NETWORK_ANOMALY = 7,
	SEC_FILE_INTEGRITY = 8,
	SEC_MEMORY_ANOMALY = 9,
	SEC_KERNEL_EXPLOIT = 10,
	SEC_DDOS_ATTACK = 11,
	SEC_LATERAL_MOVEMENT = 12,
	SEC_DATA_EXFILTRATION = 13,
	SEC_C2_COMMUNICATION = 14,
	SEC_VULNERABILITY_EXPLOIT = 15,
};

/* Attack severity levels */
enum attack_severity {
	SEVERITY_LOW = 1,
	SEVERITY_MEDIUM = 2,
	SEVERITY_HIGH = 3,
	SEVERITY_CRITICAL = 4,
};

/* Security event structure */
struct security_event {
	__u64 timestamp_ns;
	__u32 event_type;
	__u32 severity;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 gid;
	char comm[16];
	char process_path[256];
	
	/* Network information */
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u32 bytes_transferred;
	
	/* File information */
	char filename[256];
	__u32 file_inode;
	__u32 file_mode;
	
	/* Attack specific data */
	__u32 attack_count;
	__u32 time_window_sec;
	__u32 confidence_score;
	
	/* Additional context */
	char user_agent[128];
	char command_line[512];
	__u32 parent_pid;
	__u32 session_id;
	
	/* Memory/process info */
	__u64 memory_usage;
	__u32 cpu_usage;
	__u32 file_descriptors;
};

/* Port scan detection structure */
struct port_scan_data {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 port;
	__u8 protocol;
	__u64 first_seen;
	__u64 last_seen;
	__u32 attempt_count;
	__u32 unique_ports;
};

/* Ping sweep detection structure */
struct ping_sweep_data {
	__u32 src_ip;
	__u32 dst_ip;
	__u64 first_ping;
	__u64 last_ping;
	__u32 ping_count;
	__u32 unique_targets;
};

/* Brute force detection structure */
struct brute_force_data {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 port;
	__u64 first_attempt;
	__u64 last_attempt;
	__u32 attempt_count;
	__u32 success_count;
};

/* Process anomaly detection */
struct process_anomaly {
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	char comm[16];
	char process_path[256];
	__u64 memory_usage;
	__u32 cpu_usage;
	__u32 network_connections;
	__u32 file_operations;
	__u32 anomaly_score;
};

/* Network anomaly detection */
struct network_anomaly {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 port;
	__u8 protocol;
	__u32 packet_count;
	__u32 byte_count;
	__u64 duration_ns;
	__u32 anomaly_type;
	__u32 severity;
};

/* File integrity monitoring */
struct file_integrity_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char filename[256];
	__u32 file_inode;
	__u32 old_mode;
	__u32 new_mode;
	__u64 old_size;
	__u64 new_size;
	__u32 operation; // 1=create, 2=modify, 3=delete, 4=permission_change
};

/* Memory anomaly detection */
struct memory_anomaly {
	__u32 pid;
	__u32 tgid;
	__u64 memory_usage;
	__u64 memory_limit;
	__u32 memory_growth_rate;
	__u32 anomaly_type; // 1=memory_leak, 2=memory_spike, 3=buffer_overflow
	__u32 severity;
};

/* Kernel exploit detection */
struct kernel_exploit_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	__u32 exploit_type; // 1=stack_overflow, 2=heap_overflow, 3=use_after_free, 4=double_free
	__u32 target_function;
	__u32 success;
	__u32 severity;
};

/* DDoS attack detection */
struct ddos_attack {
	__u32 target_ip;
	__u16 target_port;
	__u8 protocol;
	__u32 source_count;
	__u32 packet_count;
	__u32 byte_count;
	__u64 attack_duration;
	__u32 attack_type; // 1=syn_flood, 2=udp_flood, 3=icmp_flood, 4=application_ddos
	__u32 severity;
};

/* Lateral movement detection */
struct lateral_movement {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 port;
	__u8 protocol;
	__u32 credential_use;
	__u32 privilege_escalation;
	__u32 network_scanning;
	__u32 service_enumeration;
	__u32 confidence_score;
};

/* Data exfiltration detection */
struct data_exfiltration {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 port;
	__u8 protocol;
	__u64 data_size;
	__u32 file_count;
	__u32 transfer_rate;
	__u32 encryption_detected;
	__u32 confidence_score;
};

/* Command and control detection */
struct c2_communication {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 port;
	__u8 protocol;
	__u32 beacon_interval;
	__u32 data_size;
	__u32 encryption_detected;
	__u32 domain_generation;
	__u32 confidence_score;
};

/* Vulnerability exploit detection */
struct vulnerability_exploit {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	__u32 cve_id;
	__u32 exploit_type;
	__u32 target_service;
	__u32 success;
	__u32 severity;
};

#endif /* __SECURITY_H */
