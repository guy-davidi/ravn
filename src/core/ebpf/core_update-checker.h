/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CORE_UPDATE_CHECKER_H
#define __CORE_UPDATE_CHECKER_H

#include "compat/linux/types.h"

/* Update event types */
enum update_event_type {
	UPDATE_PACKAGE_MANAGER = 1,
	UPDATE_SYSTEM_UPDATE = 2,
	UPDATE_FIREWALL_UPDATE = 3,
	UPDATE_KERNEL_UPDATE = 4,
	UPDATE_FIRMWARE_UPDATE = 5,
	UPDATE_THIRD_PARTY_UPDATE = 6,
	UPDATE_SECURITY_UPDATE = 7,
	UPDATE_AUTOMATIC_UPDATE = 8,
	UPDATE_MANUAL_UPDATE = 9,
};

/* Update status */
enum update_status {
	UPDATE_STATUS_PENDING = 1,
	UPDATE_STATUS_IN_PROGRESS = 2,
	UPDATE_STATUS_COMPLETED = 3,
	UPDATE_STATUS_FAILED = 4,
	UPDATE_STATUS_ROLLBACK = 5,
};

/* Update event structure */
struct update_event {
	__u64 timestamp_ns;
	__u32 event_type;
	__u32 status;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 gid;
	char comm[16];
	char process_path[256];
	
	/* Update specific data */
	char package_name[128];
	char old_version[32];
	char new_version[32];
	char update_source[64];
	__u32 update_size;
	__u32 security_update;
	__u32 critical_update;
	
	/* System information */
	char hostname[64];
	char os_version[64];
	char kernel_version[32];
	__u32 system_uptime;
	
	/* Network information */
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	
	/* Additional context */
	char command_line[512];
	__u32 parent_pid;
	__u32 session_id;
	__u32 exit_code;
	__u32 duration_ms;
};

/* Package manager activity */
struct package_manager_activity {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	char package_manager[32]; // apt, yum, dnf, pacman, etc.
	char operation[32]; // install, update, remove, upgrade
	char package_name[128];
	char version[32];
	__u32 success;
	__u32 exit_code;
	__u32 duration_ms;
};

/* System update detection */
struct system_update {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	char update_type[32]; // security, feature, bugfix
	char os_version[64];
	char kernel_version[32];
	__u32 update_count;
	__u32 security_count;
	__u32 critical_count;
	__u32 success;
	__u32 reboot_required;
};

/* Firewall update detection */
struct firewall_update {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	char firewall_type[32]; // iptables, ufw, firewalld, etc.
	char operation[32]; // add, remove, modify, reload
	__u32 rule_count;
	__u32 port_count;
	__u32 ip_count;
	__u32 success;
	__u32 duration_ms;
};

/* Kernel update detection */
struct kernel_update {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	char old_version[32];
	char new_version[32];
	char kernel_type[32]; // mainline, stable, lts, rt
	__u32 security_update;
	__u32 critical_update;
	__u32 success;
	__u32 reboot_required;
	__u32 modules_updated;
};

/* Firmware update detection */
struct firmware_update {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	char device_name[64];
	char old_version[32];
	char new_version[32];
	char firmware_type[32]; // bios, uefi, device
	__u32 success;
	__u32 reboot_required;
	__u32 duration_ms;
};

/* Third-party update detection */
struct third_party_update {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	char application_name[128];
	char old_version[32];
	char new_version[32];
	char update_source[64];
	__u32 security_update;
	__u32 critical_update;
	__u32 success;
	__u32 automatic_update;
};

/* Security update detection */
struct security_update {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	char package_name[128];
	char cve_id[32];
	char severity[16]; // low, medium, high, critical
	__u32 exploit_available;
	__u32 patch_available;
	__u32 success;
	__u32 reboot_required;
	__u32 system_restart_required;
};

/* Automatic update detection */
struct automatic_update {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	char update_type[32]; // security, feature, bugfix
	char package_name[128];
	char version[32];
	__u32 scheduled_time;
	__u32 success;
	__u32 user_notified;
	__u32 user_approved;
};

/* Manual update detection */
struct manual_update {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 uid;
	char comm[16];
	char update_type[32]; // security, feature, bugfix
	char package_name[128];
	char version[32];
	char command_line[512];
	__u32 success;
	__u32 duration_ms;
	__u32 exit_code;
};

#endif /* __CORE_UPDATE_CHECKER_H */
