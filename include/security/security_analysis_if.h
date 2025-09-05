/* SPDX-License-Identifier: MIT */
/*
 * Security Analysis Interface
 * 
 * This file defines the interface for security analysis with CRUD operations
 * and proper function naming conventions.
 *
 * Author: Guy Davidi
 * Date: 2025
 */

#ifndef _RAVN_SECURITY_ANALYSIS_IF_H
#define _RAVN_SECURITY_ANALYSIS_IF_H

#include <stddef.h>
#include <stdint.h>

/* Forward declarations */
struct security_analysis;
struct security_analysis_config;
struct security_analysis_status;
struct security_analysis_updates;
struct security_analysis_result;
struct security_event;

/**
 * Security analysis states
 */
enum security_analysis_state {
	SECURITY_ANALYSIS_STATE_CREATED = 1,
	SECURITY_ANALYSIS_STATE_READY = 2,
	SECURITY_ANALYSIS_STATE_DELETED = 3,
};

/**
 * Security event types
 */
enum security_event_type {
	SECURITY_EVENT_PRIVILEGE_ESCALATION = 1,
	SECURITY_EVENT_SUSPICIOUS_PROCESS = 2,
	SECURITY_EVENT_MALWARE_DETECTION = 3,
	SECURITY_EVENT_NETWORK_ANOMALY = 4,
	SECURITY_EVENT_FILE_INTEGRITY = 5,
	SECURITY_EVENT_MEMORY_ANOMALY = 6,
	SECURITY_EVENT_KERNEL_EXPLOIT = 7,
	SECURITY_EVENT_DDOS_ATTACK = 8,
	SECURITY_EVENT_LATERAL_MOVEMENT = 9,
	SECURITY_EVENT_DATA_EXFILTRATION = 10,
	SECURITY_EVENT_C2_COMMUNICATION = 11,
	SECURITY_EVENT_VULNERABILITY_EXPLOIT = 12,
};

/**
 * Security severity levels
 */
enum security_severity {
	SECURITY_SEVERITY_LOW = 1,
	SECURITY_SEVERITY_MEDIUM = 2,
	SECURITY_SEVERITY_HIGH = 3,
	SECURITY_SEVERITY_CRITICAL = 4,
};

/**
 * Security threat levels
 */
enum security_threat_level {
	SECURITY_THREAT_LOW = 1,
	SECURITY_THREAT_MEDIUM = 2,
	SECURITY_THREAT_HIGH = 3,
	SECURITY_THREAT_CRITICAL = 4,
};

/**
 * struct security_event - Security event structure
 * @id: Event ID
 * @timestamp_ns: Event timestamp in nanoseconds
 * @event_type: Type of security event
 * @severity: Event severity level
 * @pid: Process ID
 * @uid: User ID
 * @gid: Group ID
 * @comm: Process command name
 * @filename: Associated filename
 */
struct security_event {
	int id;
	uint64_t timestamp_ns;
	enum security_event_type event_type;
	enum security_severity severity;
	uint32_t pid;
	uint32_t uid;
	uint32_t gid;
	char comm[16];
	char filename[256];
};

/**
 * struct security_analysis_config - Security analysis configuration
 * @threat_threshold: Threat detection threshold (0-100)
 * @anomaly_threshold: Anomaly detection threshold (0-10)
 * @time_window_seconds: Analysis time window
 * @enabled: Whether analysis is enabled
 */
struct security_analysis_config {
	double threat_threshold;
	double anomaly_threshold;
	uint32_t time_window_seconds;
	int enabled;
};

/**
 * struct security_analysis_updates - Security analysis configuration updates
 * @threat_threshold: New threat threshold (-1 = no change)
 * @anomaly_threshold: New anomaly threshold (-1 = no change)
 * @time_window_seconds: New time window (0 = no change)
 * @enabled: New enabled state (-1 = no change)
 */
struct security_analysis_updates {
	double threat_threshold;
	double anomaly_threshold;
	uint32_t time_window_seconds;
	int enabled;
};

/**
 * struct security_analysis_stats - Security analysis statistics
 * @total_events: Total events analyzed
 * @threats_detected: Number of threats detected
 * @anomalies_detected: Number of anomalies detected
 * @last_analysis_time: Timestamp of last analysis
 */
struct security_analysis_stats {
	uint64_t total_events;
	uint64_t threats_detected;
	uint64_t anomalies_detected;
	time_t last_analysis_time;
};

/**
 * struct security_analysis_status - Security analysis status
 * @state: Current analysis state
 * @enabled: Whether analysis is enabled
 * @threat_threshold: Current threat threshold
 * @anomaly_threshold: Current anomaly threshold
 * @time_window_seconds: Current time window
 * @stats: Analysis statistics
 */
struct security_analysis_status {
	enum security_analysis_state state;
	int enabled;
	double threat_threshold;
	double anomaly_threshold;
	uint32_t time_window_seconds;
	struct security_analysis_stats stats;
};

/**
 * struct security_analysis_result - Security analysis result
 * @timestamp_ns: Analysis timestamp
 * @event_id: ID of analyzed event
 * @threat_score: Calculated threat score (0-100)
 * @anomaly_score: Calculated anomaly score (0-10)
 * @is_threat: Whether event is a threat
 * @is_anomaly: Whether event is anomalous
 * @threat_level: Threat level classification
 * @recommendations: Array of security recommendations
 * @recommendation_count: Number of recommendations
 */
struct security_analysis_result {
	uint64_t timestamp_ns;
	int event_id;
	double threat_score;
	double anomaly_score;
	int is_threat;
	int is_anomaly;
	enum security_threat_level threat_level;
	char recommendations[10][256]; /* Up to 10 recommendations */
	uint32_t recommendation_count;
};

/**
 * struct security_analysis - Security analysis structure
 * @state: Current analysis state
 * @config: Analysis configuration
 * @stats: Analysis statistics
 */
struct security_analysis {
	enum security_analysis_state state;
	struct security_analysis_config config;
	struct security_analysis_stats stats;
};

/**
 * security_analysis_create() - Create/initialize security analysis engine
 * @analysis: Pointer to security analysis structure
 * @config: Analysis configuration
 *
 * Initialize the security analysis engine with the given configuration.
 *
 * Return: 0 on success, negative error code on failure
 */
int security_analysis_create(struct security_analysis *analysis, const struct security_analysis_config *config);

/**
 * security_analysis_read() - Read security analysis status and results
 * @analysis: Pointer to security analysis structure
 * @status: Pointer to store status information
 *
 * Read the current status and statistics of the security analysis engine.
 *
 * Return: 0 on success, negative error code on failure
 */
int security_analysis_read(const struct security_analysis *analysis, struct security_analysis_status *status);

/**
 * security_analysis_update() - Update security analysis configuration
 * @analysis: Pointer to security analysis structure
 * @updates: Configuration updates
 *
 * Update the configuration of the security analysis engine.
 *
 * Return: 0 on success, negative error code on failure
 */
int security_analysis_update(struct security_analysis *analysis, const struct security_analysis_updates *updates);

/**
 * security_analysis_delete() - Delete/cleanup security analysis engine
 * @analysis: Pointer to security analysis structure
 *
 * Cleanup and delete the security analysis engine.
 *
 * Return: 0 on success, negative error code on failure
 */
int security_analysis_delete(struct security_analysis *analysis);

/**
 * security_analysis_analyze() - Analyze event for security threats
 * @analysis: Pointer to security analysis structure
 * @event: Event to analyze
 * @result: Pointer to store analysis result
 *
 * Analyze an event for potential security threats and anomalies.
 *
 * Return: 0 on success, negative error code on failure
 */
int security_analysis_analyze(struct security_analysis *analysis, const struct security_event *event,
			     struct security_analysis_result *result);

#endif /* _RAVN_SECURITY_ANALYSIS_IF_H */
