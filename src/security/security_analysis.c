/* SPDX-License-Identifier: MIT */
/*
 * Security Analysis Layer with CRUD Operations
 * 
 * This file implements security analysis with clear CRUD operations
 * and proper function naming conventions.
 *
 * Author: Guy Davidi
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <time.h>

#include "security/security_analysis_if.h"

/* Forward declarations */
static double calculate_threat_score(const struct security_event *event);
static double calculate_anomaly_score(const struct security_event *event);
static void generate_recommendations(const struct security_event *event, struct security_analysis_result *result);

/**
 * security_analysis_create() - Create/initialize security analysis engine
 * @analysis: Pointer to security analysis structure
 * @config: Analysis configuration
 *
 * Initialize the security analysis engine with the given configuration.
 *
 * Return: 0 on success, negative error code on failure
 */
int security_analysis_create(struct security_analysis *analysis, const struct security_analysis_config *config)
{
	if (!analysis) {
		return -EINVAL;
	}

	/* Initialize analysis structure */
	memset(analysis, 0, sizeof(*analysis));
	analysis->state = SECURITY_ANALYSIS_STATE_CREATED;

	/* Set configuration */
	if (config) {
		analysis->config = *config;
	} else {
		/* Default configuration */
		analysis->config.threat_threshold = 70.0;
		analysis->config.anomaly_threshold = 2.0;
		analysis->config.time_window_seconds = 60;
		analysis->config.enabled = 1;
	}

	/* Initialize statistics */
	analysis->stats.total_events = 0;
	analysis->stats.threats_detected = 0;
	analysis->stats.anomalies_detected = 0;
	analysis->stats.last_analysis_time = 0;

	analysis->state = SECURITY_ANALYSIS_STATE_READY;

	printf("[INFO] Security analysis created\n");
	return 0;
}

/**
 * security_analysis_read() - Read security analysis status and results
 * @analysis: Pointer to security analysis structure
 * @status: Pointer to store status information
 *
 * Read the current status and statistics of the security analysis engine.
 *
 * Return: 0 on success, negative error code on failure
 */
int security_analysis_read(const struct security_analysis *analysis, struct security_analysis_status *status)
{
	if (!analysis || !status) {
		return -EINVAL;
	}

	/* Copy status information */
	status->state = analysis->state;
	status->enabled = analysis->config.enabled;
	status->threat_threshold = analysis->config.threat_threshold;
	status->anomaly_threshold = analysis->config.anomaly_threshold;
	status->time_window_seconds = analysis->config.time_window_seconds;

	/* Copy statistics */
	status->stats = analysis->stats;

	return 0;
}

/**
 * security_analysis_update() - Update security analysis configuration
 * @analysis: Pointer to security analysis structure
 * @updates: Configuration updates
 *
 * Update the configuration of the security analysis engine.
 *
 * Return: 0 on success, negative error code on failure
 */
int security_analysis_update(struct security_analysis *analysis, const struct security_analysis_updates *updates)
{
	if (!analysis || !updates) {
		return -EINVAL;
	}

	/* Update configuration */
	if (updates->threat_threshold >= 0.0) {
		analysis->config.threat_threshold = updates->threat_threshold;
	}

	if (updates->anomaly_threshold >= 0.0) {
		analysis->config.anomaly_threshold = updates->anomaly_threshold;
	}

	if (updates->time_window_seconds > 0) {
		analysis->config.time_window_seconds = updates->time_window_seconds;
	}

	if (updates->enabled >= 0) {
		analysis->config.enabled = updates->enabled;
	}

	printf("[INFO] Security analysis updated\n");
	return 0;
}

/**
 * security_analysis_delete() - Delete/cleanup security analysis engine
 * @analysis: Pointer to security analysis structure
 *
 * Cleanup and delete the security analysis engine.
 *
 * Return: 0 on success, negative error code on failure
 */
int security_analysis_delete(struct security_analysis *analysis)
{
	if (!analysis) {
		return -EINVAL;
	}

	/* Reset state */
	analysis->state = SECURITY_ANALYSIS_STATE_DELETED;

	/* Clear statistics */
	memset(&analysis->stats, 0, sizeof(analysis->stats));

	printf("[INFO] Security analysis deleted\n");
	return 0;
}

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
			     struct security_analysis_result *result)
{
	double threat_score = 0.0;
	double anomaly_score = 0.0;
	int is_threat = 0;
	int is_anomaly = 0;

	if (!analysis || !event || !result) {
		return -EINVAL;
	}

	if (analysis->state != SECURITY_ANALYSIS_STATE_READY || !analysis->config.enabled) {
		return -EINVAL;
	}

	/* Initialize result */
	memset(result, 0, sizeof(*result));
	result->timestamp_ns = event->timestamp_ns;
	result->event_id = event->id;

	/* Calculate threat score */
	threat_score = calculate_threat_score(event);
	result->threat_score = threat_score;

	/* Calculate anomaly score */
	anomaly_score = calculate_anomaly_score(event);
	result->anomaly_score = anomaly_score;

	/* Determine if event is a threat */
	if (threat_score >= analysis->config.threat_threshold) {
		is_threat = 1;
		result->is_threat = 1;
		
		/* Determine threat level */
		if (threat_score >= 90.0) {
			result->threat_level = SECURITY_THREAT_CRITICAL;
		} else if (threat_score >= 80.0) {
			result->threat_level = SECURITY_THREAT_HIGH;
		} else if (threat_score >= 70.0) {
			result->threat_level = SECURITY_THREAT_MEDIUM;
		} else {
			result->threat_level = SECURITY_THREAT_LOW;
		}
	}

	/* Determine if event is anomalous */
	if (anomaly_score >= analysis->config.anomaly_threshold) {
		is_anomaly = 1;
		result->is_anomaly = 1;
	}

	/* Generate recommendations */
	generate_recommendations(event, result);

	/* Update statistics */
	analysis->stats.total_events++;
	if (is_threat) {
		analysis->stats.threats_detected++;
	}
	if (is_anomaly) {
		analysis->stats.anomalies_detected++;
	}
	analysis->stats.last_analysis_time = time(NULL);

	return 0;
}

/**
 * calculate_threat_score() - Calculate threat score for event
 * @event: Event to analyze
 *
 * Calculate a threat score based on event characteristics.
 *
 * Return: Threat score (0-100)
 */
static double calculate_threat_score(const struct security_event *event)
{
	double score = 0.0;

	/* Base score from event type */
	switch (event->event_type) {
	case SECURITY_EVENT_PRIVILEGE_ESCALATION:
		score += 80.0;
		break;
	case SECURITY_EVENT_SUSPICIOUS_PROCESS:
		score += 60.0;
		break;
	case SECURITY_EVENT_MALWARE_DETECTION:
		score += 90.0;
		break;
	case SECURITY_EVENT_NETWORK_ANOMALY:
		score += 50.0;
		break;
	case SECURITY_EVENT_FILE_INTEGRITY:
		score += 40.0;
		break;
	case SECURITY_EVENT_MEMORY_ANOMALY:
		score += 70.0;
		break;
	case SECURITY_EVENT_KERNEL_EXPLOIT:
		score += 95.0;
		break;
	case SECURITY_EVENT_DDOS_ATTACK:
		score += 85.0;
		break;
	case SECURITY_EVENT_LATERAL_MOVEMENT:
		score += 75.0;
		break;
	case SECURITY_EVENT_DATA_EXFILTRATION:
		score += 80.0;
		break;
	case SECURITY_EVENT_C2_COMMUNICATION:
		score += 90.0;
		break;
	case SECURITY_EVENT_VULNERABILITY_EXPLOIT:
		score += 85.0;
		break;
	default:
		score += 20.0;
		break;
	}

	/* Adjust based on severity */
	switch (event->severity) {
	case SECURITY_SEVERITY_CRITICAL:
		score += 20.0;
		break;
	case SECURITY_SEVERITY_HIGH:
		score += 15.0;
		break;
	case SECURITY_SEVERITY_MEDIUM:
		score += 10.0;
		break;
	case SECURITY_SEVERITY_LOW:
		score += 5.0;
		break;
	}

	/* Adjust based on process characteristics */
	if (event->uid == 0) { /* Root user */
		score += 10.0;
	}

	/* Check for suspicious process names */
	if (strstr(event->comm, "nc") || strstr(event->comm, "netcat") ||
	    strstr(event->comm, "nmap") || strstr(event->comm, "masscan")) {
		score += 15.0;
	}

	/* Check for suspicious file paths */
	if (strstr(event->filename, "/tmp/") || strstr(event->filename, "/dev/shm/")) {
		score += 10.0;
	}

	/* Cap the score at 100 */
	if (score > 100.0) {
		score = 100.0;
	}

	return score;
}

/**
 * calculate_anomaly_score() - Calculate anomaly score for event
 * @event: Event to analyze
 *
 * Calculate an anomaly score based on event patterns.
 *
 * Return: Anomaly score (0-10)
 */
static double calculate_anomaly_score(const struct security_event *event)
{
	double score = 0.0;
	time_t current_time = time(NULL);
	struct tm *tm_info = localtime(&current_time);

	/* Time-based anomalies */
	if (tm_info->tm_hour < 6 || tm_info->tm_hour > 22) {
		score += 2.0; /* Activity outside normal hours */
	}

	if (tm_info->tm_wday == 0 || tm_info->tm_wday == 6) {
		score += 1.0; /* Weekend activity */
	}

	/* Process-based anomalies */
	if (event->uid == 0) {
		score += 1.0; /* Root activity */
	}

	/* File-based anomalies */
	if (strstr(event->filename, "passwd") || strstr(event->filename, "shadow")) {
		score += 3.0; /* Access to sensitive files */
	}

	/* Network-based anomalies */
	if (event->event_type == SECURITY_EVENT_NETWORK_ANOMALY) {
		score += 2.0;
	}

	return score;
}

/**
 * generate_recommendations() - Generate security recommendations
 * @event: Event that was analyzed
 * @result: Analysis result to update with recommendations
 *
 * Generate security recommendations based on the analysis.
 */
static void generate_recommendations(const struct security_event *event, struct security_analysis_result *result)
{
	/* Initialize recommendations */
	result->recommendation_count = 0;

	/* Generate recommendations based on threat level */
	if (result->is_threat) {
		switch (result->threat_level) {
		case SECURITY_THREAT_CRITICAL:
			strcpy(result->recommendations[0], "IMMEDIATE: Block process and investigate");
			strcpy(result->recommendations[1], "Alert security team immediately");
			strcpy(result->recommendations[2], "Isolate affected system");
			strcpy(result->recommendations[3], "Review system logs for related activity");
			result->recommendation_count = 4;
			break;
		case SECURITY_THREAT_HIGH:
			strcpy(result->recommendations[0], "Monitor process closely");
			strcpy(result->recommendations[1], "Review system logs");
			strcpy(result->recommendations[2], "Consider blocking if pattern continues");
			result->recommendation_count = 3;
			break;
		case SECURITY_THREAT_MEDIUM:
			strcpy(result->recommendations[0], "Log for future analysis");
			strcpy(result->recommendations[1], "Monitor for similar patterns");
			result->recommendation_count = 2;
			break;
		case SECURITY_THREAT_LOW:
			strcpy(result->recommendations[0], "Continue monitoring");
			result->recommendation_count = 1;
			break;
		}
	}

	/* Add specific recommendations based on event type */
	if (event->event_type == SECURITY_EVENT_VULNERABILITY_EXPLOIT) {
		strcpy(result->recommendations[result->recommendation_count], 
		       "Apply security patches immediately");
		result->recommendation_count++;
	}

	if (event->event_type == SECURITY_EVENT_NETWORK_ANOMALY) {
		strcpy(result->recommendations[result->recommendation_count], 
		       "Review network firewall rules");
		result->recommendation_count++;
	}
}
