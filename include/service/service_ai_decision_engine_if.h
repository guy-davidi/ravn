/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AI Decision Engine Service Layer Interface
 * 
 * This file defines the interface for the AI decision engine service layer.
 * It provides intelligent analysis of security events, anomaly detection,
 * and automated response decisions.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#ifndef _ravn_SERVICE_AI_DECISION_ENGINE_IF_H
#define _ravn_SERVICE_AI_DECISION_ENGINE_IF_H

#include <stddef.h>
#include <stdint.h>
#include "abstraction/abstraction_event_processor_if.h"

/* Forward declarations */
struct service_ai_decision_engine;
struct service_ai_analysis;
struct service_ai_engine_stats;

/**
 * Threat levels
 */
enum service_threat_level {
	SERVICE_THREAT_NONE = 0,
	SERVICE_THREAT_LOW = 1,
	SERVICE_THREAT_MEDIUM = 2,
	SERVICE_THREAT_HIGH = 3,
	SERVICE_THREAT_CRITICAL = 4,
};

/**
 * struct service_ai_analysis - AI analysis results
 * @timestamp_ns: Analysis timestamp
 * @event_type: Type of event analyzed
 * @pid: Process ID
 * @uid: User ID
 * @anomaly_score: Anomaly score (0-100)
 * @threat_score: Threat score (0-100)
 * @is_anomaly: Whether event is anomalous
 * @is_threat: Whether event represents a threat
 * @threat_level: Threat level classification
 * @recommendations: Array of security recommendations
 * @recommendation_count: Number of recommendations
 * @confidence: Analysis confidence (0-100)
 */
struct service_ai_analysis {
	uint64_t timestamp_ns;
	uint32_t event_type;
	uint32_t pid;
	uint32_t uid;
	double anomaly_score;
	double threat_score;
	int is_anomaly;
	int is_threat;
	enum service_threat_level threat_level;
	char recommendations[10][256]; /* Up to 10 recommendations */
	uint32_t recommendation_count;
	double confidence;
};

/**
 * struct service_ai_baseline_stats - Baseline statistics for anomaly detection
 * @avg_events_per_minute: Average events per minute
 * @avg_process_count: Average process count
 * @avg_network_connections: Average network connections
 * @avg_file_operations: Average file operations
 * @established: Whether baseline is established
 */
struct service_ai_baseline_stats {
	double avg_events_per_minute;
	double avg_process_count;
	double avg_network_connections;
	double avg_file_operations;
	int established;
};

/**
 * struct service_ai_anomaly_params - Anomaly detection parameters
 * @threshold_multiplier: Threshold multiplier for anomaly detection
 * @time_window_seconds: Time window for analysis
 * @min_events_for_analysis: Minimum events required for analysis
 */
struct service_ai_anomaly_params {
	double threshold_multiplier;
	uint32_t time_window_seconds;
	uint32_t min_events_for_analysis;
};

/**
 * struct service_ai_threat_params - Threat scoring parameters
 * @base_score: Base threat score
 * @severity_weight: Weight for severity factor
 * @frequency_weight: Weight for frequency factor
 * @pattern_weight: Weight for pattern factor
 * @context_weight: Weight for context factor
 */
struct service_ai_threat_params {
	double base_score;
	double severity_weight;
	double frequency_weight;
	double pattern_weight;
	double context_weight;
};

/**
 * struct service_ai_decision_engine - AI decision engine structure
 * @initialized: Whether the engine is initialized
 * @analysis_count: Total number of analyses performed
 * @threat_detected_count: Number of threats detected
 * @baseline_stats: Baseline statistics
 * @anomaly_params: Anomaly detection parameters
 * @threat_params: Threat scoring parameters
 */
struct service_ai_decision_engine {
	int initialized;
	uint64_t analysis_count;
	uint64_t threat_detected_count;
	struct service_ai_baseline_stats baseline_stats;
	struct service_ai_anomaly_params anomaly_params;
	struct service_ai_threat_params threat_params;
};

/**
 * struct service_ai_engine_stats - AI engine statistics
 * @analysis_count: Total analyses performed
 * @threat_detected_count: Threats detected
 * @baseline_established: Whether baseline is established
 * @avg_events_per_minute: Average events per minute
 */
struct service_ai_engine_stats {
	uint64_t analysis_count;
	uint64_t threat_detected_count;
	int baseline_established;
	double avg_events_per_minute;
};

/**
 * service_ai_decision_engine_init() - Initialize AI decision engine
 * @engine: Pointer to AI decision engine structure
 *
 * Initialize the AI decision engine and prepare for event analysis.
 *
 * Return: 0 on success, negative error code on failure
 */
int service_ai_decision_engine_init(struct service_ai_decision_engine *engine);

/**
 * service_ai_decision_engine_cleanup() - Cleanup AI decision engine
 * @engine: Pointer to AI decision engine structure
 *
 * Cleanup the AI decision engine and free all resources.
 *
 * Return: 0 on success, negative error code on failure
 */
int service_ai_decision_engine_cleanup(struct service_ai_decision_engine *engine);

/**
 * service_ai_analyze_event() - Analyze event for threats
 * @engine: Pointer to AI decision engine
 * @event: Event to analyze
 * @analysis: Pointer to store analysis results
 *
 * Analyze an event for potential security threats using AI algorithms.
 *
 * Return: 0 on success, negative error code on failure
 */
int service_ai_analyze_event(struct service_ai_decision_engine *engine,
			    const struct abstraction_event *event,
			    struct service_ai_analysis *analysis);

/**
 * service_ai_update_baseline() - Update baseline statistics
 * @engine: Pointer to AI decision engine
 * @event: Event to incorporate into baseline
 *
 * Update baseline statistics with new event data.
 *
 * Return: 0 on success, negative error code on failure
 */
int service_ai_update_baseline(struct service_ai_decision_engine *engine,
			      const struct abstraction_event *event);

/**
 * service_ai_get_engine_stats() - Get AI engine statistics
 * @engine: Pointer to AI decision engine
 * @stats: Pointer to store statistics
 *
 * Get current AI engine statistics.
 *
 * Return: 0 on success, negative error code on failure
 */
int service_ai_get_engine_stats(struct service_ai_decision_engine *engine,
			       struct service_ai_engine_stats *stats);

#endif /* _ravn_SERVICE_AI_DECISION_ENGINE_IF_H */
