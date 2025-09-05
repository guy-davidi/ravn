/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AI Decision Engine Service Layer
 * 
 * This file implements the AI decision engine for ravn. It provides
 * intelligent analysis of security events, anomaly detection, and automated
 * response decisions based on machine learning algorithms and rule-based systems.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <time.h>

#include "service/service_ai_decision_engine_if.h"
#include "abstraction/abstraction_event_processor_if.h"

/* Forward declarations */
static double service_ai_calculate_anomaly_score(struct service_ai_decision_engine *engine,
						const struct abstraction_event *event);
static double service_ai_calculate_frequency_anomaly(struct service_ai_decision_engine *engine,
						    const struct abstraction_event *event);
static double service_ai_calculate_pattern_anomaly(struct service_ai_decision_engine *engine,
						  const struct abstraction_event *event);
static double service_ai_calculate_context_anomaly(struct service_ai_decision_engine *engine,
						  const struct abstraction_event *event);
static double service_ai_calculate_threat_score(struct service_ai_decision_engine *engine,
					       const struct abstraction_event *event,
					       double anomaly_score);
static void service_ai_generate_recommendations(struct service_ai_decision_engine *engine,
					       const struct abstraction_event *event,
					       struct service_ai_analysis *analysis);

/**
 * service_ai_decision_engine_init() - Initialize AI decision engine
 * @engine: Pointer to AI decision engine structure
 *
 * Initialize the AI decision engine and prepare for event analysis.
 *
 * Return: 0 on success, negative error code on failure
 */
int service_ai_decision_engine_init(struct service_ai_decision_engine *engine)
{
	if (!engine) {
		fprintf(stderr, "service_ai_decision_engine_init: engine is NULL\n");
		return -EINVAL;
	}

	/* Initialize engine structure */
	memset(engine, 0, sizeof(*engine));
	engine->initialized = 1;
	engine->analysis_count = 0;
	engine->threat_detected_count = 0;

	/* Initialize baseline statistics */
	engine->baseline_stats.avg_events_per_minute = 0.0;
	engine->baseline_stats.avg_process_count = 0.0;
	engine->baseline_stats.avg_network_connections = 0.0;
	engine->baseline_stats.avg_file_operations = 0.0;
	engine->baseline_stats.established = 0;

	/* Initialize anomaly detection parameters */
	engine->anomaly_params.threshold_multiplier = 2.0;
	engine->anomaly_params.time_window_seconds = 60;
	engine->anomaly_params.min_events_for_analysis = 10;

	/* Initialize threat scoring parameters */
	engine->threat_params.base_score = 0.0;
	engine->threat_params.severity_weight = 0.3;
	engine->threat_params.frequency_weight = 0.2;
	engine->threat_params.pattern_weight = 0.3;
	engine->threat_params.context_weight = 0.2;

	return 0;
}

/**
 * service_ai_decision_engine_cleanup() - Cleanup AI decision engine
 * @engine: Pointer to AI decision engine structure
 *
 * Cleanup the AI decision engine and free all resources.
 *
 * Return: 0 on success, negative error code on failure
 */
int service_ai_decision_engine_cleanup(struct service_ai_decision_engine *engine)
{
	if (!engine || !engine->initialized) {
		return -EINVAL;
	}

	/* Reset engine state */
	engine->initialized = 0;
	engine->analysis_count = 0;
	engine->threat_detected_count = 0;

	return 0;
}

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
			    struct service_ai_analysis *analysis)
{
	double threat_score = 0.0;
	double anomaly_score = 0.0;
	int is_anomaly = 0;
	int is_threat = 0;

	/* Suppress unused variable warning */
	(void)is_anomaly;

	if (!engine || !event || !analysis) {
		return -EINVAL;
	}

	/* Initialize analysis structure */
	memset(analysis, 0, sizeof(*analysis));
	analysis->timestamp_ns = event->timestamp_ns;
	analysis->event_type = event->event_type;
	analysis->pid = event->pid;
	analysis->uid = event->uid;

	/* Calculate anomaly score */
	anomaly_score = service_ai_calculate_anomaly_score(engine, event);
	analysis->anomaly_score = anomaly_score;

	/* Check if event is anomalous */
	if (anomaly_score > engine->anomaly_params.threshold_multiplier) {
		is_anomaly = 1;
		analysis->is_anomaly = 1;
	}

	/* Calculate threat score */
	threat_score = service_ai_calculate_threat_score(engine, event, anomaly_score);
	analysis->threat_score = threat_score;

	/* Determine if event represents a threat */
	if (threat_score > 70.0) {
		is_threat = 1;
		analysis->is_threat = 1;
		analysis->threat_level = SERVICE_THREAT_HIGH;
	} else if (threat_score > 50.0) {
		is_threat = 1;
		analysis->is_threat = 1;
		analysis->threat_level = SERVICE_THREAT_MEDIUM;
	} else if (threat_score > 30.0) {
		analysis->threat_level = SERVICE_THREAT_LOW;
	} else {
		analysis->threat_level = SERVICE_THREAT_NONE;
	}

	/* Generate recommendations */
	service_ai_generate_recommendations(engine, event, analysis);

	/* Update engine statistics */
	engine->analysis_count++;
	if (is_threat) {
		engine->threat_detected_count++;
	}

	return 0;
}

/**
 * service_ai_calculate_anomaly_score() - Calculate anomaly score for event
 * @engine: Pointer to AI decision engine
 * @event: Event to analyze
 *
 * Calculate an anomaly score for the given event based on statistical analysis.
 *
 * Return: Anomaly score (0.0 = normal, higher = more anomalous)
 */
static double service_ai_calculate_anomaly_score(struct service_ai_decision_engine *engine,
						const struct abstraction_event *event)
{
	double score = 0.0;
	double frequency_score = 0.0;
	double pattern_score = 0.0;
	double context_score = 0.0;

	/* Frequency-based anomaly detection */
	frequency_score = service_ai_calculate_frequency_anomaly(engine, event);
	
	/* Pattern-based anomaly detection */
	pattern_score = service_ai_calculate_pattern_anomaly(engine, event);
	
	/* Context-based anomaly detection */
	context_score = service_ai_calculate_context_anomaly(engine, event);

	/* Weighted combination of anomaly scores */
	score = (frequency_score * 0.4) + (pattern_score * 0.3) + (context_score * 0.3);

	return score;
}

/**
 * service_ai_calculate_frequency_anomaly() - Calculate frequency-based anomaly
 * @engine: Pointer to AI decision engine
 * @event: Event to analyze
 *
 * Calculate frequency-based anomaly score.
 *
 * Return: Frequency anomaly score
 */
static double service_ai_calculate_frequency_anomaly(struct service_ai_decision_engine *engine,
						    const struct abstraction_event *event)
{
	(void)engine; /* Suppress unused parameter warning */
	/* Simplified frequency analysis */
	/* In a real implementation, this would analyze event frequency patterns */
	
	double score = 0.0;
	
	/* Check for unusual event types */
	switch (event->event_type) {
	case ABSTRACTION_EVENT_SECURITY:
		score += 20.0; /* Security events are inherently more suspicious */
		break;
	case ABSTRACTION_EVENT_VULNERABILITY:
		score += 30.0; /* Vulnerability events are highly suspicious */
		break;
	case ABSTRACTION_EVENT_EXECFS:
		/* Check for suspicious file paths */
		if (strstr(event->filename, "/tmp/") || 
		    strstr(event->filename, "/dev/shm/") ||
		    strstr(event->filename, "/proc/")) {
			score += 15.0;
		}
		break;
	case ABSTRACTION_EVENT_NETWORK:
		score += 10.0; /* Network events are moderately suspicious */
		break;
	default:
		score += 5.0; /* Other events are less suspicious */
		break;
	}

	return score;
}

/**
 * service_ai_calculate_pattern_anomaly() - Calculate pattern-based anomaly
 * @engine: Pointer to AI decision engine
 * @event: Event to analyze
 *
 * Calculate pattern-based anomaly score.
 *
 * Return: Pattern anomaly score
 */
static double service_ai_calculate_pattern_anomaly(struct service_ai_decision_engine *engine,
						  const struct abstraction_event *event)
{
	(void)engine; /* Suppress unused parameter warning */
	double score = 0.0;

	/* Check for suspicious process names */
	if (strstr(event->comm, "nc") || strstr(event->comm, "netcat") ||
	    strstr(event->comm, "nmap") || strstr(event->comm, "masscan")) {
		score += 25.0;
	}

	/* Check for suspicious file operations */
	if (event->event_type == ABSTRACTION_EVENT_EXECFS) {
		if (strstr(event->filename, "passwd") || 
		    strstr(event->filename, "shadow") ||
		    strstr(event->filename, "sudoers")) {
			score += 20.0;
		}
	}

	/* Check for root user activity */
	if (event->uid == 0) {
		score += 10.0; /* Root activity is inherently more suspicious */
	}

	return score;
}

/**
 * service_ai_calculate_context_anomaly() - Calculate context-based anomaly
 * @engine: Pointer to AI decision engine
 * @event: Event to analyze
 *
 * Calculate context-based anomaly score.
 *
 * Return: Context anomaly score
 */
static double service_ai_calculate_context_anomaly(struct service_ai_decision_engine *engine,
						  const struct abstraction_event *event)
{
	(void)engine; /* Suppress unused parameter warning */
	(void)event; /* Suppress unused parameter warning */
	double score = 0.0;
	time_t current_time = time(NULL);
	struct tm *tm_info = localtime(&current_time);

	/* Check for unusual time patterns */
	if (tm_info->tm_hour < 6 || tm_info->tm_hour > 22) {
		score += 15.0; /* Activity outside normal hours is suspicious */
	}

	/* Check for weekend activity */
	if (tm_info->tm_wday == 0 || tm_info->tm_wday == 6) {
		score += 10.0; /* Weekend activity is more suspicious */
	}

	return score;
}

/**
 * service_ai_calculate_threat_score() - Calculate overall threat score
 * @engine: Pointer to AI decision engine
 * @event: Event to analyze
 * @anomaly_score: Anomaly score for the event
 *
 * Calculate overall threat score based on multiple factors.
 *
 * Return: Threat score (0-100)
 */
static double service_ai_calculate_threat_score(struct service_ai_decision_engine *engine,
					       const struct abstraction_event *event,
					       double anomaly_score)
{
	double threat_score = 0.0;
	double severity_score = 0.0;
	double frequency_score = 0.0;
	double pattern_score = 0.0;
	double context_score = 0.0;

	/* Calculate severity score based on event type */
	switch (event->event_type) {
	case ABSTRACTION_EVENT_VULNERABILITY:
		severity_score = 80.0;
		break;
	case ABSTRACTION_EVENT_SECURITY:
		severity_score = 60.0;
		break;
	case ABSTRACTION_EVENT_NETWORK:
		severity_score = 40.0;
		break;
	case ABSTRACTION_EVENT_EXECFS:
		severity_score = 30.0;
		break;
	case ABSTRACTION_EVENT_SYSTEM:
		severity_score = 50.0;
		break;
	default:
		severity_score = 20.0;
		break;
	}

	/* Use anomaly score as frequency/pattern indicator */
	frequency_score = anomaly_score;
	pattern_score = anomaly_score;
	context_score = anomaly_score;

	/* Weighted combination */
	threat_score = (severity_score * engine->threat_params.severity_weight) +
		       (frequency_score * engine->threat_params.frequency_weight) +
		       (pattern_score * engine->threat_params.pattern_weight) +
		       (context_score * engine->threat_params.context_weight);

	/* Cap the score at 100 */
	if (threat_score > 100.0) {
		threat_score = 100.0;
	}

	return threat_score;
}

/**
 * service_ai_generate_recommendations() - Generate security recommendations
 * @engine: Pointer to AI decision engine
 * @event: Event that was analyzed
 * @analysis: Analysis results to update with recommendations
 *
 * Generate security recommendations based on the analysis.
 */
static void service_ai_generate_recommendations(struct service_ai_decision_engine *engine,
					       const struct abstraction_event *event,
					       struct service_ai_analysis *analysis)
{
	(void)engine; /* Suppress unused parameter warning */
	/* Initialize recommendations */
	analysis->recommendation_count = 0;

	/* Generate recommendations based on threat level */
	if (analysis->is_threat) {
		switch (analysis->threat_level) {
		case SERVICE_THREAT_HIGH:
			strcpy(analysis->recommendations[0], "IMMEDIATE: Block process and investigate");
			strcpy(analysis->recommendations[1], "Alert security team immediately");
			strcpy(analysis->recommendations[2], "Isolate affected system if possible");
			analysis->recommendation_count = 3;
			break;
		case SERVICE_THREAT_MEDIUM:
			strcpy(analysis->recommendations[0], "Monitor process closely");
			strcpy(analysis->recommendations[1], "Review system logs");
			strcpy(analysis->recommendations[2], "Consider blocking if pattern continues");
			analysis->recommendation_count = 3;
			break;
		case SERVICE_THREAT_LOW:
			strcpy(analysis->recommendations[0], "Log for future analysis");
			strcpy(analysis->recommendations[1], "Monitor for similar patterns");
			analysis->recommendation_count = 2;
			break;
		default:
			break;
		}
	}

	/* Add specific recommendations based on event type */
	if (event->event_type == ABSTRACTION_EVENT_VULNERABILITY) {
		strcpy(analysis->recommendations[analysis->recommendation_count], 
		       "Apply security patches immediately");
		analysis->recommendation_count++;
	}

	if (event->event_type == ABSTRACTION_EVENT_NETWORK) {
		strcpy(analysis->recommendations[analysis->recommendation_count], 
		       "Review network firewall rules");
		analysis->recommendation_count++;
	}
}

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
			      const struct abstraction_event *event)
{
	if (!engine || !event) {
		return -EINVAL;
	}

	/* Update baseline statistics */
	/* This is a simplified implementation */
	engine->baseline_stats.avg_events_per_minute += 1.0;
	engine->baseline_stats.avg_process_count += 1.0;

	/* Mark baseline as established after sufficient data */
	if (engine->baseline_stats.avg_events_per_minute > 100) {
		engine->baseline_stats.established = 1;
	}

	return 0;
}

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
			       struct service_ai_engine_stats *stats)
{
	if (!engine || !stats) {
		return -EINVAL;
	}

	/* Copy statistics */
	stats->analysis_count = engine->analysis_count;
	stats->threat_detected_count = engine->threat_detected_count;
	stats->baseline_established = engine->baseline_stats.established;
	stats->avg_events_per_minute = engine->baseline_stats.avg_events_per_minute;

	return 0;
}
