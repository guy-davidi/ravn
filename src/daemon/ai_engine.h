/*
 * RAVN AI Engine - Header File
 *
 * This header defines the AI engine interface for the RAVN security platform,
 * providing AI-powered threat detection using sliding window analysis and
 * deep learning models for real-time security monitoring.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 *
 * The AI engine implements:
 * - Sliding window analysis for temporal pattern detection
 * - Deep learning model inference for threat scoring
 * - Real-time event sequence analysis
 * - Multi-threaded background processing
 *
 * Architecture:
 * - CNN + LSTM model for sequence analysis
 * - 10-second sliding window with 1-second intervals
 * - Real-time threat level calculation
 * - Background analysis thread for continuous monitoring
 */

#ifndef RAVN_AI_ENGINE_H
#define RAVN_AI_ENGINE_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>

/* Forward declaration */
struct ravn_event;

/*
 * AI Model Configuration Parameters
 */
#define WINDOW_SIZE_SECONDS 10		/* Sliding window duration in seconds */
#define SLIDE_INTERVAL_SECONDS 1	/* Window slide interval in seconds */
#define MAX_EVENTS_PER_WINDOW 1000	/* Maximum events per process in window */
#define MAX_PROCESSES 100		/* Maximum processes to track simultaneously */

/*
 * Threat Level Thresholds
 * These values define the boundaries for threat level classification
 */
#define THREAT_LEVEL_LOW 0.0		/* Normal system activity */
#define THREAT_LEVEL_MEDIUM 0.3		/* Suspicious activity detected */
#define THREAT_LEVEL_HIGH 0.7		/* High probability of attack */
#define THREAT_LEVEL_CRITICAL 0.9	/* Critical threat confirmed */

/**
 * struct event_sequence - Event sequence for a single process
 * @pid: Process ID
 * @event_count: Number of events in the sequence
 * @events: Array of event types in chronological order
 * @timestamps: Array of event timestamps (nanoseconds since epoch)
 * @threat_score: Calculated threat score for this sequence
 *
 * Represents a sequence of events from a single process within
 * the sliding window. Used for pattern analysis and threat detection.
 */
struct event_sequence {
	uint32_t pid;					/* Process ID */
	uint32_t event_count;				/* Number of events */
	uint32_t events[MAX_EVENTS_PER_WINDOW];	/* Event types array */
	uint64_t timestamps[MAX_EVENTS_PER_WINDOW];	/* Event timestamps */
	float threat_score;				/* Calculated threat score */
};

/**
 * struct sliding_window - Sliding window for temporal analysis
 * @start_time: Window start timestamp (nanoseconds)
 * @end_time: Window end timestamp (nanoseconds)
 * @processes: Array of process event sequences
 * @process_count: Number of active processes in window
 * @overall_threat_score: Overall threat score for the window
 * @threat_level: Human-readable threat level string
 * @threat_reason: Explanation of threat assessment
 *
 * Represents a time window containing event sequences from multiple
 * processes. Used for temporal pattern analysis and threat detection.
 */
struct sliding_window {
	uint64_t start_time;				/* Window start time */
	uint64_t end_time;				/* Window end time */
	struct event_sequence processes[MAX_PROCESSES];	/* Process sequences */
	int process_count;				/* Active process count */
	float overall_threat_score;			/* Overall threat score */
	char threat_level[16];				/* Threat level string */
	char threat_reason[256];			/* Threat reason */
};

/**
 * struct ai_engine - AI engine instance
 * @weights: Model weights for inference
 * @initialized: Initialization status flag
 * @model_path: Path to the AI model file
 * @window: Current sliding window instance
 * @analysis_thread: Background analysis thread handle
 * @thread_running: Thread running status flag
 * @should_stop: Thread stop request flag
 *
 * Main AI engine structure containing model data, configuration,
 * and thread management for background analysis.
 */
typedef struct ai_engine ai_engine_t;
struct ai_engine {
	float weights[100];				/* Model weights */
	int initialized;				/* Initialization flag */
	char model_path[256];				/* Model file path */
	struct sliding_window window;			/* Sliding window */
	pthread_t analysis_thread;			/* Analysis thread */
	int thread_running;				/* Thread status */
	int should_stop;				/* Stop request flag */
};

/*
 * AI Engine Core Functions
 */

/**
 * ai_engine_init - Initialize AI engine instance
 * @model_path: Path to the AI model file
 *
 * Allocates and initializes a new AI engine instance with the specified
 * model file. Loads model weights and initializes the sliding window.
 *
 * Return: Pointer to initialized AI engine, NULL on failure
 */
ai_engine_t *ai_engine_init(const char *model_path);

/**
 * ai_engine_cleanup - Cleanup AI engine instance
 * @engine: AI engine instance to cleanup
 *
 * Performs complete cleanup of the AI engine instance including
 * thread termination, resource deallocation, and memory cleanup.
 */
void ai_engine_cleanup(ai_engine_t *engine);

/**
 * ai_engine_start_analysis - Start AI analysis processing
 * @engine: AI engine instance
 *
 * Starts the AI analysis processing for the given engine instance.
 * This function prepares the engine for continuous analysis.
 *
 * Return: 0 on success, -1 on failure
 */
int ai_engine_start_analysis(ai_engine_t *engine);

/**
 * ai_engine_stop_analysis - Stop AI analysis processing
 * @engine: AI engine instance
 *
 * Stops the AI analysis processing and performs cleanup.
 */
void ai_engine_stop_analysis(ai_engine_t *engine);

/**
 * ai_engine_analyze_event - Analyze a single event
 * @engine: AI engine instance
 * @event: Event to analyze
 *
 * Analyzes a single event and returns a threat score.
 *
 * Return: Threat score (0.0 to 1.0), -1.0 on error
 */
float ai_engine_analyze_event(ai_engine_t *engine, const struct ravn_event *event);

/*
 * Thread Management Functions
 */

/**
 * ai_engine_start_thread - Start background analysis thread
 * @engine: AI engine instance
 *
 * Starts the background analysis thread for continuous processing.
 *
 * Return: 0 on success, -1 on failure
 */
int ai_engine_start_thread(ai_engine_t *engine);

/**
 * ai_engine_stop_thread - Stop background analysis thread
 * @engine: AI engine instance
 *
 * Stops the background analysis thread and waits for completion.
 */
void ai_engine_stop_thread(ai_engine_t *engine);

/**
 * ai_thread_func - Background analysis thread function
 * @arg: AI engine instance pointer
 *
 * Main function for the background analysis thread. Performs
 * continuous sliding window analysis and threat detection.
 *
 * Return: NULL (thread exit value)
 */
void *ai_thread_func(void *arg);

/*
 * Sliding Window Functions
 */

/**
 * sliding_window_init - Initialize sliding window
 * @window: Sliding window structure to initialize
 *
 * Initializes a sliding window structure with default values.
 *
 * Return: 0 on success, -1 on failure
 */
int sliding_window_init(struct sliding_window *window);

/**
 * sliding_window_update - Update sliding window with current time
 * @window: Sliding window structure
 * @current_time: Current timestamp in nanoseconds
 *
 * Updates the sliding window to the current time, removing
 * expired events and preparing for new analysis.
 *
 * Return: 0 on success, -1 on failure
 */
int sliding_window_update(struct sliding_window *window, uint64_t current_time);

/**
 * sliding_window_analyze - Analyze current sliding window
 * @window: Sliding window structure to analyze
 *
 * Performs threat analysis on the current sliding window
 * and updates threat scores and classifications.
 *
 * Return: 0 on success, -1 on failure
 */
int sliding_window_analyze(struct sliding_window *window);

/*
 * Event Processing Functions
 */

/**
 * ai_process_event - Process event JSON data
 * @event_json: JSON string containing event data
 *
 * Processes a JSON event string and updates the AI analysis.
 *
 * Return: 0 on success, -1 on failure
 */
int ai_process_event(const char *event_json);

/**
 * ai_analyze_sequence - Analyze event sequence
 * @sequence: Event sequence to analyze
 *
 * Analyzes an event sequence for threat patterns and updates
 * the threat score.
 *
 * Return: 0 on success, -1 on failure
 */
int ai_analyze_sequence(struct event_sequence *sequence);

/**
 * ai_calculate_threat_score - Calculate threat score for sequence
 * @sequence: Event sequence to score
 *
 * Calculates a threat score for the given event sequence
 * using the AI model.
 *
 * Return: Threat score (0.0 to 1.0), -1.0 on error
 */
float ai_calculate_threat_score(struct event_sequence *sequence);

/*
 * Model Functions
 */

/**
 * ai_load_model - Load AI model from file
 * @model_path: Path to model file
 *
 * Loads the AI model weights from the specified file.
 *
 * Return: 0 on success, -1 on failure
 */
int ai_load_model(const char *model_path);

/**
 * ai_predict - Make prediction using AI model
 * @features: Input feature vector
 * @feature_count: Number of features
 *
 * Makes a prediction using the loaded AI model with the given features.
 *
 * Return: Prediction score (0.0 to 1.0), -1.0 on error
 */
float ai_predict(const float *features, int feature_count);

/*
 * Utility Functions
 */

/**
 * ai_is_suspicious_sequence - Check if sequence is suspicious
 * @sequence: Event sequence to check
 *
 * Determines if an event sequence exhibits suspicious behavior
 * patterns.
 *
 * Return: 1 if suspicious, 0 if normal, -1 on error
 */
int ai_is_suspicious_sequence(const struct event_sequence *sequence);

/**
 * ai_detect_attack_pattern - Detect attack patterns in sequence
 * @sequence: Event sequence to analyze
 *
 * Detects known attack patterns in the event sequence.
 *
 * Return: 1 if attack pattern detected, 0 if normal, -1 on error
 */
int ai_detect_attack_pattern(const struct event_sequence *sequence);

#endif // RAVN_AI_ENGINE_H
