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
 * Event Type Enums - Comprehensive categorization of security events
 * These enums make the code more readable and maintainable
 */

/**
 * enum process_event_type - Process-related event types
 */
enum process_event_type {
	PROCESS_SPAWN = 1,		/* Process creation (execve, fork, clone) */
	PROCESS_EXIT = 2,		/* Process termination */
	PROCESS_WORKING_DIR_CHANGE = 3,	/* Working directory change (chdir) */
	PROCESS_ENV_VAR_CHANGE = 4,	/* Environment variable modification */
	PROCESS_SIGNAL_HANDLING = 5,	/* Signal handling (kill, signal) */
	PROCESS_PRIORITY_CHANGE = 6,	/* Priority change (nice, setpriority) */
	PROCESS_GROUP_OPERATION = 7,	/* Process group operations */
	PROCESS_SESSION_OPERATION = 8,	/* Session operations */
	PROCESS_AFFINITY_CHANGE = 9,	/* CPU affinity changes */
	PROCESS_MEMORY_MAP = 10,	/* Memory mapping operations */
	PROCESS_CREDENTIAL_CHANGE = 11,	/* Credential changes (setuid, setgid) */
	PROCESS_COMMAND_COMPLEXITY = 12	/* Command complexity estimation */
};

/**
 * enum file_event_type - File operation event types
 */
enum file_event_type {
	FILE_SENSITIVE_ACCESS = 1,	/* Access to sensitive files */
	FILE_EXECUTABLE_ACCESS = 2,	/* Access to executable files */
	FILE_CONFIG_ACCESS = 3,		/* Access to configuration files */
	FILE_LOG_ACCESS = 4,		/* Access to log files */
	FILE_TEMP_OPERATION = 5,	/* Temporary file operations */
	FILE_CREATION = 6,		/* File creation */
	FILE_DELETION = 7,		/* File deletion */
	FILE_MODIFICATION = 8,		/* File modification */
	FILE_DIRECTORY_TRAVERSAL = 9,	/* Directory traversal */
	FILE_PERMISSION_CHANGE = 10	/* File permission changes */
};

/**
 * enum network_event_type - Network operation event types
 */
enum network_event_type {
	NETWORK_CONNECTION = 1,		/* Network connection establishment */
	NETWORK_SUSPICIOUS_PORT = 2,	/* Connection to suspicious ports */
	NETWORK_DATA_TRANSFER = 3,	/* Data transfer operations */
	NETWORK_CONNECTION_DURATION = 4, /* Connection duration analysis */
	NETWORK_PROTOCOL_DIVERSITY = 5,	/* Multiple protocol usage */
	NETWORK_EXTERNAL_CONNECTION = 6, /* External network connections */
	NETWORK_PORT_SCANNING = 7,	/* Port scanning behavior */
	NETWORK_ERROR = 8		/* Network error events */
};

/**
 * enum security_event_type - Security-related event types
 */
enum security_event_type {
	SECURITY_PRIVILEGE_ESCALATION = 1,	/* Privilege escalation attempts */
	SECURITY_AUTHENTICATION = 2,		/* Authentication events */
	SECURITY_FAILED_OPERATION = 3,		/* Failed security operations */
	SECURITY_SUSPICIOUS_SYSCALL = 4,	/* Suspicious system calls */
	SECURITY_CAPABILITY_USAGE = 5,		/* Capability usage */
	SECURITY_CONTEXT_CHANGE = 6,		/* Security context changes */
	SECURITY_AUDIT_EVENT = 7,		/* Audit events */
	SECURITY_POLICY_VIOLATION = 8		/* Security policy violations */
};

/**
 * enum behavioral_event_type - Behavioral pattern event types
 */
enum behavioral_event_type {
	BEHAVIORAL_STEALTH = 1,		/* Stealth behavior patterns */
	BEHAVIORAL_PERSISTENCE = 2,	/* Persistence attempts */
	BEHAVIORAL_EVASION = 3,		/* Evasion techniques */
	BEHAVIORAL_LATERAL_MOVEMENT = 4,	/* Lateral movement patterns */
	BEHAVIORAL_DATA_EXFILTRATION = 5,	/* Data exfiltration patterns */
	BEHAVIORAL_COMMAND_INJECTION = 6,	/* Command injection attempts */
	BEHAVIORAL_BUFFER_OVERFLOW = 7,		/* Buffer overflow patterns */
	BEHAVIORAL_CODE_INJECTION = 8,		/* Code injection patterns */
	BEHAVIORAL_ANTI_FORENSICS = 9,		/* Anti-forensics techniques */
	BEHAVIORAL_COMMUNICATION = 10		/* Communication patterns */
};

/**
 * enum threat_classification - Threat level classifications
 */
enum threat_classification {
	THREAT_NORMAL = 0,		/* Normal system activity */
	THREAT_SUSPICIOUS = 1,		/* Suspicious activity detected */
	THREAT_MALICIOUS = 2		/* Malicious activity confirmed */
};

/**
 * enum temporal_feature_type - Temporal pattern feature types
 */
enum temporal_feature_type {
	TEMPORAL_EVENT_FREQUENCY = 0,		/* Events per second */
	TEMPORAL_BURST_INTENSITY = 1,		/* Events in 1-second bursts */
	TEMPORAL_TIME_REGULARITY = 2,		/* Standard deviation of intervals */
	TEMPORAL_SEQUENCE_DURATION = 3,		/* Sequence duration (normalized) */
	TEMPORAL_PEAK_ACTIVITY_TIME = 4,	/* When most events occurred */
	TEMPORAL_QUIET_PERIODS = 5,		/* Periods with no events */
	TEMPORAL_ACCELERATION_RATE = 6,		/* Increasing event frequency */
	TEMPORAL_DECELERATION_RATE = 7		/* Decreasing event frequency */
};

/**
 * enum system_feature_type - System resource usage feature types
 */
enum system_feature_type {
	SYSTEM_CPU_INTENSITY = 0,		/* CPU usage intensity */
	SYSTEM_MEMORY_INTENSITY = 1,		/* Memory usage intensity */
	SYSTEM_DISK_IO_INTENSITY = 2,		/* Disk I/O intensity */
	SYSTEM_LOAD_IMPACT = 3,			/* System load impact */
	SYSTEM_RESOURCE_CONTENTION = 4,		/* Resource contention */
	SYSTEM_SYSCALL_FREQUENCY = 5,		/* System call frequency */
	SYSTEM_INTERRUPT_HANDLING = 6,		/* Interrupt handling */
	SYSTEM_KERNEL_OPERATIONS = 7		/* Kernel operations */
};

/**
 * enum feature_category - Feature extraction categories
 */
enum feature_category {
	FEATURE_TEMPORAL = 0,		/* Temporal pattern features */
	FEATURE_PROCESS = 1,		/* Process behavior features */
	FEATURE_FILE = 2,		/* File access pattern features */
	FEATURE_NETWORK = 3,		/* Network behavior features */
	FEATURE_SECURITY = 4,		/* Security event features */
	FEATURE_SYSTEM = 5,		/* System resource usage features */
	FEATURE_BEHAVIORAL = 6		/* Behavioral pattern features */
};

/*
 * AI Model Configuration Parameters
 */
#define WINDOW_SIZE_SECONDS 10		/* Sliding window duration in seconds */
#define SLIDE_INTERVAL_SECONDS 1	/* Window slide interval in seconds */
#define MAX_EVENTS_PER_WINDOW 1000	/* Maximum events per process in window */
#define MAX_PROCESSES 100		/* Maximum processes to track simultaneously */

/*
 * RAVN Security Feature Extraction Parameters
 * Multi-dimensional feature extraction for comprehensive threat detection
 */
#define TOTAL_FEATURES 64		/* Total number of extracted features */
#define TEMPORAL_FEATURES 8		/* Time-based pattern features */
#define PROCESS_FEATURES 12		/* Process behavior features */
#define FILE_FEATURES 10		/* File access pattern features */
#define NETWORK_FEATURES 8		/* Network behavior features */
#define SECURITY_FEATURES 8		/* Security event features */
#define SYSTEM_FEATURES 8		/* System resource usage features */
#define BEHAVIORAL_FEATURES 10		/* Behavioral pattern features */

/*
 * Feature Category Offsets
 */
#define TEMPORAL_OFFSET 0		/* Temporal features start at index 0 */
#define PROCESS_OFFSET 8		/* Process features start at index 8 */
#define FILE_OFFSET 20		/* File features start at index 20 */
#define NETWORK_OFFSET 30		/* Network features start at index 30 */
#define SECURITY_OFFSET 38		/* Security features start at index 38 */
#define SYSTEM_OFFSET 46		/* System features start at index 46 */
#define BEHAVIORAL_OFFSET 54		/* Behavioral features start at index 54 */

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

/*
 * RAVN Security Feature Extraction Functions
 */

/**
 * extract_features_from_events - Extract comprehensive features from event sequence
 * @sequence: Event sequence to analyze
 * @features: Output array for extracted features (must be TOTAL_FEATURES size)
 *
 * Extracts 64 multi-dimensional features from the event sequence using the
 * RAVN Security Feature Extraction Algorithm. Features are organized into
 * categories: temporal, process, file, network, security, system, and behavioral.
 *
 * Return: 0 on success, -1 on failure
 */
int extract_features_from_events(const struct event_sequence *sequence, float *features);

/**
 * extract_temporal_features - Extract temporal pattern features
 * @sequence: Event sequence to analyze
 * @features: Output array for temporal features (8 features)
 *
 * Extracts time-based pattern features including event frequency, burst
 * intensity, time regularity, and sequence duration.
 */
void extract_temporal_features(const struct event_sequence *sequence, float *features);

/**
 * extract_process_features - Extract process behavior features
 * @sequence: Event sequence to analyze
 * @features: Output array for process features (12 features)
 *
 * Extracts process behavior features including spawn count, tree depth,
 * command complexity, and process management operations.
 */
void extract_process_features(const struct event_sequence *sequence, float *features);

/**
 * extract_file_features - Extract file access pattern features
 * @sequence: Event sequence to analyze
 * @features: Output array for file features (10 features)
 *
 * Extracts file access pattern features including sensitive file access,
 * executable file operations, and file permission changes.
 */
void extract_file_features(const struct event_sequence *sequence, float *features);

/**
 * extract_network_features - Extract network behavior features
 * @sequence: Event sequence to analyze
 * @features: Output array for network features (8 features)
 *
 * Extracts network behavior features including connection count, suspicious
 * port usage, data transfer volume, and protocol diversity.
 */
void extract_network_features(const struct event_sequence *sequence, float *features);

/**
 * extract_security_features - Extract security event features
 * @sequence: Event sequence to analyze
 * @features: Output array for security features (8 features)
 *
 * Extracts security event features including privilege escalation attempts,
 * authentication events, failed operations, and suspicious syscalls.
 */
void extract_security_features(const struct event_sequence *sequence, float *features);

/**
 * extract_system_features - Extract system resource usage features
 * @sequence: Event sequence to analyze
 * @features: Output array for system features (8 features)
 *
 * Extracts system resource usage features including CPU usage, memory
 * consumption, disk I/O intensity, and system load impact.
 */
void extract_system_features(const struct event_sequence *sequence, float *features);

/**
 * extract_behavioral_features - Extract behavioral pattern features
 * @sequence: Event sequence to analyze
 * @features: Output array for behavioral features (10 features)
 *
 * Extracts behavioral pattern features including stealth behavior, persistence
 * attempts, evasion techniques, and lateral movement patterns.
 */
void extract_behavioral_features(const struct event_sequence *sequence, float *features);

/**
 * normalize_features - Normalize features to [0,1] range
 * @features: Feature array to normalize
 * @count: Number of features to normalize
 *
 * Normalizes all features to the [0,1] range for consistent neural network input.
 */
void normalize_features(float *features, int count);

#endif // RAVN_AI_ENGINE_H
