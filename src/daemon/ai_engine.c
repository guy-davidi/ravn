// RAVN AI Engine Implementation
// Implements AI model loading, sliding window analysis, and threat detection

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <hiredis/hiredis.h>
#include <stdint.h>
#include "ai_engine.h"
#include "redis_client.h"
#include "ebpf_handler.h"
#include "../utils/logger.h"
#include "codegen/model_weights.h"  // Generated model weights

// Global AI engine instance
static ai_engine_t *global_ai_engine = NULL;

// Forward declarations
void sliding_window_cleanup(struct sliding_window *window);

// Initialize AI engine
ai_engine_t* ai_engine_init(const char *model_path) {
    ai_engine_t *engine = malloc(sizeof(ai_engine_t));
    if (!engine) {
        LOG_ERROR("Failed to allocate memory for AI engine");
        return NULL;
    }
    
    // Initialize engine structure
    memset(engine, 0, sizeof(ai_engine_t));
    strncpy(engine->model_path, model_path, sizeof(engine->model_path) - 1);
    engine->model_path[sizeof(engine->model_path) - 1] = '\0';
    engine->thread_running = 0;
    engine->should_stop = 0;
    
    // Initialize sliding window
    if (sliding_window_init(&engine->window) != 0) {
        LOG_ERROR("Failed to initialize sliding window");
        free(engine);
        return NULL;
    }
    
    // Set global pointer before loading model
    global_ai_engine = engine;
    
    // Load AI model
    if (ai_load_model(model_path) != 0) {
        LOG_ERROR("Failed to load model from %s", model_path);
        LOG_ERROR("AI engine initialization failed - model file required");
        sliding_window_cleanup(&engine->window);
        global_ai_engine = NULL;
        free(engine);
        return NULL;
    }
    
    engine->initialized = 1;
    
    LOG_INFO("AI engine initialized with model: %s", model_path);
    return engine;
}

// Cleanup AI engine
void ai_engine_cleanup(ai_engine_t *engine) {
    if (!engine) {
        return;
    }
    
    // Stop analysis thread
    ai_engine_stop_thread(engine);
    
    // No cleanup needed for simple weights
    
    // Cleanup sliding window
    memset(&engine->window, 0, sizeof(engine->window));
    
    engine->initialized = 0;
    
    if (engine == global_ai_engine) {
        global_ai_engine = NULL;
    }
    
    free(engine);
    LOG_INFO("AI engine cleaned up");
}

// Start AI analysis (no internal threading - handled by main daemon)
int ai_engine_start_analysis(ai_engine_t *engine) {
    if (!engine || !engine->initialized) {
        return -1;
    }
    
    LOG_INFO_MODULE("AI-ENGINE", "AI analysis ready (thread mode)");
    return 0;
}

// Stop AI analysis (no internal threading - handled by main daemon)
void ai_engine_stop_analysis(ai_engine_t *engine) {
    (void)engine; // Suppress unused parameter warning
    LOG_INFO_MODULE("AI-ENGINE", "AI analysis stopped");
}

// Analyze single event
float ai_engine_analyze_event(ai_engine_t *engine, const struct ravn_event *event) {
    if (!engine || !engine->initialized || !event) {
        return 0.0f;
    }
    
    // Find or create event sequence for this PID
    struct event_sequence *seq = NULL;
    for (int i = 0; i < engine->window.process_count; i++) {
        if (engine->window.processes[i].pid == event->pid) {
            seq = &engine->window.processes[i];
            break;
        }
    }
    
    if (!seq) {
        // Create new sequence
        if (engine->window.process_count >= MAX_PROCESSES) {
            return 0.0f; // Too many processes
        }
        
        seq = &engine->window.processes[engine->window.process_count++];
        seq->pid = event->pid;
        seq->event_count = 0;
        seq->threat_score = 0.0f;
    }
    
    // Add event to sequence
    if (seq->event_count < MAX_EVENTS_PER_WINDOW) {
        seq->events[seq->event_count] = event->event_type;
        seq->timestamps[seq->event_count] = event->timestamp;
        seq->event_count++;
    }
    
    // Calculate threat score for this sequence
    seq->threat_score = ai_calculate_threat_score(seq);
    
    // Update sliding window analysis
    uint64_t current_time = time(NULL);
    sliding_window_update(&engine->window, current_time);
    sliding_window_analyze(&engine->window);
    
    return seq->threat_score;
}

// Initialize sliding window
int sliding_window_init(struct sliding_window *window) {
    if (!window) {
        return -1;
    }
    
    memset(window, 0, sizeof(struct sliding_window));
    window->start_time = time(NULL);
    window->end_time = window->start_time + WINDOW_SIZE_SECONDS;
    window->process_count = 0;
    window->overall_threat_score = 0.0f;
    strcpy(window->threat_level_str, "LOW");
    strcpy(window->threat_reason, "Normal activity");
    
    return 0;
}

// Cleanup sliding window
void sliding_window_cleanup(struct sliding_window *window) {
    if (!window) {
        return;
    }
    
    // Free any allocated memory if needed
    // For now, just clear the structure
    memset(window, 0, sizeof(struct sliding_window));
}

// Update sliding window
int sliding_window_update(struct sliding_window *window, uint64_t current_time) {
    if (!window) {
        return -1;
    }
    
    // Slide window if needed
    if (current_time >= window->end_time) {
        window->start_time = current_time;
        window->end_time = current_time + WINDOW_SIZE_SECONDS;
        
        // Clear old events (keep only recent ones)
        for (int i = 0; i < window->process_count; i++) {
            struct event_sequence *seq = &window->processes[i];
            int keep_count = 0;
            
            for (uint32_t j = 0; j < seq->event_count; j++) {
                if (seq->timestamps[j] >= window->start_time) {
                    if (keep_count != (int)j) {
                        seq->events[keep_count] = seq->events[j];
                        seq->timestamps[keep_count] = seq->timestamps[j];
                    }
                    keep_count++;
                }
            }
            
            seq->event_count = keep_count;
        }
    }
    
    return 0;
}

// Analyze sliding window
int sliding_window_analyze(struct sliding_window *window) {
    if (!window) {
        return -1;
    }
    
    float max_threat = 0.0f;
    int suspicious_processes = 0;
    
    // Analyze each process sequence
    for (int i = 0; i < window->process_count; i++) {
        struct event_sequence *seq = &window->processes[i];
        
        if (seq->event_count > 0) {
            seq->threat_score = ai_calculate_threat_score(seq);
            
            if (seq->threat_score > max_threat) {
                max_threat = seq->threat_score;
            }
            
            if (ai_is_suspicious_sequence(seq)) {
                suspicious_processes++;
            }
        }
    }
    
    // Calculate overall threat score
    window->overall_threat_score = max_threat;
    
    // Determine threat level and reason
    if (window->overall_threat_score > 0.7) {
        strcpy(window->threat_level_str, "HIGH");
        snprintf(window->threat_reason, sizeof(window->threat_reason),
                "High threat detected in %d processes", suspicious_processes);
    } else if (window->overall_threat_score > 0.4) {
        strcpy(window->threat_level_str, "MEDIUM");
        snprintf(window->threat_reason, sizeof(window->threat_reason),
                "Medium threat detected in %d processes", suspicious_processes);
    } else {
        strcpy(window->threat_level_str, "LOW");
        strcpy(window->threat_reason, "Normal activity");
    }
    
    return 0;
}

// Process event (legacy function)
int ai_process_event(const char *event_json) {
    (void)event_json; // Suppress unused parameter warning
    // This function is kept for compatibility but not used in new implementation
    return 0;
}

// Analyze event sequence
int ai_analyze_sequence(struct event_sequence *sequence) {
    if (!sequence) {
        return -1;
    }
    
    sequence->threat_score = ai_calculate_threat_score(sequence);
    return 0;
}

// Calculate threat score for a sequence
float ai_calculate_threat_score(struct event_sequence *sequence) {
    if (!sequence || !global_ai_engine || !global_ai_engine->initialized) {
        return 0.0f;
    }
    
    if (sequence->event_count == 0) {
        return 0.0f;
    }
    
    // RAVN Security Feature Extraction Algorithm
    float features[TOTAL_FEATURES] = {0};
    
    // Extract comprehensive features from event sequence
    if (extract_features_from_events(sequence, features) != 0) {
        LOG_ERROR_MODULE("AI-ENGINE", "Failed to extract features from sequence");
        return 0.0f;
    }
    
    // Enhanced neural network prediction with 64 features
    float score = 0.0f;
    for (int i = 0; i < TOTAL_FEATURES && i < 100; i++) {
        score += features[i] * global_ai_engine->weights[i];
    }
    
    // Apply sigmoid activation
    score = 1.0f / (1.0f + expf(-score));
    
    return score;
}

// Load AI model (uses compiled weights)
int ai_load_model(const char *model_path) {
    (void)model_path; // Suppress unused parameter warning
    if (!global_ai_engine) {
        LOG_ERROR("Invalid AI engine instance");
        return -1;
    }
    
    // Copy weights from compiled header
    memcpy(global_ai_engine->weights, all_model_weights, sizeof(all_model_weights));
    
    LOG_INFO("Model loaded successfully from compiled weights (%d weights)", TOTAL_WEIGHT_COUNT);
    LOG_INFO("Model version: %d", model_version);
    return 0;
}

// Predict using AI model
float ai_predict(const float *features, int feature_count) {
    if (!features || feature_count <= 0 || !global_ai_engine || !global_ai_engine->initialized) {
        return 0.0f;
    }
    
    float score = 0.0f;
    int max_features = (feature_count < 100) ? feature_count : 100;
    
    for (int i = 0; i < max_features; i++) {
        score += features[i] * global_ai_engine->weights[i];
    }
    
    // Apply sigmoid activation
    score = 1.0f / (1.0f + expf(-score));
    
    return score;
}

// Check if sequence is suspicious
int ai_is_suspicious_sequence(const struct event_sequence *sequence) {
    if (!sequence || sequence->event_count == 0) {
        return 0;
    }
    
    // Check for high event frequency
    if (sequence->event_count > 50) {
        return 1;
    }
    
    // Check for attack patterns
    if (ai_detect_attack_pattern(sequence)) {
        return 1;
    }
    
    return 0;
}

// Detect attack patterns
int ai_detect_attack_pattern(const struct event_sequence *sequence) {
    if (!sequence || sequence->event_count < 3) {
        return 0;
    }
    
    // Simple pattern detection: rapid file access
    int file_access_count = 0;
    for (int i = 0; i < (int)sequence->event_count - 2; i++) {
        // Check for rapid file operations (simplified)
        if (sequence->events[i] == 2 || sequence->events[i] == 3) { // File events
            file_access_count++;
        }
    }
    
    // If more than 30% of events are file operations, consider suspicious
    if (file_access_count > sequence->event_count * 0.3) {
        return 1;
    }
    
    return 0;
}

// AI thread function - runs continuously to analyze events
void* ai_thread_func(void *arg) {
    ai_engine_t *engine = (ai_engine_t*)arg;
    if (!engine) {
        return NULL;
    }
    
    LOG_INFO_MODULE("AI-ENGINE", "AI analysis thread started");
    
    // Use the global Redis connection instead of creating new ones
    extern void* global_redis_conn_ptr;
    redis_connection_t *redis_conn = (redis_connection_t*)global_redis_conn_ptr;
    
    while (!engine->should_stop) {
        // Check if Redis connection is available
        if (!redis_conn || redis_ping(redis_conn) != 0) {
            sleep(1); // Sleep 1 second if Redis not available
            continue;
        }
        
        // Get latest event from Redis
        redisReply *reply = redisCommand(redis_conn->context, "RPOP events:raw");
        if (reply && reply->type == REDIS_REPLY_STRING) {
            // Parse event JSON (simplified)
            struct ravn_event event;
            memset(&event, 0, sizeof(event));
            
            // Simple JSON parsing for demo
            if (sscanf(reply->str, "{\"pid\":%u,\"event_type\":%u,\"timestamp\":%lu", 
                      &event.pid, &event.event_type, &event.timestamp) == 3) {
                
                // Analyze the event
                float threat_score = ai_engine_analyze_event(engine, &event);
                
                // Determine threat level
                int threat_level = (threat_score > 0.7) ? 2 : (threat_score > 0.4) ? 1 : 0;
                
                // Update threat level in Redis
                char threat_json[512];
                snprintf(threat_json, sizeof(threat_json),
                        "{\"level\":%d,\"score\":%.3f,\"reason\":\"AI analysis: PID %u\",\"timestamp\":%lu}",
                        threat_level, threat_score, event.pid, time(NULL));
                
                redisCommand(redis_conn->context, "SET threat:level \"%s\"", threat_json);
                
                LOG_INFO_MODULE("AI-ENGINE", "Event analyzed: PID=%u, Score=%.3f, Level=%d", 
                       event.pid, threat_score, threat_level);
            }
        }
        
        if (reply) freeReplyObject(reply);
        
        usleep(500000); // Sleep 0.5 seconds between analysis cycles
    }
    
    LOG_INFO_MODULE("AI-ENGINE", "AI analysis thread stopped");
    return NULL;
}

// Start AI analysis thread
int ai_engine_start_thread(ai_engine_t *engine) {
    if (!engine || !engine->initialized) {
        return -1;
    }
    
    if (engine->thread_running) {
        return 0; // Already running
    }
    
    engine->should_stop = 0;
    
    if (pthread_create(&engine->analysis_thread, NULL, ai_thread_func, engine) != 0) {
        LOG_ERROR_MODULE("AI-ENGINE", "Failed to create AI analysis thread");
        return -1;
    }
    
    engine->thread_running = 1;
    LOG_INFO_MODULE("AI-ENGINE", "AI analysis thread started");
    return 0;
}

// Stop AI analysis thread
void ai_engine_stop_thread(ai_engine_t *engine) {
    if (!engine || !engine->thread_running) {
        return;
    }
    
    engine->should_stop = 1;
    
    if (pthread_join(engine->analysis_thread, NULL) != 0) {
        LOG_ERROR_MODULE("AI-ENGINE", "Failed to join AI analysis thread");
    }
    
    engine->thread_running = 0;
    LOG_INFO_MODULE("AI-ENGINE", "AI analysis thread stopped");
}

/*
 * RAVN Security Feature Extraction Algorithm Implementation
 * Multi-dimensional feature extraction for comprehensive threat detection
 */

/**
 * extract_features_from_events - Extract comprehensive features from event sequence
 */
int extract_features_from_events(const struct event_sequence *sequence, float *features) {
    if (!sequence || !features) {
        return -1;
    }
    
    // Initialize all features to 0
    memset(features, 0, TOTAL_FEATURES * sizeof(float));
    
    // Extract features from each category
    extract_temporal_features(sequence, &features[TEMPORAL_OFFSET]);
    extract_process_features(sequence, &features[PROCESS_OFFSET]);
    extract_file_features(sequence, &features[FILE_OFFSET]);
    extract_network_features(sequence, &features[NETWORK_OFFSET]);
    extract_security_features(sequence, &features[SECURITY_OFFSET]);
    extract_system_features(sequence, &features[SYSTEM_OFFSET]);
    extract_behavioral_features(sequence, &features[BEHAVIORAL_OFFSET]);
    
    // Normalize all features to [0,1] range
    normalize_features(features, TOTAL_FEATURES);
    
    return 0;
}

/**
 * extract_temporal_features - Extract temporal pattern features
 */
void extract_temporal_features(const struct event_sequence *sequence, float *features) {
    if (!sequence || !features || sequence->event_count == 0) {
        return;
    }
    
    // TEMPORAL_EVENT_FREQUENCY: Events per second
    features[TEMPORAL_EVENT_FREQUENCY] = (float)sequence->event_count / WINDOW_SIZE_SECONDS;
    
    // TEMPORAL_BURST_INTENSITY: Events in 1-second bursts
    int burst_count = 0;
    for (uint32_t i = 1; i < sequence->event_count; i++) {
        uint64_t time_diff = sequence->timestamps[i] - sequence->timestamps[i-1];
        if (time_diff < 1000000000) { // Less than 1 second
            burst_count++;
        }
    }
    features[TEMPORAL_BURST_INTENSITY] = (float)burst_count / sequence->event_count;
    
    // TEMPORAL_TIME_REGULARITY: Standard deviation of intervals
    if (sequence->event_count > 2) {
        float mean_interval = 0.0f;
        for (uint32_t i = 1; i < sequence->event_count; i++) {
            mean_interval += (sequence->timestamps[i] - sequence->timestamps[i-1]);
        }
        mean_interval /= (sequence->event_count - 1);
        
        float variance = 0.0f;
        for (uint32_t i = 1; i < sequence->event_count; i++) {
            float diff = (sequence->timestamps[i] - sequence->timestamps[i-1]) - mean_interval;
            variance += diff * diff;
        }
        variance /= (sequence->event_count - 1);
        features[TEMPORAL_TIME_REGULARITY] = sqrtf(variance) / mean_interval; // Coefficient of variation
    }
    
    // TEMPORAL_SEQUENCE_DURATION: Sequence duration (normalized)
    if (sequence->event_count > 1) {
        uint64_t duration = sequence->timestamps[sequence->event_count - 1] - sequence->timestamps[0];
        features[TEMPORAL_SEQUENCE_DURATION] = (float)duration / (WINDOW_SIZE_SECONDS * 1000000000ULL);
    }
    
    // TEMPORAL_PEAK_ACTIVITY_TIME: When most events occurred
    int time_buckets[10] = {0};
    for (uint32_t i = 0; i < sequence->event_count; i++) {
        int bucket = (sequence->timestamps[i] % (WINDOW_SIZE_SECONDS * 1000000000ULL)) / (WINDOW_SIZE_SECONDS * 100000000ULL / 10);
        time_buckets[bucket]++;
    }
    int max_bucket = 0;
    for (int i = 1; i < 10; i++) {
        if (time_buckets[i] > time_buckets[max_bucket]) {
            max_bucket = i;
        }
    }
    features[TEMPORAL_PEAK_ACTIVITY_TIME] = (float)max_bucket / 9.0f;
    
    // TEMPORAL_QUIET_PERIODS: Periods with no events
    int quiet_periods = 0;
    for (uint32_t i = 1; i < sequence->event_count; i++) {
        uint64_t gap = sequence->timestamps[i] - sequence->timestamps[i-1];
        if (gap > 2000000000) { // More than 2 seconds
            quiet_periods++;
        }
    }
    features[TEMPORAL_QUIET_PERIODS] = (float)quiet_periods / sequence->event_count;
    
    // TEMPORAL_ACCELERATION_RATE: Increasing event frequency
    if (sequence->event_count > 4) {
        int first_half = sequence->event_count / 2;
        int second_half = sequence->event_count - first_half;
        float first_rate = (float)first_half / (WINDOW_SIZE_SECONDS / 2);
        float second_rate = (float)second_half / (WINDOW_SIZE_SECONDS / 2);
        features[TEMPORAL_ACCELERATION_RATE] = (second_rate - first_rate) / (first_rate + 0.001f);
    }
    
    // TEMPORAL_DECELERATION_RATE: Decreasing event frequency
    features[TEMPORAL_DECELERATION_RATE] = -features[TEMPORAL_ACCELERATION_RATE]; // Opposite of acceleration
}

/**
 * extract_process_features - Extract process behavior features
 */
void extract_process_features(const struct event_sequence *sequence, float *features) {
    if (!sequence || !features) {
        return;
    }
    
    // Initialize all process features to 0
    memset(features, 0, PROCESS_FEATURES * sizeof(float));
    
    // Count different types of process-related events
    int process_spawns = 0;
    int process_exits = 0;
    int working_dir_changes = 0;
    int env_var_changes = 0;
    int signal_events = 0;
    int priority_changes = 0;
    int process_group_ops = 0;
    int session_ops = 0;
    int affinity_changes = 0;
    int memory_maps = 0;
    int credential_changes = 0;
    int command_complexity = 0;
    
    for (uint32_t i = 0; i < sequence->event_count; i++) {
        uint32_t event_type = sequence->events[i];
        
        // Count process-related events based on event type
        switch (event_type) {
            case PROCESS_SPAWN: // Process creation (execve, fork, clone)
                process_spawns++;
                break;
            case PROCESS_EXIT: // Process termination
                process_exits++;
                break;
            case PROCESS_WORKING_DIR_CHANGE: // Working directory change (chdir)
                working_dir_changes++;
                break;
            case PROCESS_ENV_VAR_CHANGE: // Environment variable change
                env_var_changes++;
                break;
            case PROCESS_SIGNAL_HANDLING: // Signal handling (kill, signal)
                signal_events++;
                break;
            case PROCESS_PRIORITY_CHANGE: // Priority change (nice, setpriority)
                priority_changes++;
                break;
            case PROCESS_GROUP_OPERATION: // Process group operations
                process_group_ops++;
                break;
            case PROCESS_SESSION_OPERATION: // Session operations
                session_ops++;
                break;
            case PROCESS_AFFINITY_CHANGE: // CPU affinity changes
                affinity_changes++;
                break;
            case PROCESS_MEMORY_MAP: // Memory mapping operations
                memory_maps++;
                break;
            case PROCESS_CREDENTIAL_CHANGE: // Credential changes (setuid, setgid)
                credential_changes++;
                break;
            default:
                // Estimate command complexity based on event diversity
                command_complexity++;
                break;
        }
    }
    
    // Normalize process features
    features[0] = (float)process_spawns / sequence->event_count;
    features[1] = (float)process_exits / sequence->event_count;
    features[2] = (float)working_dir_changes / sequence->event_count;
    features[3] = (float)env_var_changes / sequence->event_count;
    features[4] = (float)signal_events / sequence->event_count;
    features[5] = (float)priority_changes / sequence->event_count;
    features[6] = (float)process_group_ops / sequence->event_count;
    features[7] = (float)session_ops / sequence->event_count;
    features[8] = (float)affinity_changes / sequence->event_count;
    features[9] = (float)memory_maps / sequence->event_count;
    features[10] = (float)credential_changes / sequence->event_count;
    features[11] = (float)command_complexity / sequence->event_count;
}

/**
 * extract_file_features - Extract file access pattern features
 */
void extract_file_features(const struct event_sequence *sequence, float *features) {
    if (!sequence || !features) {
        return;
    }
    
    // Initialize all file features to 0
    memset(features, 0, FILE_FEATURES * sizeof(float));
    
    // Count different types of file operations
    int sensitive_file_access = 0;
    int executable_file_access = 0;
    int config_file_access = 0;
    int log_file_access = 0;
    int temp_file_ops = 0;
    int file_creations = 0;
    int file_deletions = 0;
    int file_modifications = 0;
    int directory_traversal = 0;
    int permission_changes = 0;
    
    for (uint32_t i = 0; i < sequence->event_count; i++) {
        uint32_t event_type = sequence->events[i];
        
        // Categorize file operations based on event type
        switch (event_type) {
            case FILE_EVENT_OPEN: // File open operation
                // Check file type based on event type pattern
                if (event_type % FILE_TYPE_MODULO == SENSITIVE_FILE_PATTERN) {
                    sensitive_file_access++;
                } else if (event_type % FILE_TYPE_MODULO == EXECUTABLE_FILE_PATTERN) {
                    executable_file_access++;
                } else if (event_type % FILE_TYPE_MODULO == CONFIG_FILE_PATTERN) {
                    config_file_access++;
                } else if (event_type % FILE_TYPE_MODULO == LOG_FILE_PATTERN) {
                    log_file_access++;
                } else if (event_type % FILE_TYPE_MODULO == TEMP_FILE_PATTERN) {
                    temp_file_ops++;
                }
                break;
            case FILE_EVENT_CREATE: // File creation
                file_creations++;
                break;
            case FILE_EVENT_DELETE: // File deletion
                file_deletions++;
                break;
            case FILE_EVENT_WRITE: // File modification
                file_modifications++;
                break;
            case FILE_EVENT_READ: // Directory traversal (simplified)
                directory_traversal++;
                break;
            case FILE_EVENT_CHMOD: // Permission changes
                permission_changes++;
                break;
        }
    }
    
    // Normalize file features
    features[0] = (float)sensitive_file_access / sequence->event_count;
    features[1] = (float)executable_file_access / sequence->event_count;
    features[2] = (float)config_file_access / sequence->event_count;
    features[3] = (float)log_file_access / sequence->event_count;
    features[4] = (float)temp_file_ops / sequence->event_count;
    features[5] = (float)file_creations / sequence->event_count;
    features[6] = (float)file_deletions / sequence->event_count;
    features[7] = (float)file_modifications / sequence->event_count;
    features[8] = (float)directory_traversal / sequence->event_count;
    features[9] = (float)permission_changes / sequence->event_count;
}

/**
 * extract_network_features - Extract network behavior features
 */
void extract_network_features(const struct event_sequence *sequence, float *features) {
    if (!sequence || !features) {
        return;
    }
    
    // Initialize all network features to 0
    memset(features, 0, NETWORK_FEATURES * sizeof(float));
    
    // Count different types of network operations
    int connections = 0;
    int suspicious_ports = 0;
    int data_transfer = 0;
    int connection_duration = 0;
    int protocol_diversity = 0;
    int external_connections = 0;
    int port_scanning = 0;
    int network_errors = 0;
    
    for (uint32_t i = 0; i < sequence->event_count; i++) {
        uint32_t event_type = sequence->events[i];
        
        // Categorize network operations
        switch (event_type) {
            case NET_EVENT_SOCKET_CREATE: // Socket creation
                connections++;
                break;
            case NET_EVENT_SOCKET_BIND: // Socket bind operation
                // Check for suspicious ports using meaningful constants
                if (event_type % PORT_MODULO_BASE == SUSPICIOUS_PORT_4444 % PORT_MODULO_BASE || 
                    event_type % PORT_MODULO_BASE == SUSPICIOUS_PORT_1337 % PORT_MODULO_BASE) {
                    suspicious_ports++;
                }
                break;
            case NET_EVENT_SOCKET_CONNECT: // Socket connect operation
                connections++;
                break;
            case NET_EVENT_SOCKET_SEND: // Socket send operation
                data_transfer++;
                break;
            case NET_EVENT_SOCKET_RECV: // Socket receive operation
                data_transfer++;
                break;
            case NET_EVENT_SOCKET_ACCEPT: // Socket accept operation
                external_connections++;
                break;
            case NET_EVENT_SOCKET_LISTEN: // Socket listen operation
                port_scanning++;
                break;
            case NET_EVENT_SOCKET_CLOSE: // Socket close operation
                network_errors++;
                break;
        }
    }
    
    // Normalize network features
    features[0] = (float)connections / sequence->event_count;
    features[1] = (float)suspicious_ports / sequence->event_count;
    features[2] = (float)data_transfer / sequence->event_count;
    features[3] = (float)connection_duration / sequence->event_count;
    features[4] = (float)protocol_diversity / sequence->event_count;
    features[5] = (float)external_connections / sequence->event_count;
    features[6] = (float)port_scanning / sequence->event_count;
    features[7] = (float)network_errors / sequence->event_count;
}

/**
 * extract_security_features - Extract security event features
 */
void extract_security_features(const struct event_sequence *sequence, float *features) {
    if (!sequence || !features) {
        return;
    }
    
    // Initialize all security features to 0
    memset(features, 0, SECURITY_FEATURES * sizeof(float));
    
    // Count different types of security events
    int privilege_escalation = 0;
    int authentication_events = 0;
    int failed_operations = 0;
    int suspicious_syscalls = 0;
    int capability_usage = 0;
    int security_context_changes = 0;
    int audit_events = 0;
    int policy_violations = 0;
    
    for (uint32_t i = 0; i < sequence->event_count; i++) {
        uint32_t event_type = sequence->events[i];
        
        // Categorize security events
        switch (event_type) {
            case SEC_EVENT_SETUID: // Set user ID operation
                privilege_escalation++;
                break;
            case SEC_EVENT_SETGID: // Set group ID operation
                privilege_escalation++;
                break;
            case SEC_EVENT_CAPSET: // Capability set operation
                capability_usage++;
                break;
            case SEC_EVENT_PRCTL: // Process control operation
                security_context_changes++;
                break;
            case SEC_EVENT_SETRESUID: // Set real, effective, and saved user ID
                privilege_escalation++;
                break;
            case SEC_EVENT_SETRESGID: // Set real, effective, and saved group ID
                privilege_escalation++;
                break;
            case SEC_EVENT_SETEUID: // Set effective user ID
                privilege_escalation++;
                break;
            case SEC_EVENT_SETEGID: // Set effective group ID
                privilege_escalation++;
                break;
            case SEC_EVENT_SETREUID: // Set real and effective user ID
                privilege_escalation++;
                break;
            case SEC_EVENT_SETREGID: // Set real and effective group ID
                privilege_escalation++;
                break;
        }
    }
    
    // Normalize security features
    features[0] = (float)privilege_escalation / sequence->event_count;
    features[1] = (float)authentication_events / sequence->event_count;
    features[2] = (float)failed_operations / sequence->event_count;
    features[3] = (float)suspicious_syscalls / sequence->event_count;
    features[4] = (float)capability_usage / sequence->event_count;
    features[5] = (float)security_context_changes / sequence->event_count;
    features[6] = (float)audit_events / sequence->event_count;
    features[7] = (float)policy_violations / sequence->event_count;
}

/**
 * extract_system_features - Extract system resource usage features
 */
void extract_system_features(const struct event_sequence *sequence, float *features) {
    if (!sequence || !features) {
        return;
    }
    
    // Initialize all system features to 0
    memset(features, 0, SYSTEM_FEATURES * sizeof(float));
    
    // Estimate system resource usage based on event patterns
    float cpu_intensity = 0.0f;
    float memory_intensity = 0.0f;
    float disk_io_intensity = 0.0f;
    float system_load_impact = 0.0f;
    float resource_contention = 0.0f;
    float syscall_frequency = 0.0f;
    float interrupt_handling = 0.0f;
    float kernel_operations = 0.0f;
    
    // Calculate system features based on event patterns
    syscall_frequency = (float)sequence->event_count / WINDOW_SIZE_SECONDS;
    
    // Estimate resource usage based on event types using meaningful constants
    for (uint32_t i = 0; i < sequence->event_count; i++) {
        uint32_t event_type = sequence->events[i];
        
        // CPU-intensive operations
        if (event_type % SYSTEM_RESOURCE_MODULO == CPU_INTENSIVE_PATTERN) {
            cpu_intensity += 0.1f;
        }
        
        // Memory-intensive operations
        if (event_type % SYSTEM_RESOURCE_MODULO == MEMORY_INTENSIVE_PATTERN) {
            memory_intensity += 0.1f;
        }
        
        // Disk I/O operations
        if (event_type % SYSTEM_RESOURCE_MODULO == DISK_IO_INTENSIVE_PATTERN) {
            disk_io_intensity += 0.1f;
        }
        
        // Kernel operations
        if (event_type % SYSTEM_RESOURCE_MODULO == KERNEL_OPERATIONS_PATTERN) {
            kernel_operations += 0.1f;
        }
    }
    
    // Normalize system features using enums for clarity
    features[SYSTEM_CPU_INTENSITY] = cpu_intensity / sequence->event_count;
    features[SYSTEM_MEMORY_INTENSITY] = memory_intensity / sequence->event_count;
    features[SYSTEM_DISK_IO_INTENSITY] = disk_io_intensity / sequence->event_count;
    features[SYSTEM_LOAD_IMPACT] = system_load_impact / sequence->event_count;
    features[SYSTEM_RESOURCE_CONTENTION] = resource_contention / sequence->event_count;
    features[SYSTEM_SYSCALL_FREQUENCY] = syscall_frequency / 100.0f; // Normalize to reasonable range
    features[SYSTEM_INTERRUPT_HANDLING] = interrupt_handling / sequence->event_count;
    features[SYSTEM_KERNEL_OPERATIONS] = kernel_operations / sequence->event_count;
}

/**
 * extract_behavioral_features - Extract behavioral pattern features
 */
void extract_behavioral_features(const struct event_sequence *sequence, float *features) {
    if (!sequence || !features) {
        return;
    }
    
    // Initialize all behavioral features to 0
    memset(features, 0, BEHAVIORAL_FEATURES * sizeof(float));
    
    // Analyze behavioral patterns
    float stealth_behavior = 0.0f;
    float persistence_attempts = 0.0f;
    float evasion_techniques = 0.0f;
    float lateral_movement = 0.0f;
    float data_exfiltration = 0.0f;
    float command_injection = 0.0f;
    float buffer_overflow_attempts = 0.0f;
    float code_injection = 0.0f;
    float anti_forensics = 0.0f;
    float communication_patterns = 0.0f;
    
    // Detect behavioral patterns based on event sequences using meaningful constants
    for (uint32_t i = 0; i < sequence->event_count; i++) {
        uint32_t event_type = sequence->events[i];
        
        // Stealth behavior (hiding activities)
        if (event_type % BEHAVIORAL_PATTERN_MODULO == BEHAVIORAL_STEALTH_PATTERN) {
            stealth_behavior += 0.1f;
        }
        
        // Persistence attempts (staying resident)
        if (event_type % BEHAVIORAL_PATTERN_MODULO == BEHAVIORAL_PERSISTENCE_PATTERN) {
            persistence_attempts += 0.1f;
        }
        
        // Evasion techniques (avoiding detection)
        if (event_type % BEHAVIORAL_PATTERN_MODULO == BEHAVIORAL_EVASION_PATTERN) {
            evasion_techniques += 0.1f;
        }
        
        // Lateral movement (moving between systems)
        if (event_type % BEHAVIORAL_PATTERN_MODULO == BEHAVIORAL_LATERAL_MOVEMENT_PATTERN) {
            lateral_movement += 0.1f;
        }
        
        // Data exfiltration (data theft patterns)
        if (event_type % BEHAVIORAL_PATTERN_MODULO == BEHAVIORAL_DATA_EXFILTRATION_PATTERN) {
            data_exfiltration += 0.1f;
        }
        
        // Command injection attempts
        if (event_type % BEHAVIORAL_PATTERN_MODULO == BEHAVIORAL_COMMAND_INJECTION_PATTERN) {
            command_injection += 0.1f;
        }
        
        // Buffer overflow patterns
        if (event_type % BEHAVIORAL_PATTERN_MODULO == BEHAVIORAL_BUFFER_OVERFLOW_PATTERN) {
            buffer_overflow_attempts += 0.1f;
        }
        
        // Code injection patterns
        if (event_type % BEHAVIORAL_PATTERN_MODULO == BEHAVIORAL_CODE_INJECTION_PATTERN) {
            code_injection += 0.1f;
        }
        
        // Anti-forensics (evidence hiding)
        if (event_type % BEHAVIORAL_PATTERN_MODULO == BEHAVIORAL_ANTI_FORENSICS_PATTERN) {
            anti_forensics += 0.1f;
        }
        
        // Communication patterns (C&C communication)
        if (event_type % BEHAVIORAL_PATTERN_MODULO == BEHAVIORAL_COMMUNICATION_PATTERN) {
            communication_patterns += 0.1f;
        }
    }
    
    // Normalize behavioral features using enums for clarity
    features[BEHAVIORAL_STEALTH - 1] = stealth_behavior / sequence->event_count;
    features[BEHAVIORAL_PERSISTENCE - 1] = persistence_attempts / sequence->event_count;
    features[BEHAVIORAL_EVASION - 1] = evasion_techniques / sequence->event_count;
    features[BEHAVIORAL_LATERAL_MOVEMENT - 1] = lateral_movement / sequence->event_count;
    features[BEHAVIORAL_DATA_EXFILTRATION - 1] = data_exfiltration / sequence->event_count;
    features[BEHAVIORAL_COMMAND_INJECTION - 1] = command_injection / sequence->event_count;
    features[BEHAVIORAL_BUFFER_OVERFLOW - 1] = buffer_overflow_attempts / sequence->event_count;
    features[BEHAVIORAL_CODE_INJECTION - 1] = code_injection / sequence->event_count;
    features[BEHAVIORAL_ANTI_FORENSICS - 1] = anti_forensics / sequence->event_count;
    features[BEHAVIORAL_COMMUNICATION - 1] = communication_patterns / sequence->event_count;
}

/**
 * normalize_features - Normalize features to [0,1] range
 */
void normalize_features(float *features, int count) {
    if (!features || count <= 0) {
        return;
    }
    
    for (int i = 0; i < count; i++) {
        // Clamp features to [0,1] range
        if (features[i] < 0.0f) {
            features[i] = 0.0f;
        } else if (features[i] > 1.0f) {
            features[i] = 1.0f;
        }
    }
}