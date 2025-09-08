// RAVN AI Engine Implementation
// Implements AI model loading, sliding window analysis, and threat detection

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <hiredis/hiredis.h>
#include "ai_engine.h"
#include "redis_client.h"
#include "ebpf_handler.h"

// Global AI engine instance
static ai_engine_t *global_ai_engine = NULL;

// Initialize AI engine
ai_engine_t* ai_engine_init(const char *model_path) {
    ai_engine_t *engine = malloc(sizeof(ai_engine_t));
    if (!engine) {
        fprintf(stderr, "[AI] Failed to allocate memory for AI engine\n");
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
        fprintf(stderr, "[AI] Failed to initialize sliding window\n");
        free(engine);
        return NULL;
    }
    
    // Load AI model
    if (ai_load_model(model_path) != 0) {
        fprintf(stderr, "[AI] Failed to load model, using random weights\n");
        // Initialize with random weights for demo
        srand(time(NULL));
        for (int i = 0; i < 100; i++) {
            engine->weights[i] = (float)rand() / RAND_MAX * 0.1 - 0.05; // Small random weights
        }
    }
    
    engine->initialized = 1;
    global_ai_engine = engine;
    
    printf("[AI] AI engine initialized with model: %s\n", model_path);
    return engine;
}

// Cleanup AI engine
void ai_engine_cleanup(ai_engine_t *engine) {
    if (!engine) {
        return;
    }
    
    // Stop analysis thread
    ai_engine_stop_thread(engine);
    
    // Cleanup sliding window
    memset(&engine->window, 0, sizeof(engine->window));
    
    engine->initialized = 0;
    
    if (engine == global_ai_engine) {
        global_ai_engine = NULL;
    }
    
    free(engine);
    printf("[AI] AI engine cleaned up\n");
}

// Start AI analysis (no internal threading - handled by main daemon)
int ai_engine_start_analysis(ai_engine_t *engine) {
    if (!engine || !engine->initialized) {
        return -1;
    }
    
    printf("[AI] AI analysis ready (thread mode)\n");
    return 0;
}

// Stop AI analysis (no internal threading - handled by main daemon)
void ai_engine_stop_analysis(ai_engine_t *engine) {
    printf("[AI] AI analysis stopped\n");
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
    strcpy(window->threat_level, "LOW");
    strcpy(window->threat_reason, "Normal activity");
    
    return 0;
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
            
            for (int j = 0; j < seq->event_count; j++) {
                if (seq->timestamps[j] >= window->start_time) {
                    if (keep_count != j) {
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
        strcpy(window->threat_level, "HIGH");
        snprintf(window->threat_reason, sizeof(window->threat_reason),
                "High threat detected in %d processes", suspicious_processes);
    } else if (window->overall_threat_score > 0.4) {
        strcpy(window->threat_level, "MEDIUM");
        snprintf(window->threat_reason, sizeof(window->threat_reason),
                "Medium threat detected in %d processes", suspicious_processes);
    } else {
        strcpy(window->threat_level, "LOW");
        strcpy(window->threat_reason, "Normal activity");
    }
    
    return 0;
}

// Process event (legacy function)
int ai_process_event(const char *event_json) {
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
    
    // Simple feature extraction
    float features[10] = {0};
    
    // Feature 1: Event count (normalized)
    features[0] = (float)sequence->event_count / MAX_EVENTS_PER_WINDOW;
    
    // Feature 2: Unique event types
    int unique_types = 0;
    for (int i = 0; i < sequence->event_count; i++) {
        int is_unique = 1;
        for (int j = 0; j < i; j++) {
            if (sequence->events[i] == sequence->events[j]) {
                is_unique = 0;
                break;
            }
        }
        if (is_unique) unique_types++;
    }
    features[1] = (float)unique_types / sequence->event_count;
    
    // Feature 3: Time span
    if (sequence->event_count > 1) {
        uint64_t time_span = sequence->timestamps[sequence->event_count - 1] - sequence->timestamps[0];
        features[2] = (float)time_span / WINDOW_SIZE_SECONDS;
    }
    
    // Feature 4: Suspicious event patterns
    features[3] = ai_detect_attack_pattern(sequence) ? 1.0f : 0.0f;
    
    // Simple linear model prediction
    float score = 0.0f;
    for (int i = 0; i < 10 && i < 100; i++) {
        score += features[i] * global_ai_engine->weights[i];
    }
    
    // Apply sigmoid activation
    score = 1.0f / (1.0f + expf(-score));
    
    return score;
}

// Load AI model
int ai_load_model(const char *model_path) {
    if (!model_path || !global_ai_engine) {
        return -1;
    }
    
    FILE *file = fopen(model_path, "rb");
    if (!file) {
        return -1;
    }
    
    // Read model weights (simplified)
    size_t read_count = fread(global_ai_engine->weights, sizeof(float), 100, file);
    fclose(file);
    
    if (read_count != 100) {
        return -1;
    }
    
    printf("[AI] Model loaded from %s\n", model_path);
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

// Save AI model
int ai_save_model(const char *model_path) {
    if (!model_path || !global_ai_engine || !global_ai_engine->initialized) {
        return -1;
    }
    
    FILE *file = fopen(model_path, "wb");
    if (!file) {
        return -1;
    }
    
    size_t write_count = fwrite(global_ai_engine->weights, sizeof(float), 100, file);
    fclose(file);
    
    if (write_count != 100) {
        return -1;
    }
    
    printf("[AI] Model saved to %s\n", model_path);
    return 0;
}

// Get threat level name
const char* ai_get_threat_level_name(float score) {
    if (score > 0.7) return "HIGH";
    if (score > 0.4) return "MEDIUM";
    return "LOW";
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
    
    printf("[AI-THREAD] AI analysis thread started\n");
    
    // Use the global Redis connection instead of creating new ones
    extern void* global_redis_conn_ptr;
    redis_connection_t *redis_conn = (redis_connection_t*)global_redis_conn_ptr;
    
    while (!engine->should_stop) {
        // Check if Redis connection is available
        if (!redis_conn || redis_ping(redis_conn) != 0) {
            usleep(1000000); // Sleep 1 second if Redis not available
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
                
                printf("[AI-THREAD] Event analyzed: PID=%u, Score=%.3f, Level=%d\n", 
                       event.pid, threat_score, threat_level);
            }
        }
        
        if (reply) freeReplyObject(reply);
        
        usleep(500000); // Sleep 0.5 seconds between analysis cycles
    }
    
    printf("[AI-THREAD] AI analysis thread stopped\n");
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
        fprintf(stderr, "[AI] Failed to create AI analysis thread\n");
        return -1;
    }
    
    engine->thread_running = 1;
    printf("[AI] AI analysis thread started\n");
    return 0;
}

// Stop AI analysis thread
void ai_engine_stop_thread(ai_engine_t *engine) {
    if (!engine || !engine->thread_running) {
        return;
    }
    
    engine->should_stop = 1;
    
    if (pthread_join(engine->analysis_thread, NULL) != 0) {
        fprintf(stderr, "[AI] Failed to join AI analysis thread\n");
    }
    
    engine->thread_running = 0;
    printf("[AI] AI analysis thread stopped\n");
}