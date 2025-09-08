// RAVN AI Engine Header
// Defines AI model and sliding window analysis functions

#ifndef RAVN_AI_ENGINE_H
#define RAVN_AI_ENGINE_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>

// Forward declaration
struct ravn_event;

// AI model parameters
#define WINDOW_SIZE_SECONDS 10
#define SLIDE_INTERVAL_SECONDS 1
#define MAX_EVENTS_PER_WINDOW 1000
#define MAX_PROCESSES 100

// Threat levels
#define THREAT_LEVEL_LOW 0.0
#define THREAT_LEVEL_MEDIUM 0.3
#define THREAT_LEVEL_HIGH 0.7
#define THREAT_LEVEL_CRITICAL 0.9

// Event sequence structure
struct event_sequence {
    uint32_t pid;
    uint32_t event_count;
    uint32_t events[MAX_EVENTS_PER_WINDOW];
    uint64_t timestamps[MAX_EVENTS_PER_WINDOW];
    float threat_score;
};

// Sliding window structure
struct sliding_window {
    uint64_t start_time;
    uint64_t end_time;
    struct event_sequence processes[MAX_PROCESSES];
    int process_count;
    float overall_threat_score;
    char threat_level[16];
    char threat_reason[256];
};

// AI model structure (simplified)
typedef struct ai_engine ai_engine_t;
struct ai_engine {
    float weights[100]; // Simplified model weights
    int initialized;
    char model_path[256];
    struct sliding_window window;
    pthread_t analysis_thread;
    int thread_running;
    int should_stop;
};

// AI engine functions
ai_engine_t* ai_engine_init(const char *model_path);
void ai_engine_cleanup(ai_engine_t *engine);
int ai_engine_start_analysis(ai_engine_t *engine);
void ai_engine_stop_analysis(ai_engine_t *engine);
float ai_engine_analyze_event(ai_engine_t *engine, const struct ravn_event *event);

// Thread management functions
int ai_engine_start_thread(ai_engine_t *engine);
void ai_engine_stop_thread(ai_engine_t *engine);
void* ai_thread_func(void *arg);

// Sliding window functions
int sliding_window_init(struct sliding_window *window);
int sliding_window_update(struct sliding_window *window, uint64_t current_time);
int sliding_window_analyze(struct sliding_window *window);

// Event processing functions
int ai_process_event(const char *event_json);
int ai_analyze_sequence(struct event_sequence *sequence);
float ai_calculate_threat_score(struct event_sequence *sequence);

// Model functions
int ai_load_model(const char *model_path);
float ai_predict(const float *features, int feature_count);
int ai_save_model(const char *model_path);

// Utility functions
const char* ai_get_threat_level_name(float score);
int ai_is_suspicious_sequence(const struct event_sequence *sequence);
int ai_detect_attack_pattern(const struct event_sequence *sequence);

#endif // RAVN_AI_ENGINE_H
