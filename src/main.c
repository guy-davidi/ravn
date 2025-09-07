#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>

#include "daemon/ebpf_handler.h"
#include "daemon/redis_client.h"
#include "daemon/ai_engine.h"

// Global variables for cleanup
static int daemon_running = 0;
static redis_connection_t *redis_conn = NULL;
static ai_engine_t *ai_engine = NULL;
static pthread_t ai_thread;
static int ai_thread_running = 0;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    printf("\n[RAVN] Received signal %d, shutting down gracefully...\n", sig);
    daemon_running = 0;
    ai_thread_running = 0;
}

// AI thread function
void* ai_thread_func(void *arg) {
    printf("[AI-THREAD] AI analysis thread started\n");
    
    while (ai_thread_running) {
        // Get event from Redis
        struct ravn_event event;
        if (redis_get_event(redis_conn, &event) == 0) {
            // Process event with AI engine
            float threat_score = ai_engine_analyze_event(ai_engine, &event);
            
            // Update threat level in Redis
            threat_level_t threat_level = {
                .timestamp = event.timestamp,
                .score = threat_score,
                .level = (threat_score > 0.7) ? THREAT_HIGH : 
                        (threat_score > 0.4) ? THREAT_MEDIUM : THREAT_LOW
            };
            
            // Create threat reason
            snprintf(threat_level.reason, sizeof(threat_level.reason),
                    "AI analysis: PID=%d, Events=%d, Score=%.3f",
                    event.pid, ai_engine->window.process_count, threat_score);
            
            redis_update_threat_level(redis_conn, &threat_level);
            
            printf("[AI-THREAD] Event analyzed: PID=%d, Score=%.3f, Level=%d\n", 
                   event.pid, threat_score, threat_level.level);
        }
        
        // Small delay to prevent busy waiting
        sleep(0); // 10ms - using sleep(0) for now
    }
    
    printf("[AI-THREAD] AI analysis thread stopped\n");
    return NULL;
}

// Initialize daemon components
int init_daemon() {
    printf("[RAVN] Initializing daemon components...\n");
    
    // Initialize Redis connection
    redis_conn = redis_connect("127.0.0.1", 6379);
    if (!redis_conn) {
        fprintf(stderr, "[ERROR] Failed to connect to Redis\n");
        return -1;
    }
    printf("[RAVN] Connected to Redis\n");
    
    // Initialize AI engine
    ai_engine = ai_engine_init("models/ravn_model.bin");
    if (!ai_engine) {
        fprintf(stderr, "[ERROR] Failed to initialize AI engine\n");
        redis_disconnect(redis_conn);
        return -1;
    }
    printf("[RAVN] AI engine initialized\n");
    
    // Initialize eBPF handlers
    if (init_ebpf_handlers() != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize eBPF handlers\n");
        ai_engine_cleanup(ai_engine);
        redis_disconnect(redis_conn);
        return -1;
    }
    printf("[RAVN] eBPF handlers initialized\n");
    
    return 0;
}

// Cleanup daemon components
void cleanup_daemon() {
    printf("[RAVN] Cleaning up daemon components...\n");
    
    // Stop AI thread
    if (ai_thread_running) {
        ai_thread_running = 0;
        pthread_join(ai_thread, NULL);
        printf("[RAVN] AI thread stopped\n");
    }
    
    if (ai_engine) {
        ai_engine_cleanup(ai_engine);
        ai_engine = NULL;
    }
    
    if (redis_conn) {
        redis_disconnect(redis_conn);
        redis_conn = NULL;
    }
    
    cleanup_ebpf_handlers();
    printf("[RAVN] Cleanup completed\n");
}

// Daemon mode - main monitoring loop with AI thread
int run_daemon_mode() {
    printf("[RAVN] Starting daemon mode (eBPF monitoring + AI thread)...\n");
    
    if (init_daemon() != 0) {
        return -1;
    }
    
    daemon_running = 1;
    ai_thread_running = 1;
    
    // Start AI analysis thread
    if (pthread_create(&ai_thread, NULL, ai_thread_func, NULL) != 0) {
        fprintf(stderr, "[ERROR] Failed to create AI thread\n");
        cleanup_daemon();
        return -1;
    }
    
    printf("[RAVN] Daemon ready - collecting eBPF events and AI analysis running in background\n");
    
    // Main monitoring loop - collect and store events
    while (daemon_running) {
        // In a real implementation, this would:
        // 1. Collect eBPF events
        // 2. Convert to ravn_event format
        // 3. Send to Redis for AI thread to process
        
        // For now, just simulate event collection
        printf("[RAVN] Monitoring system events... (Press Ctrl+C to stop)\n");
        sleep(5); // Check every 5 seconds
    }
    
    cleanup_daemon();
    return 0;
}

// CLI mode - simple dashboard
int run_cli_mode() {
    printf("[RAVN] Starting CLI mode...\n");
    
    // Connect to Redis to read data
    redis_conn = redis_connect("127.0.0.1", 6379);
    if (!redis_conn) {
        fprintf(stderr, "[ERROR] Failed to connect to Redis\n");
        return -1;
    }
    
    printf("\n=== RAVN Security Dashboard ===\n");
    printf("Press Ctrl+C to exit\n\n");
    
    while (1) {
        // Get latest threat level
        threat_level_t threat_level;
        if (redis_get_threat_level(redis_conn, &threat_level) == 0) {
            const char *level_str = (threat_level.level == THREAT_HIGH) ? "HIGH" :
                                   (threat_level.level == THREAT_MEDIUM) ? "MEDIUM" : "LOW";
            
            printf("\r[%ld] Threat Level: %s (Score: %.3f)    ", 
                   threat_level.timestamp, level_str, threat_level.score);
            fflush(stdout);
        }
        
        sleep(1);
    }
    
    redis_disconnect(redis_conn);
    return 0;
}

// Print usage information
void print_usage(const char *progname) {
    printf("RAVN Security Platform - eBPF-based Threat Detection\n");
    printf("\nUsage: %s [OPTIONS] [MODE]\n", progname);
    printf("\nModes:\n");
    printf("  daemon, d    Run in daemon mode (monitoring)\n");
    printf("  cli, c       Run in CLI mode (dashboard)\n");
    printf("\nOptions:\n");
    printf("  -h, --help   Show this help message\n");
    printf("  -v, --version Show version information\n");
    printf("\nExamples:\n");
    printf("  %s daemon    # Start monitoring daemon\n", progname);
    printf("  %s cli       # Start CLI dashboard\n", progname);
    printf("  %s -h        # Show help\n", progname);
}

// Print version information
void print_version() {
    printf("RAVN Security Platform v1.0.0\n");
    printf("eBPF-based Real-time Threat Detection\n");
    printf("Built with C, libbpf, Redis, and AI\n");
}

int main(int argc, char *argv[]) {
    int opt;
    char *mode = NULL;
    
    // Long options
    static struct option long_options[] = {
        {"help",    no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    
    // Parse command line arguments
    while ((opt = getopt_long(argc, argv, "hv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Get mode from remaining arguments
    if (optind < argc) {
        mode = argv[optind];
    } else {
        print_usage(argv[0]);
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Run in appropriate mode
    if (strcmp(mode, "daemon") == 0 || strcmp(mode, "d") == 0) {
        return run_daemon_mode();
    } else if (strcmp(mode, "cli") == 0 || strcmp(mode, "c") == 0) {
        return run_cli_mode();
    } else {
        fprintf(stderr, "[ERROR] Unknown mode: %s\n", mode);
        print_usage(argv[0]);
        return 1;
    }
}
