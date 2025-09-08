#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#include "daemon/ebpf_handler.h"
#include "daemon/redis_client.h"
#include "daemon/ai_engine.h"

// Global variables for cleanup
static int daemon_running = 0;
static redis_connection_t *redis_conn = NULL;
static ai_engine_t *ai_engine = NULL;
static pthread_t ai_thread;
static int ai_thread_running = 0;

// Global Redis connection pointer for eBPF handler
void* global_redis_conn_ptr = NULL;

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
        usleep(10000); // 10ms delay
    }
    
    printf("[AI-THREAD] AI analysis thread stopped\n");
    return NULL;
}

// Initialize daemon components in proper layered order
int init_daemon() {
    printf("[RAVN] Initializing daemon components in layered architecture...\n");
    
    // Layer 1: Initialize eBPF handlers (lowest level - system monitoring)
    printf("[RAVN] Layer 1: Initializing eBPF system monitoring...\n");
    if (init_ebpf_handlers() != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize eBPF handlers\n");
        return -1;
    }
    printf("[RAVN] ✓ eBPF handlers initialized\n");
    
    // Layer 2: Initialize Redis database (middle layer - data storage)
    printf("[RAVN] Layer 2: Initializing Redis database connection...\n");
    redis_conn = redis_connect("127.0.0.1", 6379);
    if (!redis_conn) {
        fprintf(stderr, "[ERROR] Failed to connect to Redis\n");
        cleanup_ebpf_handlers(); // Cleanup eBPF layer
        return -1;
    }
    printf("[RAVN] ✓ Redis database connected\n");
    
    // Set global Redis connection pointer for eBPF handler
    global_redis_conn_ptr = redis_conn;
    printf("[RAVN] ✓ Redis connection linked to eBPF handler\n");
    
    // Layer 3: Initialize AI engine (highest level - analysis)
    printf("[RAVN] Layer 3: Initializing AI analysis engine...\n");
    ai_engine = ai_engine_init("models/ravn_model.bin");
    if (!ai_engine) {
        fprintf(stderr, "[ERROR] Failed to initialize AI engine\n");
        redis_disconnect(redis_conn); // Cleanup Redis layer
        cleanup_ebpf_handlers();      // Cleanup eBPF layer
        return -1;
    }
    printf("[RAVN] ✓ AI engine initialized\n");
    
    printf("[RAVN] ✓ All layers initialized successfully\n");
    return 0;
}

// Cleanup daemon components in reverse layered order
void cleanup_daemon() {
    printf("[RAVN] Cleaning up daemon components in reverse layered order...\n");
    
    // Layer 3: Cleanup AI engine (highest level first)
    printf("[RAVN] Layer 3: Cleaning up AI analysis engine...\n");
    if (ai_thread_running) {
        ai_thread_running = 0;
        pthread_join(ai_thread, NULL);
        printf("[RAVN] ✓ AI thread stopped\n");
    }
    
    if (ai_engine) {
        ai_engine_cleanup(ai_engine);
        ai_engine = NULL;
        printf("[RAVN] ✓ AI engine cleaned up\n");
    }
    
    // Layer 2: Cleanup Redis database (middle layer)
    printf("[RAVN] Layer 2: Cleaning up Redis database connection...\n");
    if (redis_conn) {
        redis_disconnect(redis_conn);
        redis_conn = NULL;
        global_redis_conn_ptr = NULL;
        printf("[RAVN] ✓ Redis database disconnected\n");
    }
    
    // Layer 1: Cleanup eBPF handlers (lowest level last)
    printf("[RAVN] Layer 1: Cleaning up eBPF system monitoring...\n");
    cleanup_ebpf_handlers();
    printf("[RAVN] ✓ eBPF handlers cleaned up\n");
    
    printf("[RAVN] ✓ All layers cleaned up successfully\n");
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
    
    // Small delay to let AI thread initialize
    sleep(1);
    
    // Main monitoring loop - collect real events from eBPF
    printf("[RAVN] Main monitoring loop started - collecting real system events\n");
    
    while (daemon_running) {
        // The real event collection is now handled by the eBPF monitoring thread
        // This main loop just keeps the daemon alive and monitors system health
        
        // Check Redis connection health
        if (redis_ping(redis_conn) != 0) {
            printf("[RAVN] Redis connection lost, attempting to reconnect...\n");
            redis_disconnect(redis_conn);
            redis_conn = redis_connect("127.0.0.1", 6379);
            if (!redis_conn) {
                printf("[RAVN] Failed to reconnect to Redis\n");
                break;
            }
        }
        
        // Sleep for a longer interval since real events are handled by eBPF thread
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
    
    int display_counter = 0;
    while (1) {
        // Clear screen every 10 iterations for better display
        if (display_counter % 10 == 0) {
            printf("\033[2J\033[H"); // Clear screen and move cursor to top
            printf("=== RAVN Security Dashboard ===\n");
            printf("Press Ctrl+C to exit\n\n");
        }
        
        // Get latest threat level
        threat_level_t threat_level;
        if (redis_get_threat_level(redis_conn, &threat_level) == 0) {
            const char *level_str = (threat_level.level == THREAT_HIGH) ? "HIGH" :
                                   (threat_level.level == THREAT_MEDIUM) ? "MEDIUM" : "LOW";
            
            // Color coding for threat levels
            const char *color = (threat_level.level == THREAT_HIGH) ? "\033[31m" : // Red
                               (threat_level.level == THREAT_MEDIUM) ? "\033[33m" : // Yellow
                               "\033[32m"; // Green
            
            printf("%s[%ld] Threat Level: %s (Score: %.3f)%s\n", 
                   color, threat_level.timestamp, level_str, threat_level.score, "\033[0m");
            printf("Reason: %s\n", threat_level.reason);
        } else {
            printf("\033[33m[%ld] No threat data available\033[0m\n", time(NULL));
        }
        
        // Show Redis connection status
        if (redis_ping(redis_conn) == 0) {
            printf("\033[32mRedis: Connected\033[0m\n");
        } else {
            printf("\033[31mRedis: Disconnected\033[0m\n");
        }
        
        printf("---\n");
        fflush(stdout);
        display_counter++;
        sleep(2);
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
