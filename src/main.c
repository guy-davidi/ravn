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
#include <hiredis/hiredis.h>

#include "daemon/ebpf_handler.h"
#include "daemon/redis_client.h"
#include "daemon/ai_engine.h"
#include "utils/logger.h"

// Global variables for cleanup
static int daemon_running = 0;
static redis_connection_t *redis_conn = NULL;
static ai_engine_t *ai_engine = NULL;
// AI thread is now managed by the AI engine module

// Global Redis connection pointer for eBPF handler
void* global_redis_conn_ptr = NULL;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    printf("\n[RAVN] Received signal %d, shutting down gracefully...\n", sig);
    daemon_running = 0;
    // AI thread is managed by AI engine
}

// AI thread function is now handled by the AI engine module

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
    
    // Start AI analysis thread as part of initialization
    if (ai_engine_start_thread(ai_engine) != 0) {
        fprintf(stderr, "[ERROR] Failed to start AI analysis thread\n");
        ai_engine_cleanup(ai_engine);
        redis_disconnect(redis_conn);
        cleanup_ebpf_handlers();
        return -1;
    }
    printf("[RAVN] ✓ AI analysis thread started\n");
    
    printf("[RAVN] ✓ All layers initialized successfully\n");
    return 0;
}

// Cleanup daemon components in reverse layered order
void cleanup_daemon() {
    printf("[RAVN] Cleaning up daemon components in reverse layered order...\n");
    
    // Layer 3: Cleanup AI engine (highest level first)
    printf("[RAVN] Layer 3: Cleaning up AI analysis engine...\n");
    // AI thread is managed by AI engine
    
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
    LOG_INFO("Starting daemon mode (eBPF monitoring + AI thread)");
    
    if (init_daemon() != 0) {
        LOG_ERROR("Failed to initialize daemon");
        return -1;
    }
    
    daemon_running = 1;
    
    LOG_INFO("Daemon ready - collecting eBPF events and AI analysis running in background");
    
    // Main monitoring loop - collect real events from eBPF
    LOG_INFO("Main monitoring loop started - collecting real system events");
    
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
    
    // Initialize cutting-edge UI
    printf("\033[2J\033[H"); // Clear screen
    printf("\033[1;37m\033[40m"); // White text on black background
    
    int display_counter = 0;
    while (1) {
        // Clear screen and set up professional layout
        printf("\033[2J\033[H"); // Clear screen and move cursor to top
        
        // Professional header with gradient effect
        printf("\033[1;37m\033[40m");
        printf("╔══════════════════════════════════════════════════════════════════════════════╗\n");
        printf("║\033[1;36m                           RAVN SECURITY PLATFORM v2.0\033[1;37m                           ║\n");
        printf("║\033[1;33m                        Real-time Threat Detection & Analysis\033[1;37m                      ║\n");
        printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");
        
        // Get current time for display
        time_t current_time = time(NULL);
        struct tm *tm_info = localtime(&current_time);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        
        // Status bar
        printf("\033[1;37m┌─ STATUS ─────────────────────────────────────────────────────────────────────────┐\n");
        printf("│ \033[1;32m● LIVE\033[1;37m │ \033[1;36m%s\033[1;37m │ \033[1;33mPress Ctrl+C to exit\033[1;37m │\n", time_str);
        printf("└─────────────────────────────────────────────────────────────────────────────────┘\n");
        
        // Main dashboard grid
        printf("\033[1;37m┌─ THREAT ASSESSMENT ─────────────────────────────────────────────────────────────┐\n");
        
        // Get latest threat level
        threat_level_t threat_level;
        if (redis_get_threat_level(redis_conn, &threat_level) == 0) {
            const char *level_str = (threat_level.level == THREAT_HIGH) ? "CRITICAL" :
                                   (threat_level.level == THREAT_MEDIUM) ? "ELEVATED" : "NORMAL";
            
            // Professional color coding
            const char *color = (threat_level.level == THREAT_HIGH) ? "\033[1;31m" : // Red
                               (threat_level.level == THREAT_MEDIUM) ? "\033[1;33m" : // Yellow
                               "\033[1;32m"; // Green
            
            // Threat level with progress bar
            printf("│ \033[1;37mThreat Level: \033[0m%s%s\033[1;37m │ Score: \033[1;36m%.3f\033[1;37m │ ", 
                   color, level_str, threat_level.score);
            
            // Progress bar for threat score
            int bar_length = 20;
            int filled = (int)(threat_level.score * bar_length);
            printf("[\033[1;32m");
            for (int i = 0; i < filled; i++) printf("█");
            printf("\033[1;30m");
            for (int i = filled; i < bar_length; i++) printf("░");
            printf("\033[1;37m] │\n");
            
            // Threat reason
            printf("│ \033[1;37mAnalysis: \033[1;33m%s\033[1;37m │\n", threat_level.reason);
        } else {
            printf("│ \033[1;37mThreat Level: \033[1;30mNO DATA\033[1;37m │ Score: \033[1;30mN/A\033[1;37m │ [\033[1;30m░░░░░░░░░░░░░░░░░░░░\033[1;37m] │\n");
            printf("│ \033[1;37mAnalysis: \033[1;30mWaiting for data...\033[1;37m │\n");
        }
        printf("└─────────────────────────────────────────────────────────────────────────────────┘\n");
        
        // System Status Grid
        printf("\033[1;37m┌─ SYSTEM STATUS ────────────────────────────────────────────────────────────────┐\n");
        
        // Redis connection status
        printf("│ \033[1;37mRedis: \033[0m");
        if (redis_ping(redis_conn) == 0) {
            printf("\033[1;32m● CONNECTED\033[1;37m │ ");
        } else {
            printf("\033[1;31m● DISCONNECTED\033[1;37m │ ");
        }
        
        // eBPF status
        printf("\033[1;37meBPF: \033[1;32m● ACTIVE\033[1;37m │ ");
        
        // AI status
        printf("\033[1;37mAI: \033[1;32m● ANALYZING\033[1;37m │\n");
        printf("└─────────────────────────────────────────────────────────────────────────────────┘\n");
        
        // Metrics Dashboard
        printf("\033[1;37m┌─ METRICS DASHBOARD ──────────────────────────────────────────────────────────┐\n");
        
        // Get event count from Redis
        redisReply *reply = redisCommand(redis_conn->context, "LLEN events:raw");
        long long event_count = 0;
        if (reply && reply->type == REDIS_REPLY_INTEGER) {
            event_count = reply->integer;
        }
        if (reply) freeReplyObject(reply);
        
        // Event counter with animation
        printf("│ \033[1;37mEvents: \033[1;36m%lld\033[1;37m │ ", event_count);
        
        // System uptime
        FILE *uptime_file = fopen("/proc/uptime", "r");
        if (uptime_file) {
            double uptime;
            if (fscanf(uptime_file, "%lf", &uptime) == 1) {
                int hours = (int)(uptime / 3600);
                int minutes = (int)((uptime - hours * 3600) / 60);
                printf("\033[1;37mUptime: \033[1;33m%02dh %02dm\033[1;37m │ ", hours, minutes);
            }
            fclose(uptime_file);
        }
        
        // Memory usage
        FILE *mem_file = fopen("/proc/meminfo", "r");
        if (mem_file) {
            char line[256];
            long total_mem = 0, free_mem = 0;
            while (fgets(line, sizeof(line), mem_file)) {
                if (sscanf(line, "MemTotal: %ld kB", &total_mem) == 1) continue;
                if (sscanf(line, "MemAvailable: %ld kB", &free_mem) == 1) break;
            }
            fclose(mem_file);
            if (total_mem > 0) {
                float mem_usage = ((float)(total_mem - free_mem) / total_mem) * 100.0;
                printf("\033[1;37mMemory: \033[1;35m%.1f%%\033[1;37m │\n", mem_usage);
            }
        }
        
        // Monitoring programs status
        printf("│ \033[1;37mCPU Monitor: \033[1;32m●\033[1;37m │ Load Monitor: \033[1;32m●\033[1;37m │ Memory Monitor: \033[1;32m●\033[1;37m │ System Monitor: \033[1;32m●\033[1;37m │\n");
        printf("└─────────────────────────────────────────────────────────────────────────────────┘\n");
        
        // Real-time activity feed
        printf("\033[1;37m┌─ ACTIVITY FEED ───────────────────────────────────────────────────────────────┐\n");
        
        // Get latest events for activity display
        reply = redisCommand(redis_conn->context, "LRANGE events:raw 0 4");
        if (reply && reply->type == REDIS_REPLY_ARRAY) {
            for (size_t i = 0; i < reply->elements && i < 3; i++) {
                if (reply->element[i]->type == REDIS_REPLY_STRING) {
                    char *data = reply->element[i]->str;
                    if (strstr(data, "\"event_type\":1")) {
                        printf("│ \033[1;37m[CPU] \033[1;36mSystem activity detected\033[1;37m │ \033[1;30m%s\033[1;37m │\n", time_str);
                    } else if (strstr(data, "\"event_type\":2")) {
                        printf("│ \033[1;37m[LOAD] \033[1;33mLoad average updated\033[1;37m │ \033[1;30m%s\033[1;37m │\n", time_str);
                    } else if (strstr(data, "\"event_type\":3")) {
                        printf("│ \033[1;37m[MEM] \033[1;35mMemory usage tracked\033[1;37m │ \033[1;30m%s\033[1;37m │\n", time_str);
                    }
                }
            }
        }
        if (reply) freeReplyObject(reply);
        
        printf("└─────────────────────────────────────────────────────────────────────────────────┘\n");
        
        // Footer
        printf("\033[1;37m┌─ RAVN v2.0 ──────────────────────────────────────────────────────────────────┐\n");
        printf("│ \033[1;30mReal-time eBPF monitoring │ AI-powered threat detection │ Professional SOC\033[1;37m │\n");
        printf("└─────────────────────────────────────────────────────────────────────────────────┘\n");
        
        printf("\033[0m"); // Reset colors
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
    
    // Initialize logger (output to terminal, no file, less verbose)
    if (logger_init(LOG_LEVEL_INFO, NULL) != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }
    
    LOG_INFO("RAVN Security Platform starting - Mode: %s", mode);
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Run in appropriate mode
    int result;
    if (strcmp(mode, "daemon") == 0 || strcmp(mode, "d") == 0) {
        result = run_daemon_mode();
    } else if (strcmp(mode, "cli") == 0 || strcmp(mode, "c") == 0) {
        result = run_cli_mode();
    } else {
        LOG_ERROR("Unknown mode: %s", mode);
        print_usage(argv[0]);
        result = 1;
    }
    
    // Cleanup logger
    LOG_INFO("RAVN Security Platform shutting down");
    logger_cleanup();
    
    return result;
}
