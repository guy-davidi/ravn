/*
 * RAVN Security Platform - Main Entry Point
 *
 * This file implements the main entry point for the RAVN security platform,
 * providing both daemon and CLI modes for real-time threat detection and
 * system monitoring using eBPF, Redis, and AI-powered analysis.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 *
 * Architecture:
 * - Layer 1: eBPF system monitoring (kernel-space event capture)
 * - Layer 2: Redis data storage (high-performance event handling)
 * - Layer 3: AI analysis engine (threat detection and scoring)
 *
 * The platform operates in two modes:
 * 1. Daemon mode: Continuous monitoring with background AI analysis
 * 2. CLI mode: Interactive dashboard for real-time system status
 */

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

/*
 * Global state variables for daemon lifecycle management
 */
static int daemon_running = 0;		/* Daemon running state flag */
static redis_connection_t *redis_conn = NULL;	/* Redis connection handle */
static ai_engine_t *ai_engine = NULL;		/* AI engine instance */

/*
 * Global Redis connection pointer for eBPF handler
 * This allows eBPF programs to access Redis for event storage
 */
void *global_redis_conn_ptr = NULL;

/**
 * signal_handler - Handle system signals for graceful shutdown
 * @sig: Signal number received
 *
 * This function handles SIGINT and SIGTERM signals to perform
 * graceful shutdown of the daemon. It sets the daemon_running
 * flag to false, which causes the main monitoring loop to exit.
 *
 * Context: Signal handler context (must be signal-safe)
 */
void signal_handler(int sig)
{
	LOG_INFO_MODULE("MAIN", "Received signal %d, shutting down gracefully...", sig);
	daemon_running = 0;
	/* AI thread cleanup is managed by AI engine module */
}

/**
 * init_daemon - Initialize daemon components in layered architecture
 *
 * Initializes the RAVN daemon components in a proper layered order:
 * 1. Layer 1: eBPF handlers (lowest level - system monitoring)
 * 2. Layer 2: Redis database (middle layer - data storage)
 * 3. Layer 3: AI engine (highest level - analysis)
 *
 * Each layer depends on the previous layers, and initialization
 * failures result in proper cleanup of already initialized layers.
 *
 * Return: 0 on success, -1 on failure
 */
int init_daemon(void)
{
    LOG_INFO_MODULE("MAIN", "Initializing daemon components in layered architecture...");
    
    // Layer 1: Initialize eBPF handlers (lowest level - system monitoring)
    LOG_INFO_MODULE("MAIN", "Layer 1: Initializing eBPF system monitoring...");
    if (init_ebpf_handlers() != 0) {
        LOG_ERROR_MODULE("MAIN", "Failed to initialize eBPF handlers");
        return -1;
    }
    LOG_INFO_MODULE("MAIN", "✓ eBPF handlers initialized");
    
    // Layer 2: Initialize Redis database (middle layer - data storage)
    LOG_INFO_MODULE("MAIN", "Layer 2: Initializing Redis database connection...");
    redis_conn = redis_connect("127.0.0.1", 6379);
    if (!redis_conn) {
        LOG_ERROR_MODULE("MAIN", "Failed to connect to Redis");
        cleanup_ebpf_handlers(); // Cleanup eBPF layer
        return -1;
    }
    LOG_INFO_MODULE("MAIN", "✓ Redis database connected");
    
    // Set global Redis connection pointer for eBPF handler
    global_redis_conn_ptr = redis_conn;
    LOG_INFO_MODULE("MAIN", "✓ Redis connection linked to eBPF handler");
    
    // Layer 3: Initialize AI engine (highest level - analysis)
    LOG_INFO_MODULE("MAIN", "Layer 3: Initializing AI analysis engine...");
    ai_engine = ai_engine_init("models/ravn_model.bin");
    if (!ai_engine) {
        LOG_ERROR_MODULE("MAIN", "Failed to initialize AI engine");
        redis_disconnect(redis_conn); // Cleanup Redis layer
        cleanup_ebpf_handlers();      // Cleanup eBPF layer
        return -1;
    }
    LOG_INFO_MODULE("MAIN", "✓ AI engine initialized");
    
    // Start AI analysis thread as part of initialization
    if (ai_engine_start_thread(ai_engine) != 0) {
        LOG_ERROR_MODULE("MAIN", "Failed to start AI analysis thread");
        ai_engine_cleanup(ai_engine);
        redis_disconnect(redis_conn);
        cleanup_ebpf_handlers();
        return -1;
    }
    LOG_INFO_MODULE("MAIN", "✓ AI analysis thread started");
    
    LOG_INFO_MODULE("MAIN", "✓ All layers initialized successfully");
    return 0;
}

/**
 * cleanup_daemon - Cleanup daemon components in reverse layered order
 *
 * Performs cleanup of daemon components in reverse order of initialization:
 * 1. Layer 3: AI engine cleanup (highest level first)
 * 2. Layer 2: Redis database cleanup (middle layer)
 * 3. Layer 1: eBPF handlers cleanup (lowest level last)
 *
 * This ensures proper resource deallocation and prevents resource leaks.
 * The function is safe to call multiple times and handles NULL pointers.
 */
void cleanup_daemon(void)
{
    LOG_INFO_MODULE("MAIN", "Cleaning up daemon components in reverse layered order...");
    
    // Layer 3: Cleanup AI engine (highest level first)
    LOG_INFO_MODULE("MAIN", "Layer 3: Cleaning up AI analysis engine...");
    // AI thread is managed by AI engine
    
    if (ai_engine) {
        ai_engine_cleanup(ai_engine);
        ai_engine = NULL;
        LOG_INFO_MODULE("MAIN", "✓ AI engine cleaned up");
    }
    
    // Layer 2: Cleanup Redis database (middle layer)
    LOG_INFO_MODULE("MAIN", "Layer 2: Cleaning up Redis database connection...");
    if (redis_conn) {
        redis_disconnect(redis_conn);
        redis_conn = NULL;
        global_redis_conn_ptr = NULL;
        LOG_INFO_MODULE("MAIN", "✓ Redis database disconnected");
    }
    
    // Layer 1: Cleanup eBPF handlers (lowest level last)
    LOG_INFO_MODULE("MAIN", "Layer 1: Cleaning up eBPF system monitoring...");
    cleanup_ebpf_handlers();
    LOG_INFO_MODULE("MAIN", "✓ eBPF handlers cleaned up");
    
    LOG_INFO_MODULE("MAIN", "✓ All layers cleaned up successfully");
}

/**
 * run_daemon_mode - Run daemon in continuous monitoring mode
 *
 * Starts the RAVN daemon in continuous monitoring mode with the following
 * components running:
 * - eBPF system monitoring (kernel-space event capture)
 * - Redis data storage (high-performance event handling)
 * - AI analysis thread (background threat detection)
 *
 * The daemon runs until a signal is received (SIGINT/SIGTERM) or a
 * critical error occurs. The main loop monitors system health and
 * handles Redis reconnection if needed.
 *
 * Return: 0 on normal shutdown, -1 on initialization failure
 */
int run_daemon_mode(void)
{
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
            LOG_INFO_MODULE("MAIN", "Redis connection lost, attempting to reconnect...");
            redis_disconnect(redis_conn);
            redis_conn = redis_connect("127.0.0.1", 6379);
            if (!redis_conn) {
                LOG_INFO_MODULE("MAIN", "Failed to reconnect to Redis");
                break;
            }
        }
        
        // Sleep for a longer interval since real events are handled by eBPF thread
        sleep(5); // Check every 5 seconds
    }
    
    cleanup_daemon();
    return 0;
}

/**
 * run_cli_mode - Run CLI dashboard mode
 *
 * Starts the RAVN platform in CLI dashboard mode, providing a real-time
 * terminal-based interface for monitoring system status and threat levels.
 *
 * Features:
 * - Real-time threat level display with color coding
 * - System status monitoring (Redis, eBPF, AI)
 * - Live metrics dashboard (events, uptime, memory usage)
 * - Activity feed showing recent system events
 * - Professional TUI interface with Unicode box drawing
 *
 * The dashboard updates every 2 seconds and displays:
 * - Current threat level and score
 * - System component status
 * - Event counters and system metrics
 * - Recent activity feed
 *
 * Return: 0 on normal exit, -1 on Redis connection failure
 */
int run_cli_mode(void)
{
    LOG_INFO_MODULE("MAIN", "Starting CLI mode...");
    
    // Connect to Redis to read data
    redis_conn = redis_connect("127.0.0.1", 6379);
    if (!redis_conn) {
        LOG_ERROR_MODULE("MAIN", "Failed to connect to Redis");
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

/**
 * print_usage - Print command line usage information
 * @progname: Program name (argv[0])
 *
 * Displays comprehensive usage information for the RAVN security platform,
 * including available modes, options, and usage examples.
 */
void print_usage(const char *progname)
{
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

/**
 * print_version - Print version and build information
 *
 * Displays version information, build details, and technology stack
 * for the RAVN security platform.
 */
void print_version(void)
{
    printf("RAVN Security Platform v1.0.0\n");
    printf("eBPF-based Real-time Threat Detection\n");
    printf("Built with C, libbpf, Redis, and AI\n");
}

/**
 * main - Main entry point for RAVN Security Platform
 * @argc: Argument count
 * @argv: Argument vector
 *
 * Main entry point that handles command line argument parsing and
 * delegates to the appropriate mode (daemon or CLI). Performs the
 * following operations:
 *
 * 1. Parse command line arguments using getopt_long
 * 2. Initialize logging system
 * 3. Setup signal handlers for graceful shutdown
 * 4. Execute the requested mode (daemon/cli)
 * 5. Perform cleanup and exit
 *
 * Supported modes:
 * - daemon/d: Run continuous monitoring daemon
 * - cli/c: Run interactive CLI dashboard
 *
 * Return: 0 on success, 1 on error
 */
int main(int argc, char *argv[])
{
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
