#include "logger.h"
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

// Global logger configuration
static logger_config_t g_logger_config = {
    .level = LOG_LEVEL_INFO,
    .use_colors = 1,
    .use_timestamps = 1,
    .use_thread_id = 0,
    .output_file = NULL,
    .log_file_path = NULL
};

// Thread-local storage for thread ID
static __thread char thread_id_str[16] = {0};

// Color codes for terminal output
#define COLOR_RESET   "\033[0m"
#define COLOR_DEBUG   "\033[36m"  // Cyan
#define COLOR_INFO    "\033[32m"  // Green
#define COLOR_WARN    "\033[33m"  // Yellow
#define COLOR_ERROR   "\033[31m"  // Red
#define COLOR_FATAL   "\033[35m"  // Magenta
#define COLOR_BOLD    "\033[1m"

// Initialize logger
int logger_init(log_level_t level, const char *log_file) {
    g_logger_config.level = level;
    
    if (log_file) {
        g_logger_config.log_file_path = strdup(log_file);
        g_logger_config.output_file = fopen(log_file, "a");
        if (!g_logger_config.output_file) {
            fprintf(stderr, "Failed to open log file: %s\n", log_file);
            return -1;
        }
    } else {
        g_logger_config.output_file = stderr;
    }
    
    // Initialize thread ID
    snprintf(thread_id_str, sizeof(thread_id_str), "%lu", pthread_self());
    
    LOG_INFO("Logger initialized - Level: %s, Output: %s", 
             logger_level_name(level), 
             log_file ? log_file : "stderr");
    
    return 0;
}

// Set log level
void logger_set_level(log_level_t level) {
    g_logger_config.level = level;
}

// Set output file
void logger_set_file(const char *file_path) {
    if (g_logger_config.output_file && g_logger_config.output_file != stderr) {
        fclose(g_logger_config.output_file);
    }
    
    if (g_logger_config.log_file_path) {
        free(g_logger_config.log_file_path);
    }
    
    if (file_path) {
        g_logger_config.log_file_path = strdup(file_path);
        g_logger_config.output_file = fopen(file_path, "a");
        if (!g_logger_config.output_file) {
            g_logger_config.output_file = stderr;
        }
    } else {
        g_logger_config.output_file = stderr;
    }
}

// Enable/disable colors
void logger_set_colors(int enable) {
    g_logger_config.use_colors = enable;
}

// Enable/disable timestamps
void logger_set_timestamps(int enable) {
    g_logger_config.use_timestamps = enable;
}

// Enable/disable thread IDs
void logger_set_thread_id(int enable) {
    g_logger_config.use_thread_id = enable;
}

// Get current log level name
const char* logger_level_name(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

// Get color code for log level
static const char* get_color_code(log_level_t level) {
    if (!g_logger_config.use_colors) {
        return "";
    }
    
    switch (level) {
        case LOG_LEVEL_DEBUG: return COLOR_DEBUG;
        case LOG_LEVEL_INFO:  return COLOR_INFO;
        case LOG_LEVEL_WARN:  return COLOR_WARN;
        case LOG_LEVEL_ERROR: return COLOR_ERROR;
        case LOG_LEVEL_FATAL: return COLOR_FATAL;
        default: return "";
    }
}

// Get timestamp string
static void get_timestamp(char *buffer, size_t size) {
    struct timeval tv;
    struct tm *tm_info;
    
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
    snprintf(buffer + strlen(buffer), size - strlen(buffer), ".%03ld", tv.tv_usec / 1000);
}

// Main logging function
void logger_log(log_level_t level, const char *file, int line, const char *func, const char *format, ...) {
    // Check if we should log this level
    if (level < g_logger_config.level) {
        return;
    }
    
    va_list args;
    char timestamp[32] = {0};
    char log_buffer[2048] = {0};
    char *color_start = "";
    char *color_end = "";
    
    // Get colors
    if (g_logger_config.use_colors) {
        color_start = (char*)get_color_code(level);
        color_end = COLOR_RESET;
    }
    
    // Get timestamp
    if (g_logger_config.use_timestamps) {
        get_timestamp(timestamp, sizeof(timestamp));
    }
    
    // Build log message
    int pos = 0;
    
    // Timestamp
    if (g_logger_config.use_timestamps) {
        pos += snprintf(log_buffer + pos, sizeof(log_buffer) - pos, "[%s] ", timestamp);
    }
    
    // Thread ID
    if (g_logger_config.use_thread_id) {
        pos += snprintf(log_buffer + pos, sizeof(log_buffer) - pos, "[TID:%s] ", thread_id_str);
    }
    
    // Log level with color
    pos += snprintf(log_buffer + pos, sizeof(log_buffer) - pos, "%s[%s]%s ", 
                    color_start, logger_level_name(level), color_end);
    
    // File:line:function
    pos += snprintf(log_buffer + pos, sizeof(log_buffer) - pos, "[%s:%d:%s] ", 
                    strrchr(file, '/') ? strrchr(file, '/') + 1 : file, line, func);
    
    // Format the actual message
    va_start(args, format);
    pos += vsnprintf(log_buffer + pos, sizeof(log_buffer) - pos, format, args);
    va_end(args);
    
    // Add newline
    if (pos < sizeof(log_buffer) - 1) {
        log_buffer[pos] = '\n';
        log_buffer[pos + 1] = '\0';
    }
    
    // Write to output
    fputs(log_buffer, g_logger_config.output_file);
    fflush(g_logger_config.output_file);
    
    // For fatal errors, also write to stderr if not already there
    if (level == LOG_LEVEL_FATAL && g_logger_config.output_file != stderr) {
        fputs(log_buffer, stderr);
        fflush(stderr);
    }
}

// Cleanup
void logger_cleanup(void) {
    if (g_logger_config.output_file && g_logger_config.output_file != stderr) {
        fclose(g_logger_config.output_file);
    }
    
    if (g_logger_config.log_file_path) {
        free(g_logger_config.log_file_path);
        g_logger_config.log_file_path = NULL;
    }
    
    g_logger_config.output_file = NULL;
}
