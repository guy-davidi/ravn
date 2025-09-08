#ifndef RAVN_LOGGER_H
#define RAVN_LOGGER_H

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>

// Log levels
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
} log_level_t;

// Log configuration
typedef struct {
    log_level_t level;
    int use_colors;
    int use_timestamps;
    int use_thread_id;
    FILE *output_file;
    char *log_file_path;
} logger_config_t;

// Initialize logger
int logger_init(log_level_t level, const char *log_file);

// Set log level
void logger_set_level(log_level_t level);

// Set output file
void logger_set_file(const char *file_path);

// Enable/disable colors
void logger_set_colors(int enable);

// Enable/disable timestamps
void logger_set_timestamps(int enable);

// Enable/disable thread IDs
void logger_set_thread_id(int enable);

// Logging functions
void logger_log(log_level_t level, const char *file, int line, const char *func, const char *format, ...);
void logger_log_with_module(log_level_t level, const char *module, const char *file, int line, const char *func, const char *format, ...);

// Convenience macros
#define LOG_DEBUG(format, ...) logger_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...)  logger_log(LOG_LEVEL_INFO,  __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...)  logger_log(LOG_LEVEL_WARN,  __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) logger_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) logger_log(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)

// Module-specific logging macros
#define LOG_DEBUG_MODULE(module, format, ...) logger_log_with_module(LOG_LEVEL_DEBUG, module, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_INFO_MODULE(module, format, ...)  logger_log_with_module(LOG_LEVEL_INFO,  module, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_WARN_MODULE(module, format, ...)  logger_log_with_module(LOG_LEVEL_WARN,  module, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_ERROR_MODULE(module, format, ...) logger_log_with_module(LOG_LEVEL_ERROR, module, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_FATAL_MODULE(module, format, ...) logger_log_with_module(LOG_LEVEL_FATAL, module, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)

// Cleanup
void logger_cleanup(void);

// Get current log level name
const char* logger_level_name(log_level_t level);

#endif // RAVN_LOGGER_H
