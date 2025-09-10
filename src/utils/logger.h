/*
 * RAVN Logger - Header File
 *
 * This header defines the logging interface for the RAVN security platform,
 * providing comprehensive logging capabilities with configurable levels,
 * output destinations, and formatting options for debugging and monitoring.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 *
 * The logger implements:
 * - Configurable log levels (DEBUG, INFO, WARN, ERROR, FATAL)
 * - Multiple output destinations (file, stdout, stderr)
 * - Color-coded output for terminal display
 * - Timestamp and thread ID support
 * - Module-specific logging with context
 * - Thread-safe logging operations
 *
 * Architecture:
 * - Centralized logging configuration
 * - Macro-based logging interface for performance
 * - Configurable output formatting
 * - Module-aware logging for better organization
 */

#ifndef RAVN_LOGGER_H
#define RAVN_LOGGER_H

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

/**
 * enum log_level_t - Log level enumeration
 * @LOG_LEVEL_DEBUG: Debug messages (lowest priority)
 * @LOG_LEVEL_INFO: Informational messages
 * @LOG_LEVEL_WARN: Warning messages
 * @LOG_LEVEL_ERROR: Error messages
 * @LOG_LEVEL_FATAL: Fatal error messages (highest priority)
 *
 * Defines the available log levels in order of increasing severity.
 * Messages below the configured level are not output.
 */
typedef enum {
	LOG_LEVEL_DEBUG = 0, /* Debug messages */
	LOG_LEVEL_INFO,	     /* Informational messages */
	LOG_LEVEL_WARN,	     /* Warning messages */
	LOG_LEVEL_ERROR,     /* Error messages */
	LOG_LEVEL_FATAL	     /* Fatal error messages */
} log_level_t;

/**
 * struct logger_config_t - Logger configuration structure
 * @level: Minimum log level to output
 * @use_colors: Enable color-coded output
 * @use_timestamps: Include timestamps in log messages
 * @use_thread_id: Include thread ID in log messages
 * @output_file: Output file handle (NULL for stdout/stderr)
 * @log_file_path: Path to log file
 *
 * Configuration structure for the logging system.
 */
typedef struct {
	log_level_t level;   /* Minimum log level */
	int use_colors;	     /* Color output flag */
	int use_timestamps;  /* Timestamp flag */
	int use_thread_id;   /* Thread ID flag */
	FILE* output_file;   /* Output file handle */
	char* log_file_path; /* Log file path */
} logger_config_t;

/*
 * Logger Initialization and Configuration Functions
 */

/**
 * logger_init - Initialize logging system
 * @level: Minimum log level to output
 * @log_file: Path to log file (NULL for stdout/stderr)
 *
 * Initializes the logging system with the specified configuration.
 * Must be called before any logging operations.
 *
 * Return: 0 on success, -1 on failure
 */
int logger_init(log_level_t level, const char* log_file);

/**
 * logger_set_level - Set minimum log level
 * @level: New minimum log level
 *
 * Changes the minimum log level for output. Messages below this
 * level will not be displayed.
 */
void logger_set_level(log_level_t level);

/**
 * logger_set_file - Set log output file
 * @file_path: Path to log file (NULL for stdout/stderr)
 *
 * Changes the output destination for log messages.
 */
void logger_set_file(const char* file_path);

/**
 * logger_set_colors - Enable/disable color output
 * @enable: 1 to enable colors, 0 to disable
 *
 * Enables or disables color-coded output for terminal display.
 */
void logger_set_colors(int enable);

/**
 * logger_set_timestamps - Enable/disable timestamps
 * @enable: 1 to enable timestamps, 0 to disable
 *
 * Enables or disables timestamp inclusion in log messages.
 */
void logger_set_timestamps(int enable);

/**
 * logger_set_thread_id - Enable/disable thread ID display
 * @enable: 1 to enable thread IDs, 0 to disable
 *
 * Enables or disables thread ID inclusion in log messages.
 */
void logger_set_thread_id(int enable);

/*
 * Core Logging Functions
 */

/**
 * logger_log - Log a message
 * @level: Log level for the message
 * @file: Source file name
 * @line: Source line number
 * @func: Function name
 * @format: printf-style format string
 * @...: Format arguments
 *
 * Core logging function that formats and outputs a log message.
 * This function is thread-safe and handles all formatting.
 */
void logger_log(log_level_t level, const char* file, int line, const char* func, const char* format,
		...);

/**
 * logger_log_with_module - Log a message with module context
 * @level: Log level for the message
 * @module: Module name for context
 * @file: Source file name
 * @line: Source line number
 * @func: Function name
 * @format: printf-style format string
 * @...: Format arguments
 *
 * Logs a message with additional module context for better organization.
 */
void logger_log_with_module(log_level_t level, const char* module, const char* file, int line,
			    const char* func, const char* format, ...);

/*
 * Convenience Logging Macros
 * These macros automatically include file, line, and function information.
 */

#define LOG_DEBUG(format, ...) \
	logger_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) \
	logger_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) \
	logger_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) \
	logger_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) \
	logger_log(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)

/*
 * Module-Specific Logging Macros
 * These macros include module context for better log organization.
 */

#define LOG_DEBUG_MODULE(module, format, ...)                                                 \
	logger_log_with_module(LOG_LEVEL_DEBUG, module, __FILE__, __LINE__, __func__, format, \
			       ##__VA_ARGS__)
#define LOG_INFO_MODULE(module, format, ...)                                                 \
	logger_log_with_module(LOG_LEVEL_INFO, module, __FILE__, __LINE__, __func__, format, \
			       ##__VA_ARGS__)
#define LOG_WARN_MODULE(module, format, ...)                                                 \
	logger_log_with_module(LOG_LEVEL_WARN, module, __FILE__, __LINE__, __func__, format, \
			       ##__VA_ARGS__)
#define LOG_ERROR_MODULE(module, format, ...)                                                 \
	logger_log_with_module(LOG_LEVEL_ERROR, module, __FILE__, __LINE__, __func__, format, \
			       ##__VA_ARGS__)
#define LOG_FATAL_MODULE(module, format, ...)                                                 \
	logger_log_with_module(LOG_LEVEL_FATAL, module, __FILE__, __LINE__, __func__, format, \
			       ##__VA_ARGS__)

/*
 * Utility Functions
 */

/**
 * logger_cleanup - Cleanup logging system
 *
 * Performs cleanup of the logging system, closing files and
 * freeing resources. Should be called before program exit.
 */
void logger_cleanup(void);

/**
 * logger_level_name - Get log level name
 * @level: Log level to get name for
 *
 * Returns the human-readable name for a log level.
 *
 * Return: Log level name string, "UNKNOWN" if invalid
 */
const char* logger_level_name(log_level_t level);

#endif // RAVN_LOGGER_H
