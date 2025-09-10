/*
 * RAVN Error Handling - Header File
 *
 * This header defines elegant error handling macros and utilities for the RAVN
 * security platform, providing consistent error handling patterns across the
 * entire codebase with automatic logging and cleanup.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 *
 * The error handling system implements:
 * - Elegant error checking macros with automatic logging
 * - Resource cleanup macros for RAII-style programming
 * - Error propagation with context preservation
 * - Consistent error return patterns
 * - Automatic error message formatting
 *
 * Architecture:
 * - Macro-based error handling for performance
 * - Context-aware error reporting
 * - Automatic resource cleanup
 * - Consistent error codes and messages
 */

#ifndef RAVN_ERROR_HANDLING_H
#define RAVN_ERROR_HANDLING_H

#include "logger.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Error handling return codes
 */
#define RAVN_SUCCESS	   0
#define RAVN_ERROR	   -1
#define RAVN_ERROR_NULL	   -2
#define RAVN_ERROR_INVALID -3
#define RAVN_ERROR_MEMORY  -4
#define RAVN_ERROR_IO	   -5
#define RAVN_ERROR_NETWORK -6
#define RAVN_ERROR_TIMEOUT -7

/**
 * Basic error checking macros
 */
#define RAVN_CHECK_NULL(ptr, module, msg)                                  \
	do {                                                               \
		if ((ptr) == NULL) {                                       \
			LOG_ERROR_MODULE(module, "NULL pointer: %s", msg); \
			return RAVN_ERROR_NULL;                            \
		}                                                          \
	} while (0)

#define RAVN_CHECK_NULL_VOID(ptr, module, msg)                             \
	do {                                                               \
		if ((ptr) == NULL) {                                       \
			LOG_ERROR_MODULE(module, "NULL pointer: %s", msg); \
			return;                                            \
		}                                                          \
	} while (0)

#define RAVN_CHECK_ERROR(result, module, msg)                                                      \
	do {                                                                                       \
		if ((result) != RAVN_SUCCESS) {                                                    \
			LOG_ERROR_MODULE(module, "Operation failed: %s (error: %d)", msg, result); \
			return result;                                                             \
		}                                                                                  \
	} while (0)

#define RAVN_CHECK_ERROR_VOID(result, module, msg)                                                 \
	do {                                                                                       \
		if ((result) != RAVN_SUCCESS) {                                                    \
			LOG_ERROR_MODULE(module, "Operation failed: %s (error: %d)", msg, result); \
			return;                                                                    \
		}                                                                                  \
	} while (0)

#define RAVN_CHECK_SYSCALL(result, module, operation)                                      \
	do {                                                                               \
		if ((result) == -1) {                                                      \
			LOG_ERROR_MODULE(module, "System call failed: %s - %s", operation, \
					 strerror(errno));                                 \
			return RAVN_ERROR;                                                 \
		}                                                                          \
	} while (0)

/**
 * Resource management macros
 */
#define RAVN_CLEANUP_ON_ERROR(cleanup_func, ...)                                                  \
	do {                                                                                      \
		int _ravn_result = (cleanup_func)(__VA_ARGS__);                                   \
		if (_ravn_result != RAVN_SUCCESS) {                                               \
			LOG_WARN_MODULE("CLEANUP", "Cleanup function failed: %s", #cleanup_func); \
		}                                                                                 \
	} while (0)

#define RAVN_FREE_IF_NOT_NULL(ptr)    \
	do {                          \
		if ((ptr) != NULL) {  \
			free(ptr);    \
			(ptr) = NULL; \
		}                     \
	} while (0)

#define RAVN_CLOSE_IF_VALID(fd)    \
	do {                       \
		if ((fd) >= 0) {   \
			close(fd); \
			(fd) = -1; \
		}                  \
	} while (0)

/**
 * Function result checking with automatic cleanup
 */
#define RAVN_CALL_WITH_CLEANUP(func, cleanup_func, module, msg)      \
	do {                                                         \
		int _ravn_result = (func);                           \
		if (_ravn_result != RAVN_SUCCESS) {                  \
			LOG_ERROR_MODULE(module, "Failed: %s", msg); \
			RAVN_CLEANUP_ON_ERROR(cleanup_func);         \
			return _ravn_result;                         \
		}                                                    \
	} while (0)

#define RAVN_CALL_WITH_CLEANUP_ARGS(func, cleanup_func, cleanup_args, module, msg) \
	do {                                                                       \
		int _ravn_result = (func);                                         \
		if (_ravn_result != RAVN_SUCCESS) {                                \
			LOG_ERROR_MODULE(module, "Failed: %s", msg);               \
			RAVN_CLEANUP_ON_ERROR(cleanup_func, cleanup_args);         \
			return _ravn_result;                                       \
		}                                                                  \
	} while (0)

/**
 * Memory allocation with error handling
 */
#define RAVN_MALLOC(ptr, size, module)                                                         \
	do {                                                                                   \
		(ptr) = malloc(size);                                                          \
		if ((ptr) == NULL) {                                                           \
			LOG_ERROR_MODULE(module, "Memory allocation failed: %zu bytes", size); \
			return RAVN_ERROR_MEMORY;                                              \
		}                                                                              \
		memset((ptr), 0, size);                                                        \
	} while (0)

#define RAVN_CALLOC(ptr, count, size, module)                                                 \
	do {                                                                                  \
		(ptr) = calloc(count, size);                                                  \
		if ((ptr) == NULL) {                                                          \
			LOG_ERROR_MODULE(module, "Memory allocation failed: %zu * %zu bytes", \
					 count, size);                                        \
			return RAVN_ERROR_MEMORY;                                             \
		}                                                                             \
	} while (0)

/**
 * File operations with error handling
 */
#define RAVN_FOPEN(file, path, mode, module)                                           \
	do {                                                                           \
		(file) = fopen(path, mode);                                            \
		if ((file) == NULL) {                                                  \
			LOG_ERROR_MODULE(module, "Failed to open file: %s - %s", path, \
					 strerror(errno));                             \
			return RAVN_ERROR_IO;                                          \
		}                                                                      \
	} while (0)

#define RAVN_FCLOSE(file, module)                                                   \
	do {                                                                        \
		if ((file) != NULL) {                                               \
			if (fclose(file) != 0) {                                    \
				LOG_WARN_MODULE(module, "Failed to close file: %s", \
						strerror(errno));                   \
			}                                                           \
			(file) = NULL;                                              \
		}                                                                   \
	} while (0)

/**
 * Network operations with error handling
 */
#define RAVN_CHECK_REDIS_RESULT(reply, module, operation)                                          \
	do {                                                                                       \
		if ((reply) == NULL) {                                                             \
			LOG_ERROR_MODULE(module, "Redis operation failed: %s - No reply",          \
					 operation);                                               \
			return RAVN_ERROR_NETWORK;                                                 \
		}                                                                                  \
		if ((reply)->type == REDIS_REPLY_ERROR) {                                          \
			LOG_ERROR_MODULE(module, "Redis error: %s - %s", operation, (reply)->str); \
			freeReplyObject(reply);                                                    \
			return RAVN_ERROR_NETWORK;                                                 \
		}                                                                                  \
	} while (0)

/**
 * Validation macros
 */
#define RAVN_CHECK_RANGE(value, min, max, module, name)                 \
	do {                                                            \
		if ((value) < (min) || (value) > (max)) {               \
			LOG_ERROR_MODULE(module,                        \
					 "Value out of range: %s = %d " \
					 "(expected: %d-%d)",           \
					 name, value, min, max);        \
			return RAVN_ERROR_INVALID;                      \
		}                                                       \
	} while (0)

#define RAVN_CHECK_SIZE(size, expected, module, name)                                             \
	do {                                                                                      \
		if ((size) != (expected)) {                                                       \
			LOG_ERROR_MODULE(module, "Size mismatch: %s = %zu (expected: %zu)", name, \
					 size, expected);                                         \
			return RAVN_ERROR_INVALID;                                                \
		}                                                                                 \
	} while (0)

/**
 * Error propagation macros
 */
#define RAVN_PROPAGATE_ERROR(result, module, context)                                   \
	do {                                                                            \
		if ((result) != RAVN_SUCCESS) {                                         \
			LOG_ERROR_MODULE(module, "Error propagated from: %s", context); \
			return result;                                                  \
		}                                                                       \
	} while (0)

#define RAVN_LOG_AND_RETURN(result, module, msg)     \
	do {                                         \
		LOG_ERROR_MODULE(module, "%s", msg); \
		return result;                       \
	} while (0)

/**
 * Debug and trace macros
 */
#define RAVN_DEBUG_CALL(module, func, ...)                                        \
	do {                                                                      \
		LOG_DEBUG_MODULE(module, "Calling: %s", #func);                   \
		int _ravn_result = func(__VA_ARGS__);                             \
		LOG_DEBUG_MODULE(module, "Result: %s = %d", #func, _ravn_result); \
	} while (0)

#define RAVN_TRACE_ENTER(module, func) LOG_DEBUG_MODULE(module, "Entering: %s", func)

#define RAVN_TRACE_EXIT(module, func, result) \
	LOG_DEBUG_MODULE(module, "Exiting: %s (result: %d)", func, result)

/**
 * Performance measurement macros
 */
#define RAVN_TIME_START(var)                    \
	struct timespec var##_start, var##_end; \
	clock_gettime(CLOCK_MONOTONIC, &var##_start)

#define RAVN_TIME_END(var, module, operation)                                           \
	do {                                                                            \
		clock_gettime(CLOCK_MONOTONIC, &var##_end);                             \
		long var##_ns = (var##_end.tv_sec - var##_start.tv_sec) * 1000000000L + \
				(var##_end.tv_nsec - var##_start.tv_nsec);              \
		LOG_DEBUG_MODULE(module, "Timing: %s took %ld.%03ld ms", operation,     \
				 var##_ns / 1000000, (var##_ns % 1000000) / 1000);      \
	} while (0)

/**
 * Assertion macros for debugging
 */
#ifdef DEBUG
#define RAVN_ASSERT(condition, module, msg)                                                     \
	do {                                                                                    \
		if (!(condition)) {                                                             \
			LOG_ERROR_MODULE(module, "Assertion failed: %s - %s", #condition, msg); \
			abort();                                                                \
		}                                                                               \
	} while (0)
#else
#define RAVN_ASSERT(condition, module, msg) ((void)0)
#endif

/**
 * Error context structure for detailed error reporting
 */
typedef struct {
	const char* file;
	int line;
	const char* function;
	const char* module;
	int error_code;
	char message[256];
} ravn_error_context_t;

/**
 * Error context macros
 */
#define RAVN_ERROR_CONTEXT_INIT(ctx, mod)                        \
	do {                                                     \
		(ctx).file = __FILE__;                           \
		(ctx).line = __LINE__;                           \
		(ctx).function = __func__;                       \
		(ctx).module = mod;                              \
		(ctx).error_code = RAVN_SUCCESS;                 \
		memset((ctx).message, 0, sizeof((ctx).message)); \
	} while (0)

#define RAVN_ERROR_CONTEXT_SET(ctx, code, msg)                             \
	do {                                                               \
		(ctx).error_code = code;                                   \
		snprintf((ctx).message, sizeof((ctx).message), "%s", msg); \
	} while (0)

#define RAVN_ERROR_CONTEXT_LOG(ctx)                                                         \
	LOG_ERROR_MODULE((ctx).module, "Error at %s:%d in %s(): %s (code: %d)", (ctx).file, \
			 (ctx).line, (ctx).function, (ctx).message, (ctx).error_code)

#endif // RAVN_ERROR_HANDLING_H
