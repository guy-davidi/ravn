/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Core Agent Interface
 * 
 * This file defines the interface for the core agent layer. It provides
 * the main entry point and core functionality for the ravn system.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#ifndef _ravn_CORE_AGENT_IF_H
#define _ravn_CORE_AGENT_IF_H

#include <stddef.h>
#include <stdint.h>

/**
 * Core agent version information
 */
#define CORE_AGENT_VERSION_MAJOR 1
#define CORE_AGENT_VERSION_MINOR 0
#define CORE_AGENT_VERSION_PATCH 0
#define CORE_AGENT_VERSION_STRING "1.0.0"

/**
 * Core agent configuration
 */
struct core_agent_config {
	uint16_t api_port;
	int daemon_mode;
	int verbose;
	int no_api;
	int no_ai;
	const char *config_file;
	const char *log_level;
};

/**
 * Core agent statistics
 */
struct core_agent_stats {
	uint64_t uptime_seconds;
	uint64_t events_processed;
	uint64_t threats_detected;
	uint64_t errors_encountered;
};

/**
 * core_agent_init() - Initialize core agent
 * @config: Agent configuration
 *
 * Initialize the core agent with the given configuration.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_agent_init(const struct core_agent_config *config);

/**
 * core_agent_run() - Run the core agent
 *
 * Run the main event processing loop.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_agent_run(void);

/**
 * core_agent_stop() - Stop the core agent
 *
 * Stop the core agent and cleanup resources.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_agent_stop(void);

/**
 * core_agent_get_stats() - Get core agent statistics
 * @stats: Pointer to store statistics
 *
 * Get current core agent statistics.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_agent_get_stats(struct core_agent_stats *stats);

#endif /* _ravn_CORE_AGENT_IF_H */
