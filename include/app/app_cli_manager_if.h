/* SPDX-License-Identifier: GPL-2.0 */
/*
 * CLI Management Application Layer Interface
 * 
 * This file defines the interface for the CLI management application layer.
 * It provides command-line interface functionality, API management, and user
 * interaction capabilities for the ravn security system.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#ifndef _ravn_APP_CLI_MANAGER_IF_H
#define _ravn_APP_CLI_MANAGER_IF_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "service/service_ai_decision_engine_if.h"
#include "abstraction/abstraction_event_processor_if.h"
#include "core/ebpf.h"

/* Forward declarations */
struct app_cli_manager;
struct app_cli_status;
struct app_cli_api_server;

/**
 * struct app_cli_api_server - API server structure
 * @running: Whether the server is running
 * @port: Server port number
 * @sockfd: Server socket file descriptor
 */
struct app_cli_api_server {
	int running;
	uint16_t port;
	int sockfd;
};

/**
 * struct app_cli_status - CLI manager status
 * @initialized: Whether the manager is initialized
 * @running: Whether the agent is running
 * @command_count: Number of commands processed
 * @ebpf_programs_loaded: Number of eBPF programs loaded
 * @ebpf_programs_attached: Number of eBPF programs attached
 * @event_stats: Event processing statistics
 * @ai_stats: AI engine statistics
 * @api_server_running: Whether API server is running
 */
struct app_cli_status {
	int initialized;
	int running;
	uint64_t command_count;
	uint32_t ebpf_programs_loaded;
	uint32_t ebpf_programs_attached;
	struct abstraction_event_stats event_stats;
	struct service_ai_engine_stats ai_stats;
	int api_server_running;
};

/**
 * struct app_cli_manager - CLI manager structure
 * @initialized: Whether the manager is initialized
 * @running: Whether the agent is running
 * @command_count: Number of commands processed
 * @ebpf_manager: eBPF program manager
 * @event_processor: Event processor
 * @ai_engine: AI decision engine
 * @api_server: API server
 */
struct app_cli_manager {
	int initialized;
	int running;
	uint64_t command_count;
	struct ebpf_manager ebpf_manager;
	struct abstraction_event_processor event_processor;
	struct service_ai_decision_engine ai_engine;
	struct app_cli_api_server api_server;
};

/**
 * app_cli_manager_init() - Initialize CLI manager
 * @manager: Pointer to CLI manager structure
 *
 * Initialize the CLI manager and prepare for command processing.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_manager_init(struct app_cli_manager *manager);

/**
 * app_cli_manager_cleanup() - Cleanup CLI manager
 * @manager: Pointer to CLI manager structure
 *
 * Cleanup the CLI manager and free all resources.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_manager_cleanup(struct app_cli_manager *manager);

/**
 * app_cli_start_agent() - Start the ravn agent
 * @manager: Pointer to CLI manager
 *
 * Start the ravn agent with all eBPF programs loaded and running.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_start_agent(struct app_cli_manager *manager);

/**
 * app_cli_stop_agent() - Stop the ravn agent
 * @manager: Pointer to CLI manager
 *
 * Stop the ravn agent and detach all eBPF programs.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_stop_agent(struct app_cli_manager *manager);

/**
 * app_cli_get_status() - Get agent status
 * @manager: Pointer to CLI manager
 * @status: Pointer to store status information
 *
 * Get current status of the ravn agent.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_get_status(struct app_cli_manager *manager, struct app_cli_status *status);

/**
 * app_cli_process_events() - Process events from eBPF programs
 * @manager: Pointer to CLI manager
 * @timeout_ms: Poll timeout in milliseconds
 *
 * Process events from eBPF programs and run them through the AI engine.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_process_events(struct app_cli_manager *manager, int timeout_ms);

/**
 * app_cli_init_api_server() - Initialize API server
 * @server: Pointer to API server structure
 *
 * Initialize the API server for external communication.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_init_api_server(struct app_cli_api_server *server);

/**
 * app_cli_start_api_server() - Start API server
 * @server: Pointer to API server structure
 *
 * Start the API server for external communication.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_start_api_server(struct app_cli_api_server *server);

/**
 * app_cli_stop_api_server() - Stop API server
 * @server: Pointer to API server structure
 *
 * Stop the API server.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_stop_api_server(struct app_cli_api_server *server);

#endif /* _ravn_APP_CLI_MANAGER_IF_H */
