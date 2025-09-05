/* SPDX-License-Identifier: GPL-2.0 */
/*
 * CLI Management Application Layer
 * 
 * This file implements the CLI management layer for ravn. It provides
 * command-line interface functionality, API management, and user interaction
 * capabilities for the ravn security system.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "app/app_cli_manager_if.h"
#include "service/service_ai_decision_engine_if.h"
#include "abstraction/abstraction_event_processor_if.h"
#include "core/ebpf.h"

/**
 * app_cli_manager_init() - Initialize CLI manager
 * @manager: Pointer to CLI manager structure
 *
 * Initialize the CLI manager and prepare for command processing.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_manager_init(struct app_cli_manager *manager)
{
	if (!manager) {
		fprintf(stderr, "app_cli_manager_init: manager is NULL\n");
		return -EINVAL;
	}

	/* Initialize manager structure */
	memset(manager, 0, sizeof(*manager));
	manager->initialized = 1;
	manager->running = 0;
	manager->command_count = 0;

	/* Initialize eBPF manager */
	if (ebpf_manager_init(&manager->ebpf_manager) < 0) {
		fprintf(stderr, "app_cli_manager_init: failed to init eBPF manager\n");
		return -errno;
	}

	/* Initialize event processor */
	if (abstraction_event_processor_init(&manager->event_processor) < 0) {
		fprintf(stderr, "app_cli_manager_init: failed to init event processor\n");
		ebpf_manager_cleanup(&manager->ebpf_manager);
		return -errno;
	}

	/* Initialize AI decision engine */
	if (service_ai_decision_engine_init(&manager->ai_engine) < 0) {
		fprintf(stderr, "app_cli_manager_init: failed to init AI engine\n");
		abstraction_event_processor_cleanup(&manager->event_processor);
		ebpf_manager_cleanup(&manager->ebpf_manager);
		return -errno;
	}

	/* Initialize API server */
	if (app_cli_init_api_server(&manager->api_server) < 0) {
		fprintf(stderr, "app_cli_manager_init: failed to init API server\n");
		service_ai_decision_engine_cleanup(&manager->ai_engine);
		abstraction_event_processor_cleanup(&manager->event_processor);
		ebpf_manager_cleanup(&manager->ebpf_manager);
		return -errno;
	}

	return 0;
}

/**
 * app_cli_manager_cleanup() - Cleanup CLI manager
 * @manager: Pointer to CLI manager structure
 *
 * Cleanup the CLI manager and free all resources.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_manager_cleanup(struct app_cli_manager *manager)
{
	if (!manager || !manager->initialized) {
		return -EINVAL;
	}

	/* Stop API server */
	app_cli_stop_api_server(&manager->api_server);

	/* Cleanup AI decision engine */
	service_ai_decision_engine_cleanup(&manager->ai_engine);

	/* Cleanup event processor */
	abstraction_event_processor_cleanup(&manager->event_processor);

	/* Cleanup eBPF manager */
	ebpf_manager_cleanup(&manager->ebpf_manager);

	/* Reset manager state */
	manager->initialized = 0;
	manager->running = 0;

	return 0;
}

/**
 * app_cli_start_agent() - Start the ravn agent
 * @manager: Pointer to CLI manager
 *
 * Start the ravn agent with all eBPF programs loaded and running.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_start_agent(struct app_cli_manager *manager)
{
	int err = 0;

	if (!manager || !manager->initialized) {
		return -EINVAL;
	}

	printf("[INFO] Starting ravn agent...\n");

	/* Load all eBPF programs */
	const char *programs[] = {
		EBPF_PROGRAM_EXECFS,
		EBPF_PROGRAM_NETWORK,
		EBPF_PROGRAM_SYSTEM,
		EBPF_PROGRAM_SECURITY,
		EBPF_PROGRAM_VULNERABILITY,
		EBPF_PROGRAM_UPDATE
	};

	const char *object_files[] = {
		"artifacts/core_execfs.bpf.o",
		"artifacts/core_network.bpf.o",
		"artifacts/core_system.bpf.o",
		"artifacts/core_security.bpf.o",
		"artifacts/core_vulnerability.bpf.o",
		"artifacts/core_update-checker.bpf.o"
	};

	/* Load eBPF programs */
	for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
		printf("[INFO] Loading eBPF program: %s\n", programs[i]);
		err = ebpf_program_load(&manager->ebpf_manager, programs[i], object_files[i]);
		if (err < 0) {
			fprintf(stderr, "[ERROR] Failed to load %s: %d\n", programs[i], err);
			continue; /* Continue loading other programs */
		}
	}

	/* Attach eBPF programs */
	for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
		printf("[INFO] Attaching eBPF program: %s\n", programs[i]);
		err = ebpf_program_attach(&manager->ebpf_manager, programs[i]);
		if (err < 0) {
			fprintf(stderr, "[ERROR] Failed to attach %s: %d\n", programs[i], err);
			continue; /* Continue attaching other programs */
		}
	}

	/* Start API server */
	printf("[INFO] Starting API server...\n");
	err = app_cli_start_api_server(&manager->api_server);
	if (err < 0) {
		fprintf(stderr, "[ERROR] Failed to start API server: %d\n", err);
		return err;
	}

	/* Mark agent as running */
	manager->running = 1;

	printf("[INFO] Agent started successfully\n");
	printf("[INFO] Monitoring system events...\n");

	return 0;
}

/**
 * app_cli_stop_agent() - Stop the ravn agent
 * @manager: Pointer to CLI manager
 *
 * Stop the ravn agent and detach all eBPF programs.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_stop_agent(struct app_cli_manager *manager)
{
	if (!manager || !manager->initialized) {
		return -EINVAL;
	}

	printf("[INFO] Stopping ravn agent...\n");

	/* Stop API server */
	app_cli_stop_api_server(&manager->api_server);

	/* Detach eBPF programs */
	const char *programs[] = {
		EBPF_PROGRAM_EXECFS,
		EBPF_PROGRAM_NETWORK,
		EBPF_PROGRAM_SYSTEM,
		EBPF_PROGRAM_SECURITY,
		EBPF_PROGRAM_VULNERABILITY,
		EBPF_PROGRAM_UPDATE
	};

	for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
		printf("[INFO] Detaching eBPF program: %s\n", programs[i]);
		ebpf_program_detach(&manager->ebpf_manager, programs[i]);
	}

	/* Mark agent as stopped */
	manager->running = 0;

	printf("[INFO] Agent stopped successfully\n");

	return 0;
}

/**
 * app_cli_get_status() - Get agent status
 * @manager: Pointer to CLI manager
 * @status: Pointer to store status information
 *
 * Get current status of the ravn agent.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_get_status(struct app_cli_manager *manager, struct app_cli_status *status)
{
	if (!manager || !status) {
		return -EINVAL;
	}

	/* Initialize status structure */
	memset(status, 0, sizeof(*status));

	/* Set basic status */
	status->initialized = manager->initialized;
	status->running = manager->running;
	status->command_count = manager->command_count;

	/* Get eBPF program status */
	const char *programs[] = {
		EBPF_PROGRAM_EXECFS,
		EBPF_PROGRAM_NETWORK,
		EBPF_PROGRAM_SYSTEM,
		EBPF_PROGRAM_SECURITY,
		EBPF_PROGRAM_VULNERABILITY,
		EBPF_PROGRAM_UPDATE
	};

	status->ebpf_programs_loaded = 0;
	status->ebpf_programs_attached = 0;

	for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
		int prog_status = ebpf_program_get_status(&manager->ebpf_manager, programs[i]);
		if (prog_status & EBPF_PROGRAM_LOADED) {
			status->ebpf_programs_loaded++;
		}
		if (prog_status & EBPF_PROGRAM_ATTACHED) {
			status->ebpf_programs_attached++;
		}
	}

	/* Get event processor statistics */
	abstraction_event_get_stats(&manager->event_processor, &status->event_stats);

	/* Get AI engine statistics */
	service_ai_get_engine_stats(&manager->ai_engine, &status->ai_stats);

	/* Get API server status */
	status->api_server_running = manager->api_server.running;

	return 0;
}

/**
 * app_cli_process_events() - Process events from eBPF programs
 * @manager: Pointer to CLI manager
 * @timeout_ms: Poll timeout in milliseconds
 *
 * Process events from eBPF programs and run them through the AI engine.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_process_events(struct app_cli_manager *manager, int timeout_ms)
{
	struct abstraction_event *event;
	struct service_ai_analysis analysis;
	int err = 0;

	if (!manager || !manager->initialized) {
		return -EINVAL;
	}

	/* Poll eBPF programs for events */
	err = ebpf_program_poll(&manager->ebpf_manager, timeout_ms);
	if (err < 0 && err != -EINTR) {
		fprintf(stderr, "app_cli_process_events: eBPF poll failed: %d\n", err);
		return err;
	}

	/* Process events from event processor */
	while (abstraction_event_dequeue(&manager->event_processor, &event) == 0) {
		/* Analyze event with AI engine */
		if (service_ai_analyze_event(&manager->ai_engine, event, &analysis) == 0) {
			/* Handle analysis results */
			if (analysis.is_threat) {
				printf("[THREAT] PID %d: %s (Score: %.1f, Level: %d)\n",
				       analysis.pid, event->comm, analysis.threat_score, analysis.threat_level);
				
				/* Print recommendations */
				for (uint32_t i = 0; i < analysis.recommendation_count; i++) {
					printf("[RECOMMEND] %s\n", analysis.recommendations[i]);
				}
			}

			/* Update baseline with event */
			service_ai_update_baseline(&manager->ai_engine, event);
		}

		/* Mark event as processed */
		abstraction_event_mark_processed(&manager->event_processor, event);
	}

	return 0;
}

/**
 * app_cli_init_api_server() - Initialize API server
 * @server: Pointer to API server structure
 *
 * Initialize the API server for external communication.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_init_api_server(struct app_cli_api_server *server)
{
	if (!server) {
		return -EINVAL;
	}

	/* Initialize server structure */
	memset(server, 0, sizeof(*server));
	server->port = 8080; /* Default port */
	server->running = 0;

	return 0;
}

/**
 * app_cli_start_api_server() - Start API server
 * @server: Pointer to API server structure
 *
 * Start the API server for external communication.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_start_api_server(struct app_cli_api_server *server)
{
	int sockfd;
	struct sockaddr_in serv_addr;

	if (!server) {
		return -EINVAL;
	}

	/* Create socket */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		return -errno;
	}

	/* Set up server address */
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(server->port);

	/* Bind socket */
	if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		close(sockfd);
		return -errno;
	}

	/* Listen for connections */
	if (listen(sockfd, 5) < 0) {
		close(sockfd);
		return -errno;
	}

	server->sockfd = sockfd;
	server->running = 1;

	printf("[INFO] API server started on port %d\n", server->port);

	return 0;
}

/**
 * app_cli_stop_api_server() - Stop API server
 * @server: Pointer to API server structure
 *
 * Stop the API server.
 *
 * Return: 0 on success, negative error code on failure
 */
int app_cli_stop_api_server(struct app_cli_api_server *server)
{
	if (!server) {
		return -EINVAL;
	}

	if (server->running && server->sockfd > 0) {
		close(server->sockfd);
		server->sockfd = -1;
	}

	server->running = 0;

	printf("[INFO] API server stopped\n");

	return 0;
}
