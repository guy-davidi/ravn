/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ravn Main Agent
 * 
 * This file implements the main agent for ravn. It integrates all layers
 * (eBPF kernel layer, abstraction layer, service layer, and application layer)
 * to provide comprehensive Linux runtime security and observability.
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
#include <sys/stat.h>
#include <getopt.h>

#include "app/app_cli_manager_if.h"
#include "service/service_ai_decision_engine_if.h"
#include "abstraction/abstraction_event_processor_if.h"
#include "core/ebpf.h"

/* Global variables */
static struct app_cli_manager g_cli_manager;
static volatile int g_running = 1;
static volatile int g_signal_received = 0;

/**
 * signal_handler() - Signal handler for graceful shutdown
 * @sig: Signal number
 */
static void signal_handler(int sig)
{
	(void)sig; /* Suppress unused parameter warning */
	g_signal_received = 1;
	g_running = 0;
}

/**
 * print_usage() - Print usage information
 * @program_name: Name of the program
 */
static void print_usage(const char *program_name)
{
	printf("Usage: %s [OPTIONS]\n", program_name);
	printf("\n");
	printf("Options:\n");
	printf("  -h, --help              Show this help message\n");
	printf("  -d, --daemon            Run as daemon\n");
	printf("  -v, --verbose           Enable verbose output\n");
	printf("  -c, --config FILE       Configuration file path\n");
	printf("  -p, --port PORT         API server port (default: 8080)\n");
	printf("  -l, --log-level LEVEL   Log level (debug, info, warn, error)\n");
	printf("  --no-api                Disable API server\n");
	printf("  --no-ai                 Disable AI decision engine\n");
	printf("\n");
	printf("Examples:\n");
	printf("  %s                      # Run in foreground with default settings\n", program_name);
	printf("  %s -d                   # Run as daemon\n", program_name);
	printf("  %s -v -p 9090           # Run with verbose output on port 9090\n", program_name);
	printf("  %s --no-api             # Run without API server\n", program_name);
	printf("\n");
}

/**
 * print_version() - Print version information
 */
static void print_version(void)
{
	printf("ravn v1.0.0\n");
	printf("Linux Runtime Security & Observability Agent\n");
	printf("Built with eBPF technology\n");
	printf("\n");
}

/**
 * setup_signal_handlers() - Setup signal handlers
 */
static void setup_signal_handlers(void)
{
	struct sigaction sa;

	/* Setup signal handler for graceful shutdown */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
}

/**
 * daemonize() - Daemonize the process
 */
static void daemonize(void)
{
	pid_t pid, sid;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "daemonize: fork failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* If we got a good PID, then we can exit the parent process */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Change the file mode mask */
	umask(0);

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		fprintf(stderr, "daemonize: setsid failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Change the current working directory */
	if (chdir("/") < 0) {
		fprintf(stderr, "daemonize: chdir failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

/**
 * main_loop() - Main event processing loop
 * @manager: Pointer to CLI manager
 */
static void main_loop(struct app_cli_manager *manager)
{
	struct app_cli_status status;
	int event_count = 0;
	time_t last_status_time = time(NULL);

	printf("[INFO] Starting main event processing loop...\n");

	while (g_running && !g_signal_received) {
		/* Process events from eBPF programs */
		if (app_cli_process_events(manager, 1000) < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "[ERROR] Event processing failed: %s\n", strerror(errno));
				break;
			}
		}

		event_count++;

		/* Print status every 60 seconds */
		if (time(NULL) - last_status_time >= 60) {
			if (app_cli_get_status(manager, &status) == 0) {
				printf("[STATUS] Events: %lu, eBPF: %u/%u, AI: %lu threats, API: %s\n",
				       status.event_stats.total_events,
				       status.ebpf_programs_attached,
				       status.ebpf_programs_loaded,
				       status.ai_stats.threat_detected_count,
				       status.api_server_running ? "running" : "stopped");
			}
			last_status_time = time(NULL);
		}

		/* Check for signal */
		if (g_signal_received) {
			printf("[INFO] Signal received, shutting down...\n");
			break;
		}
	}

	printf("[INFO] Main loop exited after processing %d event cycles\n", event_count);
}

/**
 * main() - Main entry point
 * @argc: Argument count
 * @argv: Argument vector
 *
 * Main entry point for the ravn agent.
 *
 * Return: 0 on success, non-zero on failure
 */
int main(int argc, char *argv[])
{
	int opt;
	int daemon_mode = 0;
	int verbose = 0;
	int no_api = 0;
	int no_ai = 0;
	const char *config_file = NULL;
	uint16_t api_port = 8080;
	const char *log_level = "info";
	int err = 0;

	/* Suppress unused variable warnings */
	(void)no_api;
	(void)no_ai;
	(void)config_file;
	(void)log_level;
	(void)verbose;

	/* Long options */
	static struct option long_options[] = {
		{"help",      no_argument,       0, 'h'},
		{"daemon",    no_argument,       0, 'd'},
		{"verbose",   no_argument,       0, 'v'},
		{"config",    required_argument, 0, 'c'},
		{"port",      required_argument, 0, 'p'},
		{"log-level", required_argument, 0, 'l'},
		{"no-api",    no_argument,       0, 1000},
		{"no-ai",     no_argument,       0, 1001},
		{"version",   no_argument,       0, 1002},
		{0, 0, 0, 0}
	};

	/* Parse command line arguments */
	while ((opt = getopt_long(argc, argv, "hdvc:p:l:", long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			return EXIT_SUCCESS;
		case 'd':
			daemon_mode = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'p':
			api_port = (uint16_t)atoi(optarg);
			if (api_port == 0) {
				fprintf(stderr, "Invalid port number: %s\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'l':
			log_level = optarg;
			break;
		case 1000:
			no_api = 1;
			break;
		case 1001:
			no_ai = 1;
			break;
		case 1002:
			print_version();
			return EXIT_SUCCESS;
		case '?':
			print_usage(argv[0]);
			return EXIT_FAILURE;
		default:
			abort();
		}
	}

	/* Check for root privileges */
	if (geteuid() != 0) {
		fprintf(stderr, "ravn requires root privileges to load eBPF programs\n");
		return EXIT_FAILURE;
	}

	/* Setup signal handlers */
	setup_signal_handlers();

	/* Daemonize if requested */
	if (daemon_mode) {
		printf("[INFO] Daemonizing ravn...\n");
		daemonize();
	}

	/* Print startup banner */
	if (!daemon_mode) {
		printf("========================================\n");
		printf("    ravn - Linux Runtime Security\n");
		printf("========================================\n");
		printf("Version: 1.0.0\n");
		printf("Mode: %s\n", daemon_mode ? "daemon" : "foreground");
		printf("Verbose: %s\n", verbose ? "enabled" : "disabled");
		printf("API Port: %d\n", api_port);
		printf("Log Level: %s\n", log_level);
		if (config_file) {
			printf("Config: %s\n", config_file);
		}
		printf("========================================\n");
	}

	/* Initialize CLI manager */
	printf("[INFO] Initializing ravn components...\n");
	err = app_cli_manager_init(&g_cli_manager);
	if (err < 0) {
		fprintf(stderr, "[ERROR] Failed to initialize CLI manager: %d\n", err);
		return EXIT_FAILURE;
	}

	/* Configure API server port */
	g_cli_manager.api_server.port = api_port;

	/* Start the agent */
	printf("[INFO] Starting ravn agent...\n");
	err = app_cli_start_agent(&g_cli_manager);
	if (err < 0) {
		fprintf(stderr, "[ERROR] Failed to start agent: %d\n", err);
		app_cli_manager_cleanup(&g_cli_manager);
		return EXIT_FAILURE;
	}

	/* Run main event processing loop */
	main_loop(&g_cli_manager);

	/* Stop the agent */
	printf("[INFO] Stopping ravn agent...\n");
	app_cli_stop_agent(&g_cli_manager);

	/* Cleanup */
	printf("[INFO] Cleaning up ravn components...\n");
	app_cli_manager_cleanup(&g_cli_manager);

	printf("[INFO] ravn shutdown complete\n");

	return EXIT_SUCCESS;
}
