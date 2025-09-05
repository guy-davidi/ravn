/* SPDX-License-Identifier: MIT */
/*
 * RAVN - Cutting-Edge eBPF Runtime Security
 * 
 * This file demonstrates the cutting-edge 3-layer architecture with CRUD operations
 * and next-generation function naming conventions powered by eBPF, AI, and kernel technology.
 *
 * Author: Guy Davidi
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>

#include "ebpf/ebpf_program_if.h"
#include "storage/storage_database_if.h"
#include "security/security_analysis_if.h"

/* Global variables */
static volatile int g_running = 1;
static struct ebpf_program g_ebpf_programs[6];
static struct security_analysis g_security_analysis;
static const char *g_db_path = "ravn.db";

/**
 * signal_handler() - Signal handler for graceful shutdown
 * @sig: Signal number
 */
static void signal_handler(int sig)
{
	(void)sig; /* Suppress unused parameter warning */
	g_running = 0;
}

/**
 * setup_signal_handlers() - Setup signal handlers
 */
static void setup_signal_handlers(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
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
	printf("  --db FILE               Database file path (default: ravn.db)\n");
	printf("\n");
	printf("Examples:\n");
	printf("  %s                      # Run with default settings\n", program_name);
	printf("  %s -d                   # Run as daemon\n", program_name);
	printf("  %s -v --db /tmp/eb.db   # Run with verbose output and custom DB\n", program_name);
	printf("\n");
}

/**
 * print_version() - Print version information
 */
static void print_version(void)
{
	printf("RAVN v2.0.0 - Cutting-Edge Edition\n");
	printf("Linux Kernel Runtime Security & AI Observability\n");
	printf("Powered by eBPF, AI, and next-gen kernel technology\n");
	printf("\n");
}

/**
 * demo_crud_operations() - Demonstrate RAVN CRUD Operations
 */
static void demo_crud_operations(void)
{
	printf("\n=== RAVN CRUD Operations Demo ===\n");

	/* 1. CREATE - Initialize components */
	printf("\n1. CREATE Operations:\n");
	
	/* Create database */
	if (storage_database_create(g_db_path) == 0) {
		printf("   ✓ Database created: %s\n", g_db_path);
	} else {
		printf("   ✗ Failed to create database\n");
		return;
	}

	/* Create eBPF programs */
	const char *programs[] = {
		"execfs", "network", "system", "security", "vulnerability", "update-checker"
	};
	const char *object_files[] = {
		"artifacts/core_execfs.bpf.o",
		"artifacts/core_network.bpf.o", 
		"artifacts/core_system.bpf.o",
		"artifacts/core_security.bpf.o",
		"artifacts/core_vulnerability.bpf.o",
		"artifacts/core_update-checker.bpf.o"
	};

	for (int i = 0; i < 6; i++) {
		if (ebpf_program_create(&g_ebpf_programs[i], programs[i], object_files[i]) == 0) {
			printf("   ✓ eBPF program created: %s\n", programs[i]);
		} else {
			printf("   ✗ Failed to create eBPF program: %s\n", programs[i]);
		}
	}

	/* Create security analysis */
	struct security_analysis_config config = {
		.threat_threshold = 70.0,
		.anomaly_threshold = 2.0,
		.time_window_seconds = 60,
		.enabled = 1
	};
	
	if (security_analysis_create(&g_security_analysis, &config) == 0) {
		printf("   ✓ Security analysis created\n");
	} else {
		printf("   ✗ Failed to create security analysis\n");
	}

	/* 2. READ - Read status and data */
	printf("\n2. READ Operations:\n");
	
	/* Read eBPF program status */
	for (int i = 0; i < 6; i++) {
		struct ebpf_program_status status;
		if (ebpf_program_read(&g_ebpf_programs[i], &status) == 0) {
			printf("   ✓ eBPF program status: %s (state: %d, loaded: %d)\n", 
			       status.name, status.state, status.loaded);
		}
	}

	/* Read security analysis status */
	struct security_analysis_status analysis_status;
	if (security_analysis_read(&g_security_analysis, &analysis_status) == 0) {
		printf("   ✓ Security analysis status: enabled=%d, threshold=%.1f\n",
		       analysis_status.enabled, analysis_status.threat_threshold);
	}

	/* Read events from database */
	struct storage_event events[10];
	struct storage_event_filter filter = {
		.event_type = 0, /* All events */
		.min_timestamp = 0,
		.max_timestamp = 0,
		.pid = 0,
		.processed = -1
	};
	
	int event_count = storage_event_read(g_db_path, &filter, events, 10);
	if (event_count >= 0) {
		printf("   ✓ Read %d events from database\n", event_count);
	} else {
		printf("   ✓ No events in database (expected for new installation)\n");
	}

	/* 3. UPDATE - Update configurations */
	printf("\n3. UPDATE Operations:\n");
	
	/* Update eBPF program configuration */
	struct ebpf_program_config ebpf_config = {
		.enabled = 1,
		.priority = 10,
		.timeout_ms = 1000
	};
	
	for (int i = 0; i < 6; i++) {
		if (ebpf_program_update(&g_ebpf_programs[i], &ebpf_config) == 0) {
			printf("   ✓ eBPF program updated: %s\n", programs[i]);
		}
	}

	/* Update security analysis configuration */
	struct security_analysis_updates analysis_updates = {
		.threat_threshold = 75.0,
		.anomaly_threshold = 2.5,
		.time_window_seconds = 120,
		.enabled = 1
	};
	
	if (security_analysis_update(&g_security_analysis, &analysis_updates) == 0) {
		printf("   ✓ Security analysis updated\n");
	}

	/* Create a sample event and store it */
	struct storage_event sample_event = {
		.id = 0, /* Will be auto-generated */
		.timestamp_ns = time(NULL) * 1000000000ULL,
		.event_type = SECURITY_EVENT_SUSPICIOUS_PROCESS,
		.severity = SECURITY_SEVERITY_MEDIUM,
		.pid = 1234,
		.uid = 1000,
		.gid = 1000,
		.comm = "suspicious_proc",
		.filename = "/tmp/malicious_file",
		.raw_data = {0x01, 0x02, 0x03, 0x04},
		.raw_size = 4,
		.processed = 0
	};
	
	int event_id = storage_event_create(g_db_path, &sample_event);
	if (event_id > 0) {
		printf("   ✓ Sample event created with ID: %d\n", event_id);
		
		/* Update the event */
		struct storage_event_updates event_updates = {
			.processed = 1,
			.severity = SECURITY_SEVERITY_HIGH
		};
		
		if (storage_event_update(g_db_path, event_id, &event_updates) == 0) {
			printf("   ✓ Sample event updated\n");
		}
	}

	/* 4. DELETE - Cleanup operations */
	printf("\n4. DELETE Operations:\n");
	
	/* Delete the sample event */
	if (event_id > 0) {
		if (storage_event_delete(g_db_path, event_id) == 0) {
			printf("   ✓ Sample event deleted\n");
		}
	}

	/* Skip deleting eBPF programs - we need them for real-time monitoring */
	printf("   ✓ eBPF programs kept for real-time monitoring\n");

	/* Delete security analysis */
	if (security_analysis_delete(&g_security_analysis) == 0) {
		printf("   ✓ Security analysis deleted\n");
	}

	printf("\n=== RAVN CRUD Operations Demo Complete ===\n");
}

/**
 * main() - Main entry point
 * @argc: Argument count
 * @argv: Argument vector
 *
 * Main entry point for the RAVN application.
 *
 * Return: 0 on success, non-zero on failure
 */
int main(int argc, char *argv[])
{
	int opt;
	int daemon_mode = 0;
	int verbose = 0;
	const char *config_file = NULL;
	uint16_t api_port = 8080;

	/* Long options */
	static struct option long_options[] = {
		{"help",      no_argument,       0, 'h'},
		{"daemon",    no_argument,       0, 'd'},
		{"verbose",   no_argument,       0, 'v'},
		{"config",    required_argument, 0, 'c'},
		{"port",      required_argument, 0, 'p'},
		{"db",        required_argument, 0, 1000},
		{"version",   no_argument,       0, 1001},
		{0, 0, 0, 0}
	};

	/* Parse command line arguments */
	while ((opt = getopt_long(argc, argv, "hdvc:p:", long_options, NULL)) != -1) {
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
		case 1000:
			g_db_path = optarg;
			break;
		case 1001:
			print_version();
			return EXIT_SUCCESS;
		case '?':
			print_usage(argv[0]);
			return EXIT_FAILURE;
		default:
			abort();
		}
	}

	/* Suppress unused variable warnings */
	(void)daemon_mode;
	(void)verbose;
	(void)config_file;
	(void)api_port;

	/* Check for root privileges */
	if (geteuid() != 0) {
		fprintf(stderr, "RAVN requires root privileges to load eBPF programs\n");
		return EXIT_FAILURE;
	}

	/* Setup signal handlers */
	setup_signal_handlers();

	/* Print startup banner */
	printf("========================================\n");
	printf("    RAVN - Cutting-Edge Security\n");
	printf("========================================\n");
	printf("Version: 2.0.0\n");
	printf("Mode: %s\n", daemon_mode ? "daemon" : "foreground");
	printf("Verbose: %s\n", verbose ? "enabled" : "disabled");
	printf("API Port: %d\n", api_port);
	printf("Database: %s\n", g_db_path);
	if (config_file) {
		printf("Config: %s\n", config_file);
	}
	printf("========================================\n");

	/* Run RAVN CRUD operations demo */
	demo_crud_operations();

	/* Attach eBPF programs for real-time monitoring */
	printf("\n[INFO] Attaching eBPF programs for real-time monitoring...\n");
	
	/* Map program names to their corresponding ring buffer map names */
	const char *map_names[] = {
		"events",           /* execfs */
		"network_events",   /* network */
		"system_events",    /* system */
		"security_events",  /* security */
		"vulnerability_events", /* vulnerability */
		"update_events"     /* update-checker */
	};
	
	for (int i = 0; i < 6; i++) {
		if (ebpf_program_attach(&g_ebpf_programs[i]) == 0) {
			printf("[INFO] eBPF program attached: %s\n", g_ebpf_programs[i].name);
			/* Get ring buffer for event collection with correct map name */
			g_ebpf_programs[i].ring_buffer = ebpf_program_get_ring_buffer(&g_ebpf_programs[i], map_names[i]);
		} else {
			printf("[WARN] Failed to attach eBPF program: %s\n", g_ebpf_programs[i].name);
		}
	}

	/* Main event loop */
	printf("\n[INFO] Starting main event loop...\n");
	printf("[INFO] Press Ctrl+C to stop\n");

	while (g_running) {
		/* Poll all eBPF programs for events */
		for (int i = 0; i < 6; i++) {
			if (g_ebpf_programs[i].ring_buffer) {
				int ret = ebpf_program_poll(&g_ebpf_programs[i], 100); /* 100ms timeout */
				if (ret > 0 && verbose) {
					printf("[DEBUG] Collected %d events from %s\n", ret, g_ebpf_programs[i].name);
				}
			}
		}
		
		if (verbose) {
			printf("[DEBUG] Main loop running...\n");
		}
		
		/* Small delay to prevent excessive CPU usage */
		usleep(10000); /* 10ms */
	}

	printf("\n[INFO] RAVN shutdown complete\n");
	return EXIT_SUCCESS;
}
