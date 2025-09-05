/* SPDX-License-Identifier: GPL-2.0 */
/*
 * eBPF Program Management
 * 
 * This file defines the core eBPF program management interface for ravn.
 * It provides functions for loading, attaching, and managing eBPF programs
 * that monitor kernel events for security and observability purposes.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#ifndef _ravn_CORE_EBPF_H
#define _ravn_CORE_EBPF_H

#include <stddef.h>
#include <stdint.h>

/**
 * struct ebpf_program - eBPF program descriptor
 * @name: Program name for identification
 * @object: libbpf object handle
 * @loaded: Whether the program is loaded
 * @attached: Whether the program is attached
 * @ring_buffer: Associated ring buffer for events
 */
struct ebpf_program {
	const char *name;
	void *object;		/* struct bpf_object * */
	int loaded;
	int attached;
	void *ring_buffer;	/* struct ring_buffer * */
};

/**
 * struct ebpf_manager - eBPF program manager
 * @programs: Array of eBPF programs
 * @num_programs: Number of programs
 * @initialized: Whether the manager is initialized
 */
struct ebpf_manager {
	struct ebpf_program *programs;
	size_t num_programs;
	int initialized;
};

/**
 * ebpf_manager_init() - Initialize eBPF program manager
 * @manager: Pointer to eBPF manager structure
 *
 * Initialize the eBPF program manager and prepare for program loading.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_manager_init(struct ebpf_manager *manager);

/**
 * ebpf_manager_cleanup() - Cleanup eBPF program manager
 * @manager: Pointer to eBPF manager structure
 *
 * Cleanup all loaded eBPF programs and free resources.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_manager_cleanup(struct ebpf_manager *manager);

/**
 * ebpf_program_load() - Load an eBPF program
 * @manager: Pointer to eBPF manager
 * @name: Program name
 * @object_file: Path to eBPF object file
 *
 * Load an eBPF program from object file and add it to the manager.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_load(struct ebpf_manager *manager, const char *name,
		      const char *object_file);

/**
 * ebpf_program_attach() - Attach an eBPF program
 * @manager: Pointer to eBPF manager
 * @name: Program name
 *
 * Attach the specified eBPF program to kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_attach(struct ebpf_manager *manager, const char *name);

/**
 * ebpf_program_detach() - Detach an eBPF program
 * @manager: Pointer to eBPF manager
 * @name: Program name
 *
 * Detach the specified eBPF program from kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_detach(struct ebpf_manager *manager, const char *name);

/**
 * ebpf_program_get_ring_buffer() - Get ring buffer for program
 * @manager: Pointer to eBPF manager
 * @name: Program name
 *
 * Get the ring buffer associated with the specified eBPF program.
 *
 * Return: Pointer to ring buffer on success, NULL on failure
 */
void *ebpf_program_get_ring_buffer(struct ebpf_manager *manager, const char *name);

/**
 * ebpf_program_poll() - Poll all eBPF program ring buffers
 * @manager: Pointer to eBPF manager
 * @timeout_ms: Poll timeout in milliseconds
 *
 * Poll all ring buffers for new events from eBPF programs.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_poll(struct ebpf_manager *manager, int timeout_ms);

/**
 * ebpf_program_get_status() - Get program status
 * @manager: Pointer to eBPF manager
 * @name: Program name
 *
 * Get the current status of the specified eBPF program.
 *
 * Return: Program status flags
 */
int ebpf_program_get_status(struct ebpf_manager *manager, const char *name);

/* eBPF program status flags */
#define EBPF_PROGRAM_LOADED	(1 << 0)
#define EBPF_PROGRAM_ATTACHED	(1 << 1)
#define EBPF_PROGRAM_ACTIVE	(1 << 2)
#define EBPF_PROGRAM_ERROR	(1 << 3)

/* eBPF program names */
#define EBPF_PROGRAM_EXECFS	"execfs"
#define EBPF_PROGRAM_NETWORK	"network"
#define EBPF_PROGRAM_SYSTEM	"system"
#define EBPF_PROGRAM_SECURITY	"security"
#define EBPF_PROGRAM_VULNERABILITY "vulnerability"
#define EBPF_PROGRAM_UPDATE	"update-checker"

#endif /* _ravn_CORE_EBPF_H */
