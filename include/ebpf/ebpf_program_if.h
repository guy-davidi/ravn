/* SPDX-License-Identifier: MIT */
/*
 * eBPF Program Management Interface
 * 
 * This file defines the interface for eBPF program management with CRUD operations
 * and proper function naming conventions.
 *
 * Author: Guy Davidi
 * Date: 2025
 */

#ifndef _RAVN_EBPF_PROGRAM_IF_H
#define _RAVN_EBPF_PROGRAM_IF_H

#include <stddef.h>
#include <stdint.h>

/* Forward declarations */
struct ebpf_program;
struct ebpf_program_status;
struct ebpf_program_config;

/**
 * eBPF program states
 */
enum ebpf_program_state {
	EBPF_PROGRAM_STATE_CREATED = 1,
	EBPF_PROGRAM_STATE_LOADED = 2,
	EBPF_PROGRAM_STATE_ATTACHED = 3,
	EBPF_PROGRAM_STATE_DELETED = 4,
};

/**
 * struct ebpf_program - eBPF program structure
 * @name: Program name
 * @object_file: Path to eBPF object file
 * @object: libbpf object handle
 * @state: Current program state
 * @enabled: Whether program is enabled
 * @priority: Program priority
 * @timeout_ms: Poll timeout in milliseconds
 * @ring_buffer: Associated ring buffer
 */
struct ebpf_program {
	char *name;
	char *object_file;
	void *object;		/* struct bpf_object * */
	enum ebpf_program_state state;
	int enabled;
	int priority;
	int timeout_ms;
	void *ring_buffer;	/* struct ring_buffer * */
};

/**
 * struct ebpf_program_status - eBPF program status
 * @name: Program name
 * @object_file: Path to eBPF object file
 * @state: Current program state
 * @loaded: Whether program is loaded
 * @attached: Whether program is attached
 * @program_count: Number of programs in object
 * @map_count: Number of maps in object
 */
struct ebpf_program_status {
	const char *name;
	const char *object_file;
	enum ebpf_program_state state;
	int loaded;
	int attached;
	uint32_t program_count;
	uint32_t map_count;
};

/**
 * struct ebpf_program_config - eBPF program configuration
 * @enabled: Whether program is enabled (-1 = no change)
 * @priority: Program priority (-1 = no change)
 * @timeout_ms: Poll timeout in milliseconds (-1 = no change)
 */
struct ebpf_program_config {
	int enabled;
	int priority;
	int timeout_ms;
};

/**
 * ebpf_program_create() - Create/load eBPF program
 * @program: Pointer to eBPF program structure
 * @name: Program name
 * @object_file: Path to eBPF object file
 *
 * Load an eBPF program from object file and initialize it.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_create(struct ebpf_program *program, const char *name, const char *object_file);

/**
 * ebpf_program_read() - Read eBPF program status
 * @program: Pointer to eBPF program structure
 * @status: Pointer to store status information
 *
 * Read the current status and information of an eBPF program.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_read(const struct ebpf_program *program, struct ebpf_program_status *status);

/**
 * ebpf_program_update() - Update eBPF program configuration
 * @program: Pointer to eBPF program structure
 * @config: New configuration
 *
 * Update the configuration of an eBPF program.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_update(struct ebpf_program *program, const struct ebpf_program_config *config);

/**
 * ebpf_program_delete() - Delete/unload eBPF program
 * @program: Pointer to eBPF program structure
 *
 * Unload and cleanup an eBPF program.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_delete(struct ebpf_program *program);

/**
 * ebpf_program_attach() - Attach eBPF program to kernel
 * @program: Pointer to eBPF program structure
 *
 * Attach the eBPF program to kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_attach(struct ebpf_program *program);

/**
 * ebpf_program_detach() - Detach eBPF program from kernel
 * @program: Pointer to eBPF program structure
 *
 * Detach the eBPF program from kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_detach(struct ebpf_program *program);

/**
 * ebpf_program_get_ring_buffer() - Get ring buffer for program
 * @program: Pointer to eBPF program structure
 * @buffer_name: Name of the ring buffer map
 *
 * Get the ring buffer associated with the specified eBPF program.
 *
 * Return: Pointer to ring buffer on success, NULL on failure
 */
void *ebpf_program_get_ring_buffer(struct ebpf_program *program, const char *buffer_name);

/**
 * ebpf_program_poll() - Poll eBPF program for events
 * @program: Pointer to eBPF program structure
 * @timeout_ms: Poll timeout in milliseconds
 *
 * Poll the eBPF program's ring buffer for new events.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_poll(struct ebpf_program *program, int timeout_ms);

#endif /* _RAVN_EBPF_PROGRAM_IF_H */
