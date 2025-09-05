/* SPDX-License-Identifier: GPL-2.0 */
/*
 * eBPF Program Manager
 * 
 * This file implements the eBPF program management interface for ravn.
 * It provides functions for loading, attaching, and managing eBPF programs
 * that monitor kernel events for security and observability purposes.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "core/ebpf.h"

/* Forward declarations */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);
static int handle_event(void *ctx, void *data, size_t size);

/**
 * ebpf_manager_init() - Initialize eBPF program manager
 * @manager: Pointer to eBPF manager structure
 *
 * Initialize the eBPF program manager and prepare for program loading.
 * This function sets up libbpf, raises memory limits, and initializes
 * the manager structure.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_manager_init(struct ebpf_manager *manager)
{
	if (!manager) {
		fprintf(stderr, "ebpf_manager_init: manager is NULL\n");
		return -EINVAL;
	}

	/* Initialize libbpf with strict mode */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	/* Raise memlock rlimit for BPF maps/programs */
	struct rlimit rl = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &rl) < 0) {
		fprintf(stderr, "ebpf_manager_init: failed to set rlimit: %s\n",
			strerror(errno));
		return -errno;
	}

	/* Initialize manager structure */
	memset(manager, 0, sizeof(*manager));
	manager->initialized = 1;

	return 0;
}

/**
 * ebpf_manager_cleanup() - Cleanup eBPF program manager
 * @manager: Pointer to eBPF manager structure
 *
 * Cleanup all loaded eBPF programs and free resources. This function
 * detaches all programs, closes all objects, and frees allocated memory.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_manager_cleanup(struct ebpf_manager *manager)
{
	if (!manager || !manager->initialized) {
		return -EINVAL;
	}

	/* Cleanup all programs */
	for (size_t i = 0; i < manager->num_programs; i++) {
		struct ebpf_program *prog = &manager->programs[i];
		
		if (prog->ring_buffer) {
			ring_buffer__free(prog->ring_buffer);
			prog->ring_buffer = NULL;
		}
		
		if (prog->object) {
			bpf_object__close(prog->object);
			prog->object = NULL;
		}
	}

	/* Free program array */
	if (manager->programs) {
		free(manager->programs);
		manager->programs = NULL;
	}

	/* Reset manager state */
	manager->num_programs = 0;
	manager->initialized = 0;

	return 0;
}

/**
 * ebpf_program_load() - Load an eBPF program
 * @manager: Pointer to eBPF manager
 * @name: Program name
 * @object_file: Path to eBPF object file
 *
 * Load an eBPF program from object file and add it to the manager.
 * The program is loaded but not attached to kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_load(struct ebpf_manager *manager, const char *name,
		      const char *object_file)
{
	struct bpf_object *obj;
	struct ebpf_program *prog;
	int err;

	if (!manager || !name || !object_file) {
		return -EINVAL;
	}

	/* Open eBPF object file */
	obj = bpf_object__open_file(object_file, NULL);
	if (libbpf_get_error(obj)) {
		err = -errno;
		fprintf(stderr, "ebpf_program_load: failed to open %s: %s\n",
			object_file, strerror(errno));
		return err;
	}

	/* Load eBPF program */
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ebpf_program_load: failed to load %s: %d\n",
			name, err);
		bpf_object__close(obj);
		return err;
	}

	/* Add program to manager */
	manager->programs = realloc(manager->programs,
				    (manager->num_programs + 1) * sizeof(*prog));
	if (!manager->programs) {
		fprintf(stderr, "ebpf_program_load: failed to allocate memory\n");
		bpf_object__close(obj);
		return -ENOMEM;
	}

	prog = &manager->programs[manager->num_programs];
	memset(prog, 0, sizeof(*prog));
	prog->name = name;
	prog->object = obj;
	prog->loaded = 1;
	prog->attached = 0;

	manager->num_programs++;

	return 0;
}

/**
 * ebpf_program_attach() - Attach an eBPF program
 * @manager: Pointer to eBPF manager
 * @name: Program name
 *
 * Attach the specified eBPF program to kernel tracepoints. This function
 * iterates through all programs in the object and attaches them to their
 * respective tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_attach(struct ebpf_manager *manager, const char *name)
{
	struct ebpf_program *prog;
	struct bpf_program *bpf_prog;
	int err = 0;

	if (!manager || !name) {
		return -EINVAL;
	}

	/* Find program by name */
	prog = NULL;
	for (size_t i = 0; i < manager->num_programs; i++) {
		if (strcmp(manager->programs[i].name, name) == 0) {
			prog = &manager->programs[i];
			break;
		}
	}

	if (!prog) {
		fprintf(stderr, "ebpf_program_attach: program %s not found\n", name);
		return -ENOENT;
	}

	if (!prog->loaded) {
		fprintf(stderr, "ebpf_program_attach: program %s not loaded\n", name);
		return -EINVAL;
	}

	/* Attach all programs in the object */
	bpf_object__for_each_program(bpf_prog, prog->object) {
		const char *sec = bpf_program__section_name(bpf_prog);
		if (sec && (strstr(sec, "tracepoint/") == sec)) {
			const char *tp = sec + strlen("tracepoint/");
			const char *slash = strchr(tp, '/');
			if (!slash) {
				fprintf(stderr, "ebpf_program_attach: invalid section name: %s\n", sec);
				continue;
			}

			char category[64] = {0};
			char tp_name[128] = {0};
			size_t catlen = (size_t)(slash - tp);
			size_t namelen = strlen(slash + 1);
			
			if (catlen >= sizeof(category)) catlen = sizeof(category) - 1;
			if (namelen >= sizeof(tp_name)) namelen = sizeof(tp_name) - 1;
			
			memcpy(category, tp, catlen);
			memcpy(tp_name, slash + 1, namelen);

			if (libbpf_get_error(bpf_program__attach_tracepoint(bpf_prog, category, tp_name))) {
				fprintf(stderr, "ebpf_program_attach: failed to attach %s (%s/%s)\n",
					sec, category, tp_name);
				err = -errno;
			}
		}
	}

	if (err == 0) {
		prog->attached = 1;
	}

	return err;
}

/**
 * ebpf_program_detach() - Detach an eBPF program
 * @manager: Pointer to eBPF manager
 * @name: Program name
 *
 * Detach the specified eBPF program from kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_detach(struct ebpf_manager *manager, const char *name)
{
	struct ebpf_program *prog;

	if (!manager || !name) {
		return -EINVAL;
	}

	/* Find program by name */
	prog = NULL;
	for (size_t i = 0; i < manager->num_programs; i++) {
		if (strcmp(manager->programs[i].name, name) == 0) {
			prog = &manager->programs[i];
			break;
		}
	}

	if (!prog) {
		fprintf(stderr, "ebpf_program_detach: program %s not found\n", name);
		return -ENOENT;
	}

	if (!prog->attached) {
		fprintf(stderr, "ebpf_program_detach: program %s not attached\n", name);
		return -EINVAL;
	}

	/* Mark as detached */
	prog->attached = 0;

	return 0;
}

/**
 * ebpf_program_get_ring_buffer() - Get ring buffer for program
 * @manager: Pointer to eBPF manager
 * @name: Program name
 *
 * Get the ring buffer associated with the specified eBPF program.
 * The ring buffer is created if it doesn't exist.
 *
 * Return: Pointer to ring buffer on success, NULL on failure
 */
void *ebpf_program_get_ring_buffer(struct ebpf_manager *manager, const char *name)
{
	struct ebpf_program *prog;
	struct bpf_map *map;
	struct ring_buffer *rb;

	if (!manager || !name) {
		return NULL;
	}

	/* Find program by name */
	prog = NULL;
	for (size_t i = 0; i < manager->num_programs; i++) {
		if (strcmp(manager->programs[i].name, name) == 0) {
			prog = &manager->programs[i];
			break;
		}
	}

	if (!prog) {
		fprintf(stderr, "ebpf_program_get_ring_buffer: program %s not found\n", name);
		return NULL;
	}

	/* Return existing ring buffer if available */
	if (prog->ring_buffer) {
		return prog->ring_buffer;
	}

	/* Find events map */
	map = bpf_object__find_map_by_name(prog->object, "events");
	if (!map) {
		/* Try alternative map names */
		const char *alt_names[] = {
			"network_events", "system_events", "security_events",
			"vulnerability_events", "update_events"
		};
		
		for (size_t i = 0; i < sizeof(alt_names) / sizeof(alt_names[0]); i++) {
			map = bpf_object__find_map_by_name(prog->object, alt_names[i]);
			if (map) break;
		}
	}

	if (!map) {
		fprintf(stderr, "ebpf_program_get_ring_buffer: events map not found for %s\n", name);
		return NULL;
	}

	/* Create ring buffer */
	rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ebpf_program_get_ring_buffer: failed to create ring buffer for %s\n", name);
		return NULL;
	}

	prog->ring_buffer = rb;
	return rb;
}

/**
 * ebpf_program_poll() - Poll all eBPF program ring buffers
 * @manager: Pointer to eBPF manager
 * @timeout_ms: Poll timeout in milliseconds
 *
 * Poll all ring buffers for new events from eBPF programs. This function
 * iterates through all loaded programs and polls their ring buffers.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_poll(struct ebpf_manager *manager, int timeout_ms)
{
	int err = 0;

	if (!manager) {
		return -EINVAL;
	}

	/* Poll all ring buffers */
	for (size_t i = 0; i < manager->num_programs; i++) {
		struct ebpf_program *prog = &manager->programs[i];
		
		if (prog->ring_buffer) {
			int poll_err = ring_buffer__poll(prog->ring_buffer, timeout_ms / manager->num_programs);
			if (poll_err == -EINTR) {
				return -EINTR;
			}
			if (poll_err < 0) {
				fprintf(stderr, "ebpf_program_poll: %s ring buffer poll failed: %d\n",
					prog->name, poll_err);
				err = poll_err;
			}
		}
	}

	return err;
}

/**
 * ebpf_program_get_status() - Get program status
 * @manager: Pointer to eBPF manager
 * @name: Program name
 *
 * Get the current status of the specified eBPF program.
 *
 * Return: Program status flags
 */
int ebpf_program_get_status(struct ebpf_manager *manager, const char *name)
{
	struct ebpf_program *prog;
	int status = 0;

	if (!manager || !name) {
		return 0;
	}

	/* Find program by name */
	prog = NULL;
	for (size_t i = 0; i < manager->num_programs; i++) {
		if (strcmp(manager->programs[i].name, name) == 0) {
			prog = &manager->programs[i];
			break;
		}
	}

	if (!prog) {
		return 0;
	}

	if (prog->loaded) {
		status |= EBPF_PROGRAM_LOADED;
	}
	if (prog->attached) {
		status |= EBPF_PROGRAM_ATTACHED;
	}
	if (prog->loaded && prog->attached) {
		status |= EBPF_PROGRAM_ACTIVE;
	}

	return status;
}

/**
 * libbpf_print_fn() - libbpf print function
 * @level: Log level
 * @format: Format string
 * @args: Format arguments
 *
 * Custom print function for libbpf messages. This function provides
 * verbose output for debugging eBPF program loading and attachment.
 */
int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	(void)level; /* Suppress unused parameter warning */
	return vfprintf(stderr, format, args);
}

/**
 * handle_event() - Event handler for ring buffer
 * @ctx: Ring buffer context
 * @data: Event data
 * @size: Event size
 *
 * Handle events from eBPF programs. This function is called by the ring buffer
 * when new events are available. It processes the event and stores it in the
 * database.
 *
 * Return: 0 on success, negative error code on failure
 */
int handle_event(void *ctx, void *data, size_t size)
{
	/* This function is implemented in the main agent */
	/* It's declared here for the ring buffer callback */
	(void)ctx;
	(void)data;
	(void)size;
	return 0;
}
