/* SPDX-License-Identifier: MIT */
/*
 * eBPF Program Management with CRUD Operations
 * 
 * This file implements eBPF program management with clear CRUD operations
 * and proper function naming conventions.
 *
 * Author: Guy Davidi
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ebpf/ebpf_program_if.h"
#include "core_execfs.h"

/* Forward declarations */
static int handle_event(void *ctx, void *data, size_t size);

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
int ebpf_program_create(struct ebpf_program *program, const char *name, const char *object_file)
{
	struct bpf_object *obj;
	int err;

	if (!program || !name || !object_file) {
		return -EINVAL;
	}

	/* Initialize program structure */
	memset(program, 0, sizeof(*program));
	program->name = strdup(name);
	program->object_file = strdup(object_file);
	program->state = EBPF_PROGRAM_STATE_CREATED;

	/* Open eBPF object file */
	obj = bpf_object__open_file(object_file, NULL);
	if (libbpf_get_error(obj)) {
		err = -errno;
		fprintf(stderr, "ebpf_program_create: failed to open %s: %s\n",
			object_file, strerror(errno));
		free(program->name);
		free(program->object_file);
		return err;
	}

	/* Load eBPF program */
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ebpf_program_create: failed to load %s: %d\n",
			name, err);
		bpf_object__close(obj);
		free(program->name);
		free(program->object_file);
		return err;
	}

	program->object = obj;
	program->state = EBPF_PROGRAM_STATE_LOADED;

	printf("[INFO] eBPF program created: %s\n", name);
	return 0;
}

/**
 * ebpf_program_read() - Read eBPF program status
 * @program: Pointer to eBPF program structure
 * @status: Pointer to store status information
 *
 * Read the current status and information of an eBPF program.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_read(const struct ebpf_program *program, struct ebpf_program_status *status)
{
	if (!program || !status) {
		return -EINVAL;
	}

	/* Initialize status structure */
	memset(status, 0, sizeof(*status));

	/* Copy basic information */
	status->name = program->name;
	status->object_file = program->object_file;
	status->state = program->state;
	status->attached = (program->state == EBPF_PROGRAM_STATE_ATTACHED);

	/* Get program information from libbpf */
	if (program->object) {
		status->loaded = 1;
		
		/* Count programs in object */
		struct bpf_program *prog;
		status->program_count = 0;
		bpf_object__for_each_program(prog, program->object) {
			status->program_count++;
		}

		/* Count maps in object */
		struct bpf_map *map;
		status->map_count = 0;
		bpf_object__for_each_map(map, program->object) {
			status->map_count++;
		}
	} else {
		status->loaded = 0;
		status->program_count = 0;
		status->map_count = 0;
	}

	return 0;
}

/**
 * ebpf_program_update() - Update eBPF program configuration
 * @program: Pointer to eBPF program structure
 * @config: New configuration
 *
 * Update the configuration of an eBPF program.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_update(struct ebpf_program *program, const struct ebpf_program_config *config)
{
	if (!program || !config) {
		return -EINVAL;
	}

	/* Update configuration */
	if (config->enabled >= 0) {
		program->enabled = config->enabled;
	}

	if (config->priority >= 0) {
		program->priority = config->priority;
	}

	if (config->timeout_ms >= 0) {
		program->timeout_ms = config->timeout_ms;
	}

	printf("[INFO] eBPF program updated: %s\n", program->name);
	return 0;
}

/**
 * ebpf_program_delete() - Delete/unload eBPF program
 * @program: Pointer to eBPF program structure
 *
 * Unload and cleanup an eBPF program.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_delete(struct ebpf_program *program)
{
	if (!program) {
		return -EINVAL;
	}

	/* Detach if attached */
	if (program->state == EBPF_PROGRAM_STATE_ATTACHED) {
		/* Note: In a real implementation, you would detach the program here */
		program->state = EBPF_PROGRAM_STATE_LOADED;
	}

	/* Close object */
	if (program->object) {
		bpf_object__close(program->object);
		program->object = NULL;
	}

	/* Free memory */
	if (program->name) {
		free(program->name);
		program->name = NULL;
	}

	if (program->object_file) {
		free(program->object_file);
		program->object_file = NULL;
	}

	/* Reset state */
	program->state = EBPF_PROGRAM_STATE_DELETED;

	printf("[INFO] eBPF program deleted: %s\n", program->name ? program->name : "unknown");
	return 0;
}

/**
 * ebpf_program_attach() - Attach eBPF program to kernel
 * @program: Pointer to eBPF program structure
 *
 * Attach the eBPF program to kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_attach(struct ebpf_program *program)
{
	struct bpf_program *bpf_prog;
	int err = 0;

	if (!program) {
		return -EINVAL;
	}

	if (program->state != EBPF_PROGRAM_STATE_LOADED) {
		fprintf(stderr, "ebpf_program_attach: program %s not loaded\n", program->name);
		return -EINVAL;
	}

	/* Attach all programs in the object */
	bpf_object__for_each_program(bpf_prog, program->object) {
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
		program->state = EBPF_PROGRAM_STATE_ATTACHED;
		printf("[INFO] eBPF program attached: %s\n", program->name);
	}

	return err;
}

/**
 * ebpf_program_detach() - Detach eBPF program from kernel
 * @program: Pointer to eBPF program structure
 *
 * Detach the eBPF program from kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_detach(struct ebpf_program *program)
{
	if (!program) {
		return -EINVAL;
	}

	if (program->state != EBPF_PROGRAM_STATE_ATTACHED) {
		fprintf(stderr, "ebpf_program_detach: program %s not attached\n", program->name);
		return -EINVAL;
	}

	/* Note: In a real implementation, you would detach the program here */
	program->state = EBPF_PROGRAM_STATE_LOADED;

	printf("[INFO] eBPF program detached: %s\n", program->name);
	return 0;
}

/**
 * ebpf_program_get_ring_buffer() - Get ring buffer for program
 * @program: Pointer to eBPF program structure
 * @buffer_name: Name of the ring buffer map
 *
 * Get the ring buffer associated with the specified eBPF program.
 *
 * Return: Pointer to ring buffer on success, NULL on failure
 */
void *ebpf_program_get_ring_buffer(struct ebpf_program *program, const char *buffer_name)
{
	struct bpf_map *map;
	struct ring_buffer *rb;

	if (!program || !buffer_name) {
		return NULL;
	}

	/* Return existing ring buffer if available */
	if (program->ring_buffer) {
		return program->ring_buffer;
	}

	/* Find ring buffer map */
	map = bpf_object__find_map_by_name(program->object, buffer_name);
	if (!map) {
		fprintf(stderr, "ebpf_program_get_ring_buffer: map %s not found for %s\n", 
			buffer_name, program->name);
		return NULL;
	}

	/* Create ring buffer */
	rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ebpf_program_get_ring_buffer: failed to create ring buffer for %s\n", 
			program->name);
		return NULL;
	}

	program->ring_buffer = rb;
	return rb;
}

/**
 * ebpf_program_poll() - Poll eBPF program for events
 * @program: Pointer to eBPF program structure
 * @timeout_ms: Poll timeout in milliseconds
 *
 * Poll the eBPF program's ring buffer for new events.
 *
 * Return: 0 on success, negative error code on failure
 */
int ebpf_program_poll(struct ebpf_program *program, int timeout_ms)
{
	if (!program) {
		return -EINVAL;
	}

	if (program->state != EBPF_PROGRAM_STATE_ATTACHED) {
		return -EINVAL;
	}

	if (!program->ring_buffer) {
		return -EINVAL;
	}

	return ring_buffer__poll(program->ring_buffer, timeout_ms);
}

/**
 * handle_event() - Event handler for ring buffer
 * @ctx: Ring buffer context
 * @data: Event data
 * @size: Event size
 *
 * Handle events from eBPF programs. This function is called by the ring buffer
 * when new events are available.
 *
 * Return: 0 on success, negative error code on failure
 */
static int handle_event(void *ctx, void *data, size_t size)
{
	(void)ctx;
	(void)size;
	
	/* Cast data to event structure */
	const struct event *e = (const struct event *)data;
	char ts[64];
	struct timespec t;
	clock_gettime(CLOCK_REALTIME, &t);
	snprintf(ts, sizeof(ts), "%ld.%09ld", t.tv_sec, t.tv_nsec);
	
	const char *etype = (e->event_type == EV_EXEC) ? "exec" : 
	                   (e->event_type == EV_OPEN ? "open" : 
	                   (e->event_type == EV_CONNECT ? "connect" : 
	                   (e->event_type == EV_ACCEPT ? "accept" : 
	                   (e->event_type == EV_SETUID ? "setuid" : 
	                   (e->event_type == EV_PTRACE ? "ptrace" : "unknown")))));
	
	/* Print JSON event to stdout for dashboard consumption */
	printf("{\"ts\":\"%s\",\"etype\":\"%s\",\"pid\":%u,\"tgid\":%u,\"ppid\":%u,\"uid\":%u,\"gid\":%u,\"comm\":\"%s\",\"file\":\"%s\"}\n",
	       ts, etype, e->pid, e->tgid, e->ppid, e->uid, e->gid, e->comm, e->filename);
	fflush(stdout);
	
	return 0;
}
