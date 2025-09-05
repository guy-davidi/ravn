/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Event Processing Abstraction Layer
 * 
 * This file implements the event processing abstraction layer for ravn.
 * It provides unified event processing, normalization, and routing between
 * the eBPF kernel layer and the service layer.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>

#include "abstraction/abstraction_event_processor_if.h"
#include "core/ebpf.h"
#include "core_execfs.h"
#include "core_network.h"

/**
 * abstraction_event_processor_init() - Initialize event processor
 * @processor: Pointer to event processor structure
 *
 * Initialize the event processor and prepare for event handling.
 *
 * Return: 0 on success, negative error code on failure
 */
int abstraction_event_processor_init(struct abstraction_event_processor *processor)
{
	if (!processor) {
		fprintf(stderr, "abstraction_event_processor_init: processor is NULL\n");
		return -EINVAL;
	}

	/* Initialize processor structure */
	memset(processor, 0, sizeof(*processor));
	processor->initialized = 1;
	processor->event_count = 0;
	processor->last_event_time = 0;

	/* Initialize event queues */
	TAILQ_INIT(&processor->pending_events);
	TAILQ_INIT(&processor->processed_events);

	/* Initialize mutex for thread safety */
	if (pthread_mutex_init(&processor->event_mutex, NULL) != 0) {
		fprintf(stderr, "abstraction_event_processor_init: failed to init mutex\n");
		return -errno;
	}

	return 0;
}

/**
 * abstraction_event_processor_cleanup() - Cleanup event processor
 * @processor: Pointer to event processor structure
 *
 * Cleanup the event processor and free all resources.
 *
 * Return: 0 on success, negative error code on failure
 */
int abstraction_event_processor_cleanup(struct abstraction_event_processor *processor)
{
	struct abstraction_event *event;

	if (!processor || !processor->initialized) {
		return -EINVAL;
	}

	/* Cleanup pending events */
	while (!TAILQ_EMPTY(&processor->pending_events)) {
		event = TAILQ_FIRST(&processor->pending_events);
		TAILQ_REMOVE(&processor->pending_events, event, list);
		free(event);
	}

	/* Cleanup processed events */
	while (!TAILQ_EMPTY(&processor->processed_events)) {
		event = TAILQ_FIRST(&processor->processed_events);
		TAILQ_REMOVE(&processor->processed_events, event, list);
		free(event);
	}

	/* Destroy mutex */
	pthread_mutex_destroy(&processor->event_mutex);

	/* Reset processor state */
	processor->initialized = 0;

	return 0;
}

/**
 * abstraction_event_normalize() - Normalize event data
 * @raw_event: Raw event data from eBPF
 * @normalized_event: Normalized event structure
 *
 * Normalize raw event data from eBPF programs into a unified format.
 *
 * Return: 0 on success, negative error code on failure
 */
int abstraction_event_normalize(const void *raw_event, size_t raw_size,
				struct abstraction_event *normalized_event)
{
	if (!raw_event || !normalized_event) {
		return -EINVAL;
	}

	/* Initialize normalized event */
	memset(normalized_event, 0, sizeof(*normalized_event));

	/* Set common fields */
	normalized_event->timestamp_ns = time(NULL) * 1000000000ULL;
	normalized_event->raw_size = raw_size;
	normalized_event->processed = 0;

	/* Copy raw event data */
	if (raw_size > sizeof(normalized_event->raw_data)) {
		raw_size = sizeof(normalized_event->raw_data);
	}
	memcpy(normalized_event->raw_data, raw_event, raw_size);

	/* Determine event type based on raw data structure */
	/* This is a simplified approach - in practice, you'd have more sophisticated detection */
	if (raw_size >= sizeof(struct event)) {
		const struct event *exec_event = (const struct event *)raw_event;
		if (exec_event->event_type == EV_EXEC || exec_event->event_type == EV_OPEN) {
			normalized_event->event_type = ABSTRACTION_EVENT_EXECFS;
			normalized_event->pid = exec_event->pid;
			normalized_event->uid = exec_event->uid;
			normalized_event->timestamp_ns = exec_event->timestamp_ns;
			strncpy(normalized_event->comm, exec_event->comm, sizeof(normalized_event->comm) - 1);
			normalized_event->comm[sizeof(normalized_event->comm) - 1] = '\0';
			strncpy(normalized_event->filename, exec_event->filename, sizeof(normalized_event->filename) - 1);
			normalized_event->filename[sizeof(normalized_event->filename) - 1] = '\0';
		}
	} else if (raw_size >= sizeof(struct network_event)) {
		const struct network_event *net_event = (const struct network_event *)raw_event;
		normalized_event->event_type = ABSTRACTION_EVENT_NETWORK;
		normalized_event->pid = net_event->pid;
		normalized_event->uid = net_event->uid;
		normalized_event->timestamp_ns = net_event->timestamp_ns;
		strncpy(normalized_event->comm, net_event->comm, sizeof(normalized_event->comm) - 1);
		normalized_event->comm[sizeof(normalized_event->comm) - 1] = '\0';
	}

	return 0;
}

/**
 * abstraction_event_queue() - Queue event for processing
 * @processor: Pointer to event processor
 * @event: Event to queue
 *
 * Queue an event for processing by the service layer.
 *
 * Return: 0 on success, negative error code on failure
 */
int abstraction_event_queue(struct abstraction_event_processor *processor,
			    struct abstraction_event *event)
{
	struct abstraction_event *queued_event;

	if (!processor || !event) {
		return -EINVAL;
	}

	/* Allocate new event for queue */
	queued_event = malloc(sizeof(*queued_event));
	if (!queued_event) {
		return -ENOMEM;
	}

	/* Copy event data */
	memcpy(queued_event, event, sizeof(*queued_event));

	/* Lock mutex */
	pthread_mutex_lock(&processor->event_mutex);

	/* Add to pending queue */
	TAILQ_INSERT_TAIL(&processor->pending_events, queued_event, list);
	processor->event_count++;
	processor->last_event_time = event->timestamp_ns;

	/* Unlock mutex */
	pthread_mutex_unlock(&processor->event_mutex);

	return 0;
}

/**
 * abstraction_event_dequeue() - Dequeue event for processing
 * @processor: Pointer to event processor
 * @event: Pointer to store dequeued event
 *
 * Dequeue an event from the pending queue for processing.
 *
 * Return: 0 on success, negative error code on failure
 */
int abstraction_event_dequeue(struct abstraction_event_processor *processor,
			      struct abstraction_event **event)
{
	struct abstraction_event *dequeued_event;

	if (!processor || !event) {
		return -EINVAL;
	}

	/* Lock mutex */
	pthread_mutex_lock(&processor->event_mutex);

	/* Check if queue is empty */
	if (TAILQ_EMPTY(&processor->pending_events)) {
		pthread_mutex_unlock(&processor->event_mutex);
		return -ENOENT;
	}

	/* Remove from pending queue */
	dequeued_event = TAILQ_FIRST(&processor->pending_events);
	TAILQ_REMOVE(&processor->pending_events, dequeued_event, list);

	/* Unlock mutex */
	pthread_mutex_unlock(&processor->event_mutex);

	*event = dequeued_event;
	return 0;
}

/**
 * abstraction_event_mark_processed() - Mark event as processed
 * @processor: Pointer to event processor
 * @event: Event to mark as processed
 *
 * Mark an event as processed and move it to the processed queue.
 *
 * Return: 0 on success, negative error code on failure
 */
int abstraction_event_mark_processed(struct abstraction_event_processor *processor,
				     struct abstraction_event *event)
{
	if (!processor || !event) {
		return -EINVAL;
	}

	/* Lock mutex */
	pthread_mutex_lock(&processor->event_mutex);

	/* Mark as processed */
	event->processed = 1;
	event->processed_time = time(NULL) * 1000000000ULL;

	/* Move to processed queue */
	TAILQ_INSERT_TAIL(&processor->processed_events, event, list);

	/* Unlock mutex */
	pthread_mutex_unlock(&processor->event_mutex);

	return 0;
}

/**
 * abstraction_event_get_stats() - Get event processing statistics
 * @processor: Pointer to event processor
 * @stats: Pointer to store statistics
 *
 * Get current event processing statistics.
 *
 * Return: 0 on success, negative error code on failure
 */
int abstraction_event_get_stats(struct abstraction_event_processor *processor,
				struct abstraction_event_stats *stats)
{
	struct abstraction_event *event;
	
	if (!processor || !stats) {
		return -EINVAL;
	}

	/* Lock mutex */
	pthread_mutex_lock(&processor->event_mutex);

	/* Copy statistics */
	stats->total_events = processor->event_count;
	/* Count pending events */
	stats->pending_events = 0;
	TAILQ_FOREACH(event, &processor->pending_events, list) {
		stats->pending_events++;
	}
	
	/* Count processed events */
	stats->processed_events = 0;
	TAILQ_FOREACH(event, &processor->processed_events, list) {
		stats->processed_events++;
	}
	stats->last_event_time = processor->last_event_time;

	/* Unlock mutex */
	pthread_mutex_unlock(&processor->event_mutex);

	return 0;
}
