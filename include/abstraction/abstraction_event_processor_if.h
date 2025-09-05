/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Event Processing Abstraction Layer Interface
 * 
 * This file defines the interface for the event processing abstraction layer.
 * It provides unified event processing, normalization, and routing between
 * the eBPF kernel layer and the service layer.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#ifndef _ravn_ABSTRACTION_EVENT_PROCESSOR_IF_H
#define _ravn_ABSTRACTION_EVENT_PROCESSOR_IF_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/queue.h>

/* Forward declarations */
struct abstraction_event_processor;
struct abstraction_event;

/**
 * Event types in the abstraction layer
 */
enum abstraction_event_type {
	ABSTRACTION_EVENT_EXECFS = 1,
	ABSTRACTION_EVENT_NETWORK = 2,
	ABSTRACTION_EVENT_SYSTEM = 3,
	ABSTRACTION_EVENT_SECURITY = 4,
	ABSTRACTION_EVENT_VULNERABILITY = 5,
	ABSTRACTION_EVENT_UPDATE = 6,
	ABSTRACTION_EVENT_UNKNOWN = 255,
};

/**
 * Event severity levels
 */
enum abstraction_event_severity {
	ABSTRACTION_SEVERITY_LOW = 1,
	ABSTRACTION_SEVERITY_MEDIUM = 2,
	ABSTRACTION_SEVERITY_HIGH = 3,
	ABSTRACTION_SEVERITY_CRITICAL = 4,
};

/**
 * struct abstraction_event - Normalized event structure
 * @timestamp_ns: Event timestamp in nanoseconds
 * @event_type: Type of event (from enum abstraction_event_type)
 * @severity: Event severity level
 * @pid: Process ID
 * @uid: User ID
 * @gid: Group ID
 * @comm: Process command name
 * @filename: Associated filename (if applicable)
 * @raw_data: Raw event data from eBPF
 * @raw_size: Size of raw event data
 * @processed: Whether event has been processed
 * @processed_time: Time when event was processed
 * @list: Queue linkage
 */
struct abstraction_event {
	uint64_t timestamp_ns;
	uint32_t event_type;
	uint32_t severity;
	uint32_t pid;
	uint32_t uid;
	uint32_t gid;
	char comm[16];
	char filename[256];
	uint8_t raw_data[1024]; /* Raw event data */
	size_t raw_size;
	int processed;
	uint64_t processed_time;
	TAILQ_ENTRY(abstraction_event) list;
};

/**
 * struct abstraction_event_stats - Event processing statistics
 * @total_events: Total number of events processed
 * @pending_events: Number of events pending processing
 * @processed_events: Number of events that have been processed
 * @last_event_time: Timestamp of last event
 */
struct abstraction_event_stats {
	uint64_t total_events;
	uint64_t pending_events;
	uint64_t processed_events;
	uint64_t last_event_time;
};

/**
 * struct abstraction_event_processor - Event processor structure
 * @initialized: Whether the processor is initialized
 * @event_count: Total event count
 * @last_event_time: Timestamp of last event
 * @pending_events: Queue of pending events
 * @processed_events: Queue of processed events
 * @event_mutex: Mutex for thread safety
 */
struct abstraction_event_processor {
	int initialized;
	uint64_t event_count;
	uint64_t last_event_time;
	TAILQ_HEAD(, abstraction_event) pending_events;
	TAILQ_HEAD(, abstraction_event) processed_events;
	pthread_mutex_t event_mutex;
};

/**
 * abstraction_event_processor_init() - Initialize event processor
 * @processor: Pointer to event processor structure
 *
 * Initialize the event processor and prepare for event handling.
 *
 * Return: 0 on success, negative error code on failure
 */
int abstraction_event_processor_init(struct abstraction_event_processor *processor);

/**
 * abstraction_event_processor_cleanup() - Cleanup event processor
 * @processor: Pointer to event processor structure
 *
 * Cleanup the event processor and free all resources.
 *
 * Return: 0 on success, negative error code on failure
 */
int abstraction_event_processor_cleanup(struct abstraction_event_processor *processor);

/**
 * abstraction_event_normalize() - Normalize event data
 * @raw_event: Raw event data from eBPF
 * @raw_size: Size of raw event data
 * @normalized_event: Normalized event structure
 *
 * Normalize raw event data from eBPF programs into a unified format.
 *
 * Return: 0 on success, negative error code on failure
 */
int abstraction_event_normalize(const void *raw_event, size_t raw_size,
				struct abstraction_event *normalized_event);

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
			    struct abstraction_event *event);

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
			      struct abstraction_event **event);

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
				     struct abstraction_event *event);

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
				struct abstraction_event_stats *stats);

#endif /* _ravn_ABSTRACTION_EVENT_PROCESSOR_IF_H */
