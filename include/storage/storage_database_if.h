/* SPDX-License-Identifier: MIT */
/*
 * Database Storage Layer Interface
 * 
 * This file defines the interface for the database storage layer with CRUD operations.
 * It provides a simple and consistent API for all data management operations.
 *
 * Author: Guy Davidi
 * Date: 2025
 */

#ifndef _RAVN_STORAGE_DATABASE_IF_H
#define _RAVN_STORAGE_DATABASE_IF_H

#include <stdint.h>
#include <stddef.h>

/* Forward declarations */
struct storage_event;
struct storage_event_filter;
struct storage_event_updates;

/**
 * struct storage_event - Event data structure
 * @id: Unique event ID (auto-generated)
 * @timestamp_ns: Event timestamp in nanoseconds
 * @event_type: Type of event
 * @severity: Event severity level
 * @pid: Process ID
 * @uid: User ID
 * @gid: Group ID
 * @comm: Process command name
 * @filename: Associated filename
 * @raw_data: Raw event data
 * @raw_size: Size of raw data
 * @processed: Whether event has been processed
 */
struct storage_event {
	int id;
	uint64_t timestamp_ns;
	uint32_t event_type;
	uint32_t severity;
	uint32_t pid;
	uint32_t uid;
	uint32_t gid;
	char comm[16];
	char filename[256];
	uint8_t raw_data[1024];
	size_t raw_size;
	int processed;
};

/**
 * struct storage_event_filter - Event filter criteria
 * @event_type: Filter by event type (0 = all)
 * @min_timestamp: Minimum timestamp filter
 * @max_timestamp: Maximum timestamp filter
 * @pid: Filter by process ID (0 = all)
 * @processed: Filter by processed status (-1 = all, 0 = unprocessed, 1 = processed)
 */
struct storage_event_filter {
	uint32_t event_type;
	uint64_t min_timestamp;
	uint64_t max_timestamp;
	uint32_t pid;
	int processed;
};

/**
 * struct storage_event_updates - Event update fields
 * @processed: Update processed status (-1 = no change)
 * @severity: Update severity level (-1 = no change)
 */
struct storage_event_updates {
	int processed;
	int severity;
};

/**
 * storage_database_create() - Create and initialize database
 * @db_path: Path to database file
 *
 * Create a new database with all required tables and indexes.
 *
 * Return: 0 on success, negative error code on failure
 */
int storage_database_create(const char *db_path);

/**
 * storage_event_create() - Create/insert new event
 * @db_path: Path to database file
 * @event: Event data to insert
 *
 * Insert a new event into the database.
 *
 * Return: Event ID on success, negative error code on failure
 */
int storage_event_create(const char *db_path, const struct storage_event *event);

/**
 * storage_event_read() - Read events from database
 * @db_path: Path to database file
 * @filter: Filter criteria for events
 * @events: Array to store read events
 * @max_events: Maximum number of events to read
 *
 * Read events from database based on filter criteria.
 *
 * Return: Number of events read on success, negative error code on failure
 */
int storage_event_read(const char *db_path, const struct storage_event_filter *filter,
		      struct storage_event *events, int max_events);

/**
 * storage_event_update() - Update existing event
 * @db_path: Path to database file
 * @event_id: ID of event to update
 * @updates: Fields to update
 *
 * Update an existing event in the database.
 *
 * Return: 0 on success, negative error code on failure
 */
int storage_event_update(const char *db_path, int event_id, const struct storage_event_updates *updates);

/**
 * storage_event_delete() - Delete event from database
 * @db_path: Path to database file
 * @event_id: ID of event to delete
 *
 * Delete an event from the database.
 *
 * Return: 0 on success, negative error code on failure
 */
int storage_event_delete(const char *db_path, int event_id);

#endif /* _RAVN_STORAGE_DATABASE_IF_H */
