/* SPDX-License-Identifier: MIT */
/*
 * Database Storage Layer with CRUD Operations
 * 
 * This file implements the database storage layer for ravn using SQLite.
 * It provides CRUD operations for all data types including events, rules,
 * configurations, and analysis results.
 *
 * Author: Guy Davidi
 * Date: 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sqlite3.h>
#include <time.h>

#include "storage/storage_database_if.h"

/**
 * storage_database_create() - Create and initialize database
 * @db_path: Path to database file
 *
 * Create a new database with all required tables and indexes.
 *
 * Return: 0 on success, negative error code on failure
 */
int storage_database_create(const char *db_path)
{
	sqlite3 *db;
	char *err_msg = 0;
	int rc;

	if (!db_path) {
		return -EINVAL;
	}

	/* Open database */
	rc = sqlite3_open(db_path, &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_database_create: Cannot open database: %s\n", 
			sqlite3_errmsg(db));
		return -errno;
	}

	/* Create events table */
	const char *create_events_sql = 
		"CREATE TABLE IF NOT EXISTS events ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"timestamp_ns INTEGER NOT NULL,"
		"event_type INTEGER NOT NULL,"
		"severity INTEGER NOT NULL,"
		"pid INTEGER NOT NULL,"
		"uid INTEGER NOT NULL,"
		"gid INTEGER NOT NULL,"
		"comm TEXT NOT NULL,"
		"filename TEXT,"
		"raw_data BLOB,"
		"processed INTEGER DEFAULT 0,"
		"created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
		");";

	rc = sqlite3_exec(db, create_events_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_database_create: SQL error creating events table: %s\n", err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return -errno;
	}

	/* Create security_rules table */
	const char *create_rules_sql = 
		"CREATE TABLE IF NOT EXISTS security_rules ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"name TEXT UNIQUE NOT NULL,"
		"description TEXT,"
		"rule_type INTEGER NOT NULL,"
		"pattern TEXT NOT NULL,"
		"severity INTEGER NOT NULL,"
		"enabled INTEGER DEFAULT 1,"
		"created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
		"updated_at DATETIME DEFAULT CURRENT_TIMESTAMP"
		");";

	rc = sqlite3_exec(db, create_rules_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_database_create: SQL error creating rules table: %s\n", err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return -errno;
	}

	/* Create analysis_results table */
	const char *create_analysis_sql = 
		"CREATE TABLE IF NOT EXISTS analysis_results ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"event_id INTEGER NOT NULL,"
		"threat_score REAL NOT NULL,"
		"anomaly_score REAL NOT NULL,"
		"is_threat INTEGER NOT NULL,"
		"threat_level INTEGER NOT NULL,"
		"recommendations TEXT,"
		"confidence REAL NOT NULL,"
		"created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
		"FOREIGN KEY(event_id) REFERENCES events(id)"
		");";

	rc = sqlite3_exec(db, create_analysis_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_database_create: SQL error creating analysis table: %s\n", err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return -errno;
	}

	/* Create indexes for better performance */
	const char *create_indexes_sql = 
		"CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_ns);"
		"CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);"
		"CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);"
		"CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed);"
		"CREATE INDEX IF NOT EXISTS idx_analysis_threat ON analysis_results(is_threat);"
		"CREATE INDEX IF NOT EXISTS idx_analysis_score ON analysis_results(threat_score);";

	rc = sqlite3_exec(db, create_indexes_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_database_create: SQL error creating indexes: %s\n", err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return -errno;
	}

	/* Close database */
	sqlite3_close(db);

	printf("[INFO] Database created successfully at: %s\n", db_path);
	return 0;
}

/**
 * storage_event_create() - Create/insert new event
 * @db_path: Path to database file
 * @event: Event data to insert
 *
 * Insert a new event into the database.
 *
 * Return: Event ID on success, negative error code on failure
 */
int storage_event_create(const char *db_path, const struct storage_event *event)
{
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	int event_id = -1;

	if (!db_path || !event) {
		return -EINVAL;
	}

	/* Open database */
	rc = sqlite3_open(db_path, &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_event_create: Cannot open database: %s\n", 
			sqlite3_errmsg(db));
		return -errno;
	}

	/* Prepare insert statement */
	const char *insert_sql = 
		"INSERT INTO events (timestamp_ns, event_type, severity, pid, uid, gid, comm, filename, raw_data, processed) "
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

	rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_event_create: Failed to prepare statement: %s\n", 
			sqlite3_errmsg(db));
		sqlite3_close(db);
		return -errno;
	}

	/* Bind parameters */
	sqlite3_bind_int64(stmt, 1, event->timestamp_ns);
	sqlite3_bind_int(stmt, 2, event->event_type);
	sqlite3_bind_int(stmt, 3, event->severity);
	sqlite3_bind_int(stmt, 4, event->pid);
	sqlite3_bind_int(stmt, 5, event->uid);
	sqlite3_bind_int(stmt, 6, event->gid);
	sqlite3_bind_text(stmt, 7, event->comm, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 8, event->filename, -1, SQLITE_STATIC);
	sqlite3_bind_blob(stmt, 9, event->raw_data, event->raw_size, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 10, event->processed);

	/* Execute statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		fprintf(stderr, "storage_event_create: Failed to execute statement: %s\n", 
			sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return -errno;
	}

	/* Get the inserted row ID */
	event_id = sqlite3_last_insert_rowid(db);

	/* Cleanup */
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return event_id;
}

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
		      struct storage_event *events, int max_events)
{
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	int count = 0;
	char sql[1024];

	if (!db_path || !events || max_events <= 0) {
		return -EINVAL;
	}

	/* Open database */
	rc = sqlite3_open(db_path, &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_event_read: Cannot open database: %s\n", 
			sqlite3_errmsg(db));
		return -errno;
	}

	/* Build SQL query based on filter */
	strcpy(sql, "SELECT id, timestamp_ns, event_type, severity, pid, uid, gid, comm, filename, raw_data, processed FROM events WHERE 1=1");

	if (filter) {
		if (filter->event_type > 0) {
			strcat(sql, " AND event_type = ?");
		}
		if (filter->min_timestamp > 0) {
			strcat(sql, " AND timestamp_ns >= ?");
		}
		if (filter->max_timestamp > 0) {
			strcat(sql, " AND timestamp_ns <= ?");
		}
		if (filter->pid > 0) {
			strcat(sql, " AND pid = ?");
		}
		if (filter->processed >= 0) {
			strcat(sql, " AND processed = ?");
		}
	}

	strcat(sql, " ORDER BY timestamp_ns DESC LIMIT ?");

	/* Prepare statement */
	rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_event_read: Failed to prepare statement: %s\n", 
			sqlite3_errmsg(db));
		sqlite3_close(db);
		return -errno;
	}

	/* Bind parameters */
	int param = 1;
	if (filter) {
		if (filter->event_type > 0) {
			sqlite3_bind_int(stmt, param++, filter->event_type);
		}
		if (filter->min_timestamp > 0) {
			sqlite3_bind_int64(stmt, param++, filter->min_timestamp);
		}
		if (filter->max_timestamp > 0) {
			sqlite3_bind_int64(stmt, param++, filter->max_timestamp);
		}
		if (filter->pid > 0) {
			sqlite3_bind_int(stmt, param++, filter->pid);
		}
		if (filter->processed >= 0) {
			sqlite3_bind_int(stmt, param++, filter->processed);
		}
	}
	sqlite3_bind_int(stmt, param, max_events);

	/* Execute query and read results */
	while (sqlite3_step(stmt) == SQLITE_ROW && count < max_events) {
		struct storage_event *event = &events[count];
		
		event->id = sqlite3_column_int(stmt, 0);
		event->timestamp_ns = sqlite3_column_int64(stmt, 1);
		event->event_type = sqlite3_column_int(stmt, 2);
		event->severity = sqlite3_column_int(stmt, 3);
		event->pid = sqlite3_column_int(stmt, 4);
		event->uid = sqlite3_column_int(stmt, 5);
		event->gid = sqlite3_column_int(stmt, 6);
		
		strncpy(event->comm, (const char*)sqlite3_column_text(stmt, 7), sizeof(event->comm) - 1);
		event->comm[sizeof(event->comm) - 1] = '\0';
		
		strncpy(event->filename, (const char*)sqlite3_column_text(stmt, 8), sizeof(event->filename) - 1);
		event->filename[sizeof(event->filename) - 1] = '\0';
		
		const void *raw_data = sqlite3_column_blob(stmt, 9);
		int raw_size = sqlite3_column_bytes(stmt, 9);
		if (raw_data && raw_size > 0) {
			size_t max_size = sizeof(event->raw_data);
			event->raw_size = (raw_size < (int)max_size) ? (size_t)raw_size : max_size;
			memcpy(event->raw_data, raw_data, event->raw_size);
		} else {
			event->raw_size = 0;
		}
		
		event->processed = sqlite3_column_int(stmt, 10);
		count++;
	}

	/* Cleanup */
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return count;
}

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
int storage_event_update(const char *db_path, int event_id, const struct storage_event_updates *updates)
{
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[512];
	int param_count = 0;

	if (!db_path || !updates || event_id <= 0) {
		return -EINVAL;
	}

	/* Open database */
	rc = sqlite3_open(db_path, &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_event_update: Cannot open database: %s\n", 
			sqlite3_errmsg(db));
		return -errno;
	}

	/* Build update SQL */
	strcpy(sql, "UPDATE events SET ");
	
	if (updates->processed >= 0) {
		if (param_count > 0) strcat(sql, ", ");
		strcat(sql, "processed = ?");
		param_count++;
	}
	
	if (updates->severity >= 0) {
		if (param_count > 0) strcat(sql, ", ");
		strcat(sql, "severity = ?");
		param_count++;
	}

	strcat(sql, " WHERE id = ?");

	/* Prepare statement */
	rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_event_update: Failed to prepare statement: %s\n", 
			sqlite3_errmsg(db));
		sqlite3_close(db);
		return -errno;
	}

	/* Bind parameters */
	int param = 1;
	if (updates->processed >= 0) {
		sqlite3_bind_int(stmt, param++, updates->processed);
	}
	if (updates->severity >= 0) {
		sqlite3_bind_int(stmt, param++, updates->severity);
	}
	sqlite3_bind_int(stmt, param, event_id);

	/* Execute statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		fprintf(stderr, "storage_event_update: Failed to execute statement: %s\n", 
			sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return -errno;
	}

	/* Check if any rows were affected */
	if (sqlite3_changes(db) == 0) {
		fprintf(stderr, "storage_event_update: No event found with ID %d\n", event_id);
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return -ENOENT;
	}

	/* Cleanup */
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return 0;
}

/**
 * storage_event_delete() - Delete event from database
 * @db_path: Path to database file
 * @event_id: ID of event to delete
 *
 * Delete an event from the database.
 *
 * Return: 0 on success, negative error code on failure
 */
int storage_event_delete(const char *db_path, int event_id)
{
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	if (!db_path || event_id <= 0) {
		return -EINVAL;
	}

	/* Open database */
	rc = sqlite3_open(db_path, &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_event_delete: Cannot open database: %s\n", 
			sqlite3_errmsg(db));
		return -errno;
	}

	/* Prepare delete statement */
	const char *delete_sql = "DELETE FROM events WHERE id = ?";
	rc = sqlite3_prepare_v2(db, delete_sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "storage_event_delete: Failed to prepare statement: %s\n", 
			sqlite3_errmsg(db));
		sqlite3_close(db);
		return -errno;
	}

	/* Bind parameter */
	sqlite3_bind_int(stmt, 1, event_id);

	/* Execute statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		fprintf(stderr, "storage_event_delete: Failed to execute statement: %s\n", 
			sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return -errno;
	}

	/* Check if any rows were affected */
	if (sqlite3_changes(db) == 0) {
		fprintf(stderr, "storage_event_delete: No event found with ID %d\n", event_id);
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return -ENOENT;
	}

	/* Cleanup */
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return 0;
}
