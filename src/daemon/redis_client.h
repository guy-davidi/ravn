/*
 * RAVN Redis Client - Header File
 *
 * This header defines the Redis client interface for the RAVN security platform,
 * providing high-performance data storage and real-time communication for
 * event handling, threat level management, and system monitoring.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 *
 * The Redis client implements:
 * - High-performance event storage and retrieval
 * - Real-time threat level management
 * - Pub/Sub messaging for live updates
 * - Connection management and health monitoring
 * - Data persistence and caching
 *
 * Architecture:
 * - Connection pooling for high throughput
 * - List-based event storage for chronological ordering
 * - String-based threat level storage for fast access
 * - Pub/Sub channels for real-time notifications
 */

#ifndef RAVN_REDIS_CLIENT_H
#define RAVN_REDIS_CLIENT_H

#include <stdint.h>
#include <time.h>

/* Forward declaration for Redis context */
typedef struct redisContext redisContext;

/**
 * struct redis_connection - Redis connection structure
 * @context: Redis context handle
 * @connected: Connection status flag
 * @host: Redis server hostname or IP address
 * @port: Redis server port number
 *
 * Represents a connection to a Redis server with status tracking.
 */
typedef struct redis_connection redis_connection_t;
struct redis_connection {
	redisContext *context;		/* Redis context */
	int connected;			/* Connection status */
	char host[256];		/* Server hostname/IP */
	int port;			/* Server port */
};

/* Include the full definition */
#include "ebpf_handler.h"

/**
 * struct threat_level - Threat level structure
 * @timestamp: Threat assessment timestamp
 * @score: Numerical threat score (0.0 to 1.0)
 * @level: Threat level classification
 * @reason: Human-readable threat assessment reason
 *
 * Represents a threat level assessment with score and classification.
 */
typedef struct threat_level threat_level_t;
struct threat_level {
	uint64_t timestamp;		/* Assessment timestamp */
	float score;			/* Threat score (0.0-1.0) */
	int level;			/* Threat level classification */
	char reason[256];		/* Assessment reason */
};

/*
 * Threat Level Constants
 * These values define the threat level classifications
 */
#define THREAT_LOW 0		/* Normal system activity */
#define THREAT_MEDIUM 1		/* Suspicious activity detected */
#define THREAT_HIGH 2		/* High probability of attack */
#define THREAT_CRITICAL 3	/* Critical threat confirmed */

/*
 * Redis Connection Management Functions
 */

/**
 * redis_connect - Connect to Redis server
 * @host: Redis server hostname or IP address
 * @port: Redis server port number
 *
 * Establishes a connection to the specified Redis server and returns
 * a connection handle for subsequent operations.
 *
 * Return: Connection handle on success, NULL on failure
 */
redis_connection_t *redis_connect(const char *host, int port);

/**
 * redis_disconnect - Disconnect from Redis server
 * @conn: Redis connection handle
 *
 * Closes the connection to the Redis server and frees associated resources.
 * This function is safe to call with NULL or already disconnected connections.
 */
void redis_disconnect(redis_connection_t *conn);

/**
 * redis_is_connected - Check connection status
 * @conn: Redis connection handle
 *
 * Checks if the Redis connection is active and ready for operations.
 *
 * Return: 1 if connected, 0 if disconnected
 */
int redis_is_connected(redis_connection_t *conn);

/*
 * Event Management Functions
 */

/**
 * redis_send_event - Send event to Redis
 * @conn: Redis connection handle
 * @event: Event to send
 *
 * Sends an event to Redis for storage and processing. The event is
 * added to the events list and published to the live events channel.
 *
 * Return: 0 on success, -1 on failure
 */
int redis_send_event(redis_connection_t *conn, const struct ravn_event *event);

/**
 * redis_get_event - Get event from Redis
 * @conn: Redis connection handle
 * @event: Event structure to populate
 *
 * Retrieves the most recent event from Redis storage.
 *
 * Return: 0 on success, -1 on failure
 */
int redis_get_event(redis_connection_t *conn, struct ravn_event *event);

/**
 * redis_subscribe_events - Subscribe to live event stream
 * @conn: Redis connection handle
 * @callback: Callback function for event processing
 *
 * Subscribes to the live event stream and calls the callback function
 * for each new event received.
 *
 * Return: 0 on success, -1 on failure
 */
int redis_subscribe_events(redis_connection_t *conn, void (*callback)(const struct ravn_event *));

/*
 * Threat Level Management Functions
 */

/**
 * redis_update_threat_level - Update threat level in Redis
 * @conn: Redis connection handle
 * @threat: Threat level structure to store
 *
 * Updates the current threat level in Redis storage and publishes
 * the update to the threat level channel.
 *
 * Return: 0 on success, -1 on failure
 */
int redis_update_threat_level(redis_connection_t *conn, const threat_level_t *threat);

/**
 * redis_get_threat_level - Get current threat level from Redis
 * @conn: Redis connection handle
 * @threat: Threat level structure to populate
 *
 * Retrieves the current threat level from Redis storage.
 *
 * Return: 0 on success, -1 on failure
 */
int redis_get_threat_level(redis_connection_t *conn, threat_level_t *threat);

/**
 * redis_subscribe_threat_updates - Subscribe to threat level updates
 * @conn: Redis connection handle
 * @callback: Callback function for threat level processing
 *
 * Subscribes to the threat level update channel and calls the callback
 * function for each threat level update received.
 *
 * Return: 0 on success, -1 on failure
 */
int redis_subscribe_threat_updates(redis_connection_t *conn, void (*callback)(const threat_level_t *));

/*
 * Utility Functions
 */

/**
 * redis_get_last_error - Get last Redis error message
 *
 * Returns the last error message from Redis operations.
 *
 * Return: Error message string, NULL if no error
 */
char *redis_get_last_error(void);

/**
 * redis_ping - Ping Redis server
 * @conn: Redis connection handle
 *
 * Sends a PING command to the Redis server to test connectivity.
 *
 * Return: 0 on success, -1 on failure
 */
int redis_ping(redis_connection_t *conn);

/**
 * redis_flush_all - Flush all Redis data
 * @conn: Redis connection handle
 *
 * Removes all data from the Redis database. Use with caution.
 *
 * Return: 0 on success, -1 on failure
 */
int redis_flush_all(redis_connection_t *conn);

#endif // RAVN_REDIS_CLIENT_H
