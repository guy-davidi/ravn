// RAVN Redis Client Implementation
// Implements Redis communication for event streaming and threat level updates

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>
#include "redis_client.h"
#include "../utils/logger.h"

// Global Redis connection
static redis_connection_t *global_redis_conn = NULL;
static char last_error[256] = {0};

// Connect to Redis server
redis_connection_t* redis_connect(const char *host, int port) {
    redis_connection_t *conn = malloc(sizeof(redis_connection_t));
    if (!conn) {
        snprintf(last_error, sizeof(last_error), "Failed to allocate memory for Redis connection");
        return NULL;
    }
    
    // Initialize connection structure
    strncpy(conn->host, host, sizeof(conn->host) - 1);
    conn->host[sizeof(conn->host) - 1] = '\0';
    conn->port = port;
    conn->connected = 0;
    
    // Connect to Redis
    conn->context = redisConnect(host, port);
    if (!conn->context || conn->context->err) {
        if (conn->context) {
            snprintf(last_error, sizeof(last_error), "Redis connection error: %s", conn->context->errstr);
            redisFree(conn->context);
        } else {
            snprintf(last_error, sizeof(last_error), "Failed to allocate Redis context");
        }
        free(conn);
        return NULL;
    }
    
    conn->connected = 1;
    global_redis_conn = conn;
    LOG_INFO("Connected to Redis at %s:%d", host, port);
    return conn;
}

// Disconnect from Redis
void redis_disconnect(redis_connection_t *conn) {
    if (conn && conn->context) {
        redisFree(conn->context);
        conn->context = NULL;
    }
    
    if (conn) {
        conn->connected = 0;
        free(conn);
    }
    
    if (conn == global_redis_conn) {
        global_redis_conn = NULL;
    }
    
    LOG_INFO("Redis connection closed");
}

// Check if Redis connection is active
int redis_is_connected(redis_connection_t *conn) {
    if (!conn || !conn->context || !conn->connected) {
        return 0;
    }
    
    // Simple check - just verify context exists and is not in error state
    if (conn->context->err) {
        conn->connected = 0;
        return 0;
    }
    
    return 1;
}

// Send event to Redis
int redis_send_event(redis_connection_t *conn, const struct ravn_event *event) {
    if (!redis_is_connected(conn)) {
        snprintf(last_error, sizeof(last_error), "Redis not connected");
        return -1;
    }
    
    // Create JSON representation with proper escaping
    char json_data[2048];
    char escaped_data[1024];
    
    // Escape quotes in data field
    int j = 0;
    for (int i = 0; event->data[i] && j < (int)sizeof(escaped_data) - 1; i++) {
        if (event->data[i] == '"') {
            escaped_data[j++] = '\\';
            escaped_data[j++] = '"';
        } else if (event->data[i] == '\\') {
            escaped_data[j++] = '\\';
            escaped_data[j++] = '\\';
        } else {
            escaped_data[j++] = event->data[i];
        }
    }
    escaped_data[j] = '\0';
    
    snprintf(json_data, sizeof(json_data),
        "{\"timestamp\":%lu,\"pid\":%u,\"tid\":%u,\"event_type\":%u,\"event_category\":%u,\"comm\":\"%s\",\"data\":\"%s\"}",
        event->timestamp, event->pid, event->tid, event->event_type, 
        event->event_category, event->comm, escaped_data);
    
    // Send to events list
    redisReply *reply = redisCommand(conn->context, "LPUSH events:raw %s", json_data);
    if (!reply) {
        snprintf(last_error, sizeof(last_error), "Failed to send event to Redis");
        return -1;
    }
    
    // Accept both integer replies (LPUSH returns list length) and status replies
    int result = (reply->type == REDIS_REPLY_INTEGER || reply->type == REDIS_REPLY_STATUS) ? 0 : -1;
    if (result != 0) {
        snprintf(last_error, sizeof(last_error), "Redis reply type: %d, expected integer or status", 
                reply->type);
    }
    freeReplyObject(reply);
    
    // Keep only last 1000 events
    redisCommand(conn->context, "LTRIM events:raw 0 999");
    
    return result;
}

// Get event from Redis
int redis_get_event(redis_connection_t *conn, struct ravn_event *event) {
    if (!redis_is_connected(conn)) {
        snprintf(last_error, sizeof(last_error), "Redis not connected");
        return -1;
    }
    
    // Get event from events list (blocking with 1 second timeout)
    redisReply *reply = redisCommand(conn->context, "BRPOP events:raw 1");
    if (!reply || reply->type != REDIS_REPLY_ARRAY || reply->elements < 2) {
        if (reply) freeReplyObject(reply);
        return -1; // No events available
    }
    
    // Parse JSON data
    const char *json_str = reply->element[1]->str;
    int parsed = sscanf(json_str,
        "{\"timestamp\":%lu,\"pid\":%u,\"tid\":%u,\"event_type\":%u,\"event_category\":%u,\"comm\":\"%15[^\"]\",\"data\":\"%1023[^\"]\"}",
        &event->timestamp, &event->pid, &event->tid, &event->event_type,
        &event->event_category, event->comm, event->data);
    
    freeReplyObject(reply);
    
    if (parsed != 7) {
        snprintf(last_error, sizeof(last_error), "Failed to parse event JSON");
        return -1;
    }
    
    return 0;
}

// Subscribe to events (simplified implementation)
int redis_subscribe_events(redis_connection_t *conn, void (*callback)(const struct ravn_event *)) {
    (void)conn; // Suppress unused parameter warning
    (void)callback; // Suppress unused parameter warning
    // This would implement Redis pub/sub for real-time events
    // For now, just return success
    printf("[Redis] Event subscription not implemented yet\n");
    return 0;
}

// Update threat level in Redis
int redis_update_threat_level(redis_connection_t *conn, const threat_level_t *threat) {
    if (!redis_is_connected(conn)) {
        snprintf(last_error, sizeof(last_error), "Redis not connected");
        return -1;
    }
    
    // Create JSON representation
    char json_data[512];
    snprintf(json_data, sizeof(json_data),
        "{\"timestamp\":%lu,\"score\":%.2f,\"level\":%d,\"reason\":\"%s\"}",
        threat->timestamp, threat->score, threat->level, threat->reason);
    
    // Store current threat level
    redisReply *reply = redisCommand(conn->context, "SET threat:current %s", json_data);
    if (!reply) {
        snprintf(last_error, sizeof(last_error), "Failed to update threat level");
        return -1;
    }
    
    int result = (reply->type == REDIS_REPLY_STATUS && strcmp(reply->str, "OK") == 0) ? 0 : -1;
    freeReplyObject(reply);
    
    // Publish threat level update
    redisCommand(conn->context, "PUBLISH threat:update %s", json_data);
    
    return result;
}

// Get current threat level from Redis
int redis_get_threat_level(redis_connection_t *conn, threat_level_t *threat) {
    if (!redis_is_connected(conn)) {
        snprintf(last_error, sizeof(last_error), "Redis not connected");
        return -1;
    }
    
    redisReply *reply = redisCommand(conn->context, "GET threat:current");
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        if (reply) freeReplyObject(reply);
        snprintf(last_error, sizeof(last_error), "No threat level data available");
        return -1;
    }
    
    // Parse JSON data - handle integer level format
    int parsed = sscanf(reply->str,
        "{\"timestamp\":%lu,\"score\":%f,\"level\":%d,\"reason\":\"%255[^\"]\"}",
        &threat->timestamp, &threat->score, &threat->level, threat->reason);
    
    freeReplyObject(reply);
    
    if (parsed != 4) {
        snprintf(last_error, sizeof(last_error), "Failed to parse threat level JSON");
        return -1;
    }
    
    return 0;
}

// Subscribe to threat level updates (simplified implementation)
int redis_subscribe_threat_updates(redis_connection_t *conn, void (*callback)(const threat_level_t *)) {
    (void)conn; // Suppress unused parameter warning
    (void)callback; // Suppress unused parameter warning
    // This would implement Redis pub/sub for real-time threat updates
    // For now, just return success
    printf("[Redis] Threat level subscription not implemented yet\n");
    return 0;
}

// Get last error message
char* redis_get_last_error(void) {
    return last_error;
}

// Ping Redis server
int redis_ping(redis_connection_t *conn) {
    if (!conn || !conn->context) {
        return -1;
    }
    
    redisReply *reply = redisCommand(conn->context, "PING");
    if (!reply) {
        return -1;
    }
    
    int result = (reply->type == REDIS_REPLY_STATUS && strcmp(reply->str, "PONG") == 0) ? 0 : -1;
    freeReplyObject(reply);
    
    return result;
}

// Flush all Redis data
int redis_flush_all(redis_connection_t *conn) {
    if (!redis_is_connected(conn)) {
        return -1;
    }
    
    redisReply *reply = redisCommand(conn->context, "FLUSHALL");
    if (!reply) {
        return -1;
    }
    
    int result = (reply->type == REDIS_REPLY_STATUS && strcmp(reply->str, "OK") == 0) ? 0 : -1;
    freeReplyObject(reply);
    
    return result;
}