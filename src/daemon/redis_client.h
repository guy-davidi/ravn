// RAVN Redis Client Header
// Defines functions for Redis communication

#ifndef RAVN_REDIS_CLIENT_H
#define RAVN_REDIS_CLIENT_H

#include <stdint.h>
#include <time.h>

// Forward declaration for Redis context
typedef struct redisContext redisContext;

// Redis connection structure
typedef struct redis_connection redis_connection_t;
struct redis_connection {
    redisContext *context;
    int connected;
    char host[256];
    int port;
};

// Include the full definition
#include "ebpf_handler.h"

// Threat level structure
typedef struct threat_level threat_level_t;
struct threat_level {
    uint64_t timestamp;
    float score;
    int level; // 0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL
    char reason[256];
};

// Threat level constants
#define THREAT_LOW 0
#define THREAT_MEDIUM 1
#define THREAT_HIGH 2
#define THREAT_CRITICAL 3

// Redis client functions
redis_connection_t* redis_connect(const char *host, int port);
void redis_disconnect(redis_connection_t *conn);
int redis_is_connected(redis_connection_t *conn);

// Event functions
int redis_send_event(redis_connection_t *conn, const struct ravn_event *event);
int redis_get_event(redis_connection_t *conn, struct ravn_event *event);
int redis_subscribe_events(redis_connection_t *conn, void (*callback)(const struct ravn_event *));

// Threat level functions
int redis_update_threat_level(redis_connection_t *conn, const threat_level_t *threat);
int redis_get_threat_level(redis_connection_t *conn, threat_level_t *threat);
int redis_subscribe_threat_updates(redis_connection_t *conn, void (*callback)(const threat_level_t *));

// Utility functions
char* redis_get_last_error(void);
int redis_ping(redis_connection_t *conn);
int redis_flush_all(redis_connection_t *conn);

#endif // RAVN_REDIS_CLIENT_H
