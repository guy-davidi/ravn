/* SPDX-License-Identifier: GPL-2.0 */
/*
 * eBPF Network Program Interface
 * 
 * This file defines the interface for the eBPF network program that monitors
 * network connections, traffic patterns, and network-based security events.
 *
 * Author: ravn Security Team
 * Date: 2025
 */

#ifndef _ravn_CORE_NETWORK_IF_H
#define _ravn_CORE_NETWORK_IF_H

#include <stdint.h>

/**
 * Network event types
 */
enum core_network_event_type {
	CORE_NETWORK_EVENT_CONNECT = 1,
	CORE_NETWORK_EVENT_ACCEPT = 2,
	CORE_NETWORK_EVENT_SEND = 3,
	CORE_NETWORK_EVENT_RECV = 4,
	CORE_NETWORK_EVENT_CLOSE = 5,
	CORE_NETWORK_EVENT_LISTEN = 6,
};

/**
 * Network protocols
 */
enum core_network_protocol {
	CORE_NETWORK_PROTOCOL_TCP = 1,
	CORE_NETWORK_PROTOCOL_UDP = 2,
	CORE_NETWORK_PROTOCOL_ICMP = 3,
	CORE_NETWORK_PROTOCOL_UNKNOWN = 255,
};

/**
 * struct core_network_event - Network event structure
 * @timestamp_ns: Event timestamp in nanoseconds
 * @event_type: Type of network event
 * @pid: Process ID
 * @tgid: Thread group ID
 * @uid: User ID
 * @gid: Group ID
 * @comm: Process command name
 * @src_addr: Source IP address
 * @dst_addr: Destination IP address
 * @src_port: Source port
 * @dst_port: Destination port
 * @bytes: Number of bytes transferred
 * @protocol: Network protocol
 */
struct core_network_event {
	uint64_t timestamp_ns;
	uint32_t event_type;
	uint32_t pid;
	uint32_t tgid;
	uint32_t uid;
	uint32_t gid;
	char comm[16];
	uint32_t src_addr;
	uint32_t dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t bytes;
	uint8_t protocol;
};

/**
 * Core network program configuration
 */
struct core_network_config {
	int monitor_connections;
	int monitor_traffic;
	int monitor_listen;
	uint32_t max_connections;
	uint32_t traffic_threshold;
};

/**
 * core_network_program_load() - Load network eBPF program
 * @config: Program configuration
 *
 * Load the network eBPF program with the given configuration.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_network_program_load(const struct core_network_config *config);

/**
 * core_network_program_attach() - Attach network eBPF program
 *
 * Attach the network eBPF program to kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_network_program_attach(void);

/**
 * core_network_program_detach() - Detach network eBPF program
 *
 * Detach the network eBPF program from kernel tracepoints.
 *
 * Return: 0 on success, negative error code on failure
 */
int core_network_program_detach(void);

/**
 * core_network_get_ring_buffer() - Get network ring buffer
 *
 * Get the ring buffer for network events.
 *
 * Return: Pointer to ring buffer on success, NULL on failure
 */
void *core_network_get_ring_buffer(void);

#endif /* _ravn_CORE_NETWORK_IF_H */
