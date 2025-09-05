/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <bpf/libbpf.h>
#include <sqlite3.h>
#include <sys/resource.h>

#include "core_execfs.h"

static volatile sig_atomic_t exiting = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args) {
	// Show all libbpf messages for debugging
	(void)level; // Suppress unused parameter warning
	return vfprintf(stderr, fmt, args);
}
static sqlite3 *g_db = NULL;
static sqlite3_stmt *g_ins_event = NULL;
static sqlite3_stmt *g_ins_score = NULL;

static int db_init(const char *path) {
	if (sqlite3_open(path, &g_db) != SQLITE_OK) {
		fprintf(stderr, "sqlite open: %s\n", sqlite3_errmsg(g_db));
		return -1;
	}
	const char *ddl_events =
		"CREATE TABLE IF NOT EXISTS events (" \
		"id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ns INTEGER, etype TEXT, pid INTEGER, tgid INTEGER, ppid INTEGER, uid INTEGER, gid INTEGER, comm TEXT, file TEXT);";
	const char *ddl_scores =
		"CREATE TABLE IF NOT EXISTS scores (" \
		"ts_s INTEGER, z REAL);";
	char *errmsg = NULL;
	if (sqlite3_exec(g_db, ddl_events, NULL, NULL, &errmsg) != SQLITE_OK) {
		fprintf(stderr, "sqlite ddl events: %s\n", errmsg);
		sqlite3_free(errmsg);
		return -1;
	}
	if (sqlite3_exec(g_db, ddl_scores, NULL, NULL, &errmsg) != SQLITE_OK) {
		fprintf(stderr, "sqlite ddl scores: %s\n", errmsg);
		sqlite3_free(errmsg);
		return -1;
	}
	const char *ins_e = "INSERT INTO events(ts_ns,etype,pid,tgid,ppid,uid,gid,comm,file) VALUES(?,?,?,?,?,?,?,?,?);";
	if (sqlite3_prepare_v2(g_db, ins_e, -1, &g_ins_event, NULL) != SQLITE_OK) {
		fprintf(stderr, "prep ins event: %s\n", sqlite3_errmsg(g_db));
		return -1;
	}
	const char *ins_s = "INSERT INTO scores(ts_s,z) VALUES(?,?);";
	if (sqlite3_prepare_v2(g_db, ins_s, -1, &g_ins_score, NULL) != SQLITE_OK) {
		fprintf(stderr, "prep ins score: %s\n", sqlite3_errmsg(g_db));
		return -1;
	}
	return 0;
}

static void db_close(void) {
	if (g_ins_event) sqlite3_finalize(g_ins_event);
	if (g_ins_score) sqlite3_finalize(g_ins_score);
	if (g_db) sqlite3_close(g_db);
	g_db = NULL; g_ins_event = NULL; g_ins_score = NULL;
}

static void handle_sigint(int sig) {
	(void)sig;
	exiting = 1;
}

// Global counters for anomaly detection
static volatile unsigned long g_sec_count = 0;
static volatile unsigned long g_exec_count = 0;
static volatile unsigned long g_open_count = 0;

static int handle_event(void *ctx, void *data, size_t len) {
	(void)ctx;
	(void)len;
	const struct event *e = (const struct event *)data;
	char ts[64];
	struct timespec t;
	clock_gettime(CLOCK_REALTIME, &t);
	snprintf(ts, sizeof(ts), "%ld.%09ld", t.tv_sec, t.tv_nsec);
	const char *etype = (e->event_type == EV_EXEC) ? "exec" : (e->event_type == EV_OPEN ? "open" : "unknown");
	
	// Update counters for anomaly detection
	__sync_fetch_and_add(&g_sec_count, 1);
	if (e->event_type == EV_EXEC) {
		__sync_fetch_and_add(&g_exec_count, 1);
	} else if (e->event_type == EV_OPEN) {
		__sync_fetch_and_add(&g_open_count, 1);
	}
	
	printf("{\"ts\":\"%s\",\"etype\":\"%s\",\"pid\":%u,\"tgid\":%u,\"ppid\":%u,\"uid\":%u,\"gid\":%u,\"comm\":\"%s\",\"file\":\"%s\"}\n",
	       ts, etype, e->pid, e->tgid, e->ppid, e->uid, e->gid, e->comm, e->filename);
	fflush(stdout);
	if (g_db && g_ins_event) {
		sqlite3_reset(g_ins_event);
		sqlite3_bind_int64(g_ins_event, 1, (sqlite3_int64)e->timestamp_ns);
		sqlite3_bind_text(g_ins_event, 2, etype, -1, SQLITE_STATIC);
		sqlite3_bind_int(g_ins_event, 3, (int)e->pid);
		sqlite3_bind_int(g_ins_event, 4, (int)e->tgid);
		sqlite3_bind_int(g_ins_event, 5, (int)e->ppid);
		sqlite3_bind_int(g_ins_event, 6, (int)e->uid);
		sqlite3_bind_int(g_ins_event, 7, (int)e->gid);
		sqlite3_bind_text(g_ins_event, 8, e->comm, -1, SQLITE_STATIC);
		sqlite3_bind_text(g_ins_event, 9, e->filename, -1, SQLITE_STATIC);
		sqlite3_step(g_ins_event);
	}
	return 0;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
	int err = 0;
	
	// Ring buffer variables
	struct ring_buffer *execfs_rb = NULL;
	struct ring_buffer *network_rb = NULL;
	struct ring_buffer *system_rb = NULL;
	struct ring_buffer *security_rb = NULL;
	struct ring_buffer *vulnerability_rb = NULL;
	struct ring_buffer *update_rb = NULL;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	// Raise memlock rlimit for BPF maps/programs
	struct rlimit rl = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
	setrlimit(RLIMIT_MEMLOCK, &rl);

	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);

	if (db_init(".cache/ravn.db") != 0) {
		fprintf(stderr, "sqlite init failed, continuing without persistence\n");
	}

	// Load multiple eBPF programs for comprehensive security monitoring
	struct bpf_object *execfs_obj = bpf_object__open_file(".cache/build/core_execfs.bpf.o", NULL);
	struct bpf_object *network_obj = bpf_object__open_file(".cache/build/core_network.bpf.o", NULL);
	struct bpf_object *system_obj = bpf_object__open_file(".cache/build/core_system.bpf.o", NULL);
	struct bpf_object *security_obj = bpf_object__open_file(".cache/build/core_security.bpf.o", NULL);
	struct bpf_object *vulnerability_obj = bpf_object__open_file(".cache/build/core_vulnerability.bpf.o", NULL);
	struct bpf_object *update_obj = bpf_object__open_file(".cache/build/core_update-checker.bpf.o", NULL);
	
	if (libbpf_get_error(execfs_obj)) {
		err = -errno;
		fprintf(stderr, "open execfs bpf obj: %s\n", strerror(errno));
		execfs_obj = NULL;
		goto cleanup;
	}
	
	if (libbpf_get_error(network_obj)) {
		err = -errno;
		fprintf(stderr, "open network bpf obj: %s\n", strerror(errno));
		network_obj = NULL;
		goto cleanup;
	}
	
	if (libbpf_get_error(system_obj)) {
		err = -errno;
		fprintf(stderr, "open system bpf obj: %s\n", strerror(errno));
		system_obj = NULL;
		goto cleanup;
	}
	
	if (libbpf_get_error(security_obj)) {
		err = -errno;
		fprintf(stderr, "open security bpf obj: %s\n", strerror(errno));
		security_obj = NULL;
		goto cleanup;
	}
	
	if (libbpf_get_error(vulnerability_obj)) {
		err = -errno;
		fprintf(stderr, "open vulnerability bpf obj: %s\n", strerror(errno));
		vulnerability_obj = NULL;
		goto cleanup;
	}
	
	if (libbpf_get_error(update_obj)) {
		err = -errno;
		fprintf(stderr, "open update-checker bpf obj: %s\n", strerror(errno));
		update_obj = NULL;
		goto cleanup;
	}
	
	// Load all eBPF programs
	err = bpf_object__load(execfs_obj);
	if (err) {
		fprintf(stderr, "load execfs bpf obj: %d\n", err);
		goto cleanup;
	}
	
	err = bpf_object__load(network_obj);
	if (err) {
		fprintf(stderr, "load network bpf obj: %d\n", err);
		goto cleanup;
	}
	
	err = bpf_object__load(system_obj);
	if (err) {
		fprintf(stderr, "load system bpf obj: %d\n", err);
		goto cleanup;
	}
	
	err = bpf_object__load(security_obj);
	if (err) {
		fprintf(stderr, "load security bpf obj: %d\n", err);
		goto cleanup;
	}
	
	err = bpf_object__load(vulnerability_obj);
	if (err) {
		fprintf(stderr, "load vulnerability bpf obj: %d\n", err);
		goto cleanup;
	}
	
	err = bpf_object__load(update_obj);
	if (err) {
		fprintf(stderr, "load update-checker bpf obj: %d\n", err);
		goto cleanup;
	}
	
	// Attach all eBPF programs
	struct bpf_object *objects[] = {execfs_obj, network_obj, system_obj, security_obj, vulnerability_obj, update_obj};
	for (int i = 0; i < 6; i++) {
		if (objects[i]) {
			struct bpf_program *prog;
			bpf_object__for_each_program(prog, objects[i]) {
				const char *sec = bpf_program__section_name(prog);
				if (sec && (strstr(sec, "tracepoint/") == sec)) {
					const char *tp = sec + strlen("tracepoint/");
					const char *slash = strchr(tp, '/');
					if (!slash) { fprintf(stderr, "invalid section name: %s\n", sec); continue; }
					char category[64] = {0};
					char name[128] = {0};
					size_t catlen = (size_t)(slash - tp);
					size_t namelen = strlen(slash + 1);
					if (catlen >= sizeof(category)) catlen = sizeof(category) - 1;
					if (namelen >= sizeof(name)) namelen = sizeof(name) - 1;
					memcpy(category, tp, catlen);
					memcpy(name, slash + 1, namelen);
					if (libbpf_get_error(bpf_program__attach_tracepoint(prog, category, name))) {
						fprintf(stderr, "attach failed for %s (%s/%s)\n", sec, category, name);
					}
				}
			}
		}
	}
	
	// Create ring buffers for all eBPF programs
	struct bpf_map *execfs_events = bpf_object__find_map_by_name(execfs_obj, "events");
	struct bpf_map *network_events = bpf_object__find_map_by_name(network_obj, "network_events");
	struct bpf_map *system_events = bpf_object__find_map_by_name(system_obj, "system_events");
	struct bpf_map *security_events = bpf_object__find_map_by_name(security_obj, "security_events");
	struct bpf_map *vulnerability_events = bpf_object__find_map_by_name(vulnerability_obj, "vulnerability_events");
	struct bpf_map *update_events = bpf_object__find_map_by_name(update_obj, "update_events");
	
	if (!execfs_events) { fprintf(stderr, "execfs events map not found\n"); err = -1; goto cleanup; }
	if (!network_events) { fprintf(stderr, "network events map not found\n"); err = -1; goto cleanup; }
	if (!system_events) { fprintf(stderr, "system events map not found\n"); err = -1; goto cleanup; }
	if (!security_events) { fprintf(stderr, "security events map not found\n"); err = -1; goto cleanup; }
	if (!vulnerability_events) { fprintf(stderr, "vulnerability events map not found\n"); err = -1; goto cleanup; }
	if (!update_events) { fprintf(stderr, "update events map not found\n"); err = -1; goto cleanup; }
	
	// Create ring buffers for all eBPF programs
	execfs_rb = ring_buffer__new(bpf_map__fd(execfs_events), handle_event, NULL, NULL);
	network_rb = ring_buffer__new(bpf_map__fd(network_events), handle_event, NULL, NULL);
	system_rb = ring_buffer__new(bpf_map__fd(system_events), handle_event, NULL, NULL);
	security_rb = ring_buffer__new(bpf_map__fd(security_events), handle_event, NULL, NULL);
	vulnerability_rb = ring_buffer__new(bpf_map__fd(vulnerability_events), handle_event, NULL, NULL);
	update_rb = ring_buffer__new(bpf_map__fd(update_events), handle_event, NULL, NULL);
	
	if (!execfs_rb) { fprintf(stderr, "failed to create execfs ring buffer\n"); err = -1; goto cleanup; }
	if (!network_rb) { fprintf(stderr, "failed to create network ring buffer\n"); err = -1; goto cleanup; }
	if (!system_rb) { fprintf(stderr, "failed to create system ring buffer\n"); err = -1; goto cleanup; }
	if (!security_rb) { fprintf(stderr, "failed to create security ring buffer\n"); err = -1; goto cleanup; }
	if (!vulnerability_rb) { fprintf(stderr, "failed to create vulnerability ring buffer\n"); err = -1; goto cleanup; }
	if (!update_rb) { fprintf(stderr, "failed to create update ring buffer\n"); err = -1; goto cleanup; }
	
	// All ring buffers created successfully

	// Agent runs silently - dashboard controls it

	// Improved anomaly detection with multiple metrics
	unsigned long last_sec = 0;
	
	// Rolling window for better anomaly detection (60 seconds)
	#define WINDOW_SIZE 60
	double event_rates[WINDOW_SIZE] = {0};
	int window_idx = 0;
	// unsigned long window_start = 0; // Unused for now
	
	while (!exiting) {
		// Poll all ring buffers
		err = ring_buffer__poll(execfs_rb, 50 /* ms */);
		if (err == -EINTR) break;
		if (err < 0) { fprintf(stderr, "execfs ring_buffer__poll: %d\n", err); }
		
		err = ring_buffer__poll(network_rb, 50 /* ms */);
		if (err == -EINTR) break;
		if (err < 0) { fprintf(stderr, "network ring_buffer__poll: %d\n", err); }
		
		err = ring_buffer__poll(system_rb, 50 /* ms */);
		if (err == -EINTR) break;
		if (err < 0) { fprintf(stderr, "system ring_buffer__poll: %d\n", err); }
		
		err = ring_buffer__poll(security_rb, 50 /* ms */);
		if (err == -EINTR) break;
		if (err < 0) { fprintf(stderr, "security ring_buffer__poll: %d\n", err); }
		
		err = ring_buffer__poll(vulnerability_rb, 50 /* ms */);
		if (err == -EINTR) break;
		if (err < 0) { fprintf(stderr, "vulnerability ring_buffer__poll: %d\n", err); }
		
		err = ring_buffer__poll(update_rb, 50 /* ms */);
		if (err == -EINTR) break;
		if (err < 0) { fprintf(stderr, "update ring_buffer__poll: %d\n", err); }
		struct timespec now;
		clock_gettime(CLOCK_REALTIME, &now);
		unsigned long cur_sec = (unsigned long)now.tv_sec;
		if (last_sec == 0) {
			last_sec = cur_sec;
		}
		if (cur_sec != last_sec) {
			// Get current counts atomically
			unsigned long sec_count = __sync_fetch_and_and(&g_sec_count, 0); // Reset to 0
			unsigned long exec_count = __sync_fetch_and_and(&g_exec_count, 0); // Reset to 0
			__sync_fetch_and_and(&g_open_count, 0); // Reset to 0
			
			// Calculate anomaly score based on multiple factors
			double total_rate = (double)sec_count;
			double exec_ratio = sec_count > 0 ? (double)exec_count / (double)sec_count : 0.0;
			
			// Store in rolling window
			event_rates[window_idx] = total_rate;
			window_idx = (window_idx + 1) % WINDOW_SIZE;
			
			// Calculate rolling statistics
			double window_mean = 0.0, window_var = 0.0;
			int valid_samples = 0;
			for (int i = 0; i < WINDOW_SIZE; i++) {
				if (event_rates[i] > 0) {
					window_mean += event_rates[i];
					valid_samples++;
				}
			}
			if (valid_samples > 0) {
				window_mean /= (double)valid_samples;
				for (int i = 0; i < WINDOW_SIZE; i++) {
					if (event_rates[i] > 0) {
						double diff = event_rates[i] - window_mean;
						window_var += diff * diff;
					}
				}
				window_var /= (double)valid_samples;
			}
			double window_std = sqrt(window_var);
			
			// Calculate Z-score with improved logic
			double z_score = 0.0;
			if (window_std > 0.0 && valid_samples > 5) {
				z_score = (total_rate - window_mean) / window_std;
			}
			
			// Boost score for suspicious patterns
			if (exec_ratio > 0.1) z_score += 1.0; // High exec ratio
			if (total_rate > window_mean * 3.0) z_score += 1.5; // Rate spike
			
			// Store score in database
			if (g_db && g_ins_score) {
				sqlite3_reset(g_ins_score);
				sqlite3_bind_int64(g_ins_score, 1, (sqlite3_int64)last_sec);
				sqlite3_bind_double(g_ins_score, 2, z_score);
				sqlite3_step(g_ins_score);
			}
			
			last_sec = cur_sec;
		}
	}

cleanup:
	if (execfs_rb) ring_buffer__free(execfs_rb);
	if (network_rb) ring_buffer__free(network_rb);
	if (system_rb) ring_buffer__free(system_rb);
	if (security_rb) ring_buffer__free(security_rb);
	if (vulnerability_rb) ring_buffer__free(vulnerability_rb);
	if (update_rb) ring_buffer__free(update_rb);
	if (execfs_obj) bpf_object__close(execfs_obj);
	if (network_obj) bpf_object__close(network_obj);
	if (system_obj) bpf_object__close(system_obj);
	if (security_obj) bpf_object__close(security_obj);
	if (vulnerability_obj) bpf_object__close(vulnerability_obj);
	if (update_obj) bpf_object__close(update_obj);
	db_close();
	return err ? 1 : 0;
}


