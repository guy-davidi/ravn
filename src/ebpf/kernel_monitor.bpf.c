/*
 * RAVN Kernel Monitor - eBPF Program (Simplified)
 *
 * This eBPF program provides basic kernel monitoring capabilities.
 * Enhanced functionality will be added in future iterations.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ravn_events.h"

/*
 * Ring buffer for kernel events
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} kernel_events SEC(".maps");

/*
 * Helper function to get current timestamp
 */
static __always_inline __u64 get_timestamp(void) {
	return bpf_ktime_get_ns();
}

/*
 * Helper function to get process name
 */
static __always_inline void get_process_name(char* comm) {
	bpf_get_current_comm(comm, 16);
}

/*
 * Helper function to send kernel event
 */
static __always_inline int send_kernel_event(__u32 event_type, __u32 cpu_id, 
					    __u64 address, __u64 size, __s64 ret) {
	struct kernel_event* event = bpf_ringbuf_reserve(&kernel_events, 
							 sizeof(struct kernel_event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp = get_timestamp();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	event->event_type = event_type;
	event->cpu_id = cpu_id;
	event->address = address;
	event->size = size;
	event->flags = 0;
	event->ret = ret;

	get_process_name(event->comm);
	
	/* Initialize arrays to zero for now - simplified */
	event->module_name[0] = 0;
	event->function_name[0] = 0;
	event->filename[0] = 0;
	event->stack_trace[0] = 0;
	event->registers[0] = 0;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

/*
 * Monitor kernel module loading (simplified)
 */
SEC("kprobe/__x64_sys_init_module")
int trace_module_load(struct pt_regs* ctx) {
	__u32 cpu_id = bpf_get_smp_processor_id();
	send_kernel_event(KERNEL_MODULE_LOAD, cpu_id, 0, 0, 0);
	return 0;
}

/*
 * Monitor kernel module unloading (simplified)
 */
SEC("kprobe/__x64_sys_delete_module")
int trace_module_unload(struct pt_regs* ctx) {
	__u32 cpu_id = bpf_get_smp_processor_id();
	send_kernel_event(KERNEL_MODULE_UNLOAD, cpu_id, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";