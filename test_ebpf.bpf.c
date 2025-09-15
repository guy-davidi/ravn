/*
 * Test eBPF program to verify function attachment
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// Simple ring buffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024);
} test_events SEC(".maps");

// Test with a function we know exists
SEC("kprobe/__x64_sys_openat2")
int test_openat2(struct pt_regs* ctx) {
	// Just return - this is just a test
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
