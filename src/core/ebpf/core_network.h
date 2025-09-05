/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETWORK_H
#define __NETWORK_H

#include "compat/linux/types.h"

enum network_event_type {
	NET_CONNECT = 1,
	NET_ACCEPT = 2,
	NET_SEND = 3,
	NET_RECV = 4,
};

struct network_event {
	__u64 timestamp_ns;
	__u32 event_type;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 gid;
	char comm[16];
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 bytes;
	__u8 protocol; // 1=TCP, 2=UDP
};

#endif /* __NETWORK_H */
