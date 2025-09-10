/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* Basic types */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

/* Common kernel types */
typedef unsigned long size_t;
typedef long ssize_t;
typedef int pid_t;
typedef int uid_t;
typedef int gid_t;
typedef unsigned int mode_t;
typedef long time_t;
typedef long long time64_t;

/* String types */
typedef char comm[16];

/* Kernel structures we need */
struct task_struct {
	int pid;
	int tgid;
	comm comm;
	uid_t uid;
	gid_t gid;
};

struct file {
	int f_flags;
	mode_t f_mode;
};

struct inode {
	uid_t i_uid;
	gid_t i_gid;
	mode_t i_mode;
};

struct dentry {
	char d_name[256];
};

struct path {
	struct dentry* dentry;
	struct inode* inode;
};

/* Network structures */
struct sock {
	__u16 sk_family;
	__u16 sk_type;
	__u16 sk_protocol;
};

struct socket {
	struct sock* sk;
};

/* Memory structures */
struct vm_area_struct {
	unsigned long vm_start;
	unsigned long vm_end;
	unsigned long vm_flags;
};

/* Time structures */
struct timespec {
	time_t tv_sec;
	long tv_nsec;
};

/* Network types */
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

/* BPF map types */
#define BPF_MAP_TYPE_RINGBUF 27

/* BPF program types */
#define BPF_PROG_TYPE_TRACEPOINT 6
#define BPF_PROG_TYPE_KPROBE	 2

/* BPF attach types */
#define BPF_TRACE_RAW_TP 0

/* BPF flags */
#define BPF_F_RDONLY 8
#define BPF_F_WRONLY 16

/* Common constants */
#define MAX_FILENAME_LEN 256
#define MAX_COMM_LEN	 16

#endif /* __VMLINUX_H__ */
