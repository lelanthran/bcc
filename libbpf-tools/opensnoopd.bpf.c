// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Lelanthran Manickum
// Copyright (c) 2024 Lelanthran Manickum
//
// Derived from opensnoop from https://github.com/iovisor/bcc
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "opensnoopd.h"

const volatile int targ_oflags = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

#if 0
static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID;
}

static __always_inline
bool trace_allowed(u32 tgid, u32 pid)
{
	u32 uid;

	/* filters */
	if (targ_tgid && targ_tgid != tgid)
		return false;
	if (targ_pid && targ_pid != pid)
		return false;
	if (valid_uid(targ_uid)) {
		uid = (u32)bpf_get_current_uid_gid();
		if (targ_uid != uid) {
			return false;
		}
	}
	return true;
}
#endif

	/*
	static const struct exclusion_list excl_list[] = {
		{ "/sys/",      5 },
		{ "/dev/",      5 },
		{ "/tmp/",      5 },
		{ "/lib/",      5 },
		{ "/proc/",     6 },
		{ "/usr/lib",   8 },
		};
		*/
#define match(skip,s,s_len,prefix,prefix_len) do {\
	for (size_t j=0; j<prefix_len && j<s_len; j++) {\
		if (prefix[j] != s[j]) {\
			skip = false;\
		}\
	}\
} while (0)


SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
{
#if 0
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		args.fname = (const char *)ctx->args[0];
		args.flags = (int)ctx->args[1];
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
#endif
	struct args_t args = {};
	args.fname = (const char *)ctx->args[1];
	args.flags = (int)ctx->args[2];
	if (args.flags & targ_oflags) {
		u32 pid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
#if 0
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		args.fname = (const char *)ctx->args[1];
		args.flags = (int)ctx->args[2];
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
#endif

	struct args_t args = {};
	args.fname = (const char *)ctx->args[1];
	args.flags = (int)ctx->args[2];
	if (args.flags & targ_oflags) {
		u32 pid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

#if 0
static __always_inline
int trace_exit(struct trace_event_raw_sys_exit* ctx)
{
	struct event event = {};
	struct args_t *ap;
	uintptr_t stack[3];
	int ret;
	u32 pid = bpf_get_current_pid_tgid();

	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0;	/* missed entry */
	ret = ctx->ret;
	if (targ_failed && ret >= 0)
		goto cleanup;	/* want failed only */

	/* event data */
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
	event.flags = ap->flags;
	event.ret = ret;

	bpf_get_stack(ctx, &stack, sizeof(stack),
		      BPF_F_USER_STACK);
	/* Skip the first address that is usually the syscall it-self */
	event.callers[0] = stack[1];
	event.callers[1] = stack[2];

	/* emit event */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}
#endif

static __always_inline
int trace_exit(struct trace_event_raw_sys_exit* ctx)
{
	struct event event = {};
	struct args_t *ap;

	u32 pid = bpf_get_current_pid_tgid();
	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0;	/* missed entry */

	/* On error, ignore the open call */
	if (ctx->ret > 0) {
		/* Event data */
		bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
		event.flags = ap->flags;
		event.ret = ctx->ret;
		// bpf_trace_printk("[%s:%s]\n", 9, event.fname, ap->fname);

		/* Emit event */
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	}
	/* Clean up the hashmap */
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
	return trace_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
