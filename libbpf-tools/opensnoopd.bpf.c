// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Rundata Systems, Gauteng, South Africa.
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
} maps_open SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} maps_unlink SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline
int trace_open_enter(struct trace_event_raw_sys_enter* ctx)
{
	/* *****************************************************************
	 * Gotta be honest, this doesn't look correct for my use-case.
	 * If a process $PID opens two files in two separate threads
	 * it's quite probable that _exit gets called for the second
	 * _enter before it gets called for the first _enter.
	 */
	struct args_t args = {};
	args.fname = (const char *)ctx->args[1];
	args.flags = (int)ctx->args[2];
	if (args.flags & targ_oflags) {
		u32 pid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&maps_open, &pid, &args, 0);
	}
	return 0;
}

static __always_inline
int trace_open_exit(struct trace_event_raw_sys_exit* ctx)
{
	struct event event = {};
	struct args_t *ap;

	u32 pid = bpf_get_current_pid_tgid();
	ap = bpf_map_lookup_elem(&maps_open, &pid);
	if (!ap)
		return 0;	/* missed entry */

	/* On error, ignore the open call */
	if (ctx->ret > 0) {
		/* Event data */
		bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
		event.flags = ap->flags;
		event.ret = ctx->ret;
		event.action = OPENSNOOPD_ACTION_OPEN;

		/* Emit event */
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	}
	/* Clean up the hashmap */
	bpf_map_delete_elem(&maps_open, &pid);
	return 0;
}

static __always_inline
int trace_unlink_enter(struct trace_event_raw_sys_enter* ctx, const char *fname)
{
	struct args_t args = {};
	args.fname = fname;
	args.flags = 0;
	/* We really need a way to filter these */
	u32 pid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&maps_unlink, &pid, &args, 0);
	return 0;
}

static __always_inline
int trace_unlink_exit(struct trace_event_raw_sys_exit* ctx)
{
	struct event event = {};
	struct args_t *ap;

	u32 pid = bpf_get_current_pid_tgid();
	ap = bpf_map_lookup_elem(&maps_unlink, &pid);
	if (!ap)
		return 0;	/* missed entry */

	/* On error, ignore the syscall */
	if (ctx->ret == 0) {
		/* Event data */
		bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
		event.flags = ap->flags;
		event.ret = ctx->ret;
		event.action = OPENSNOOPD_ACTION_UNLINK;

		/* Emit event */
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	}
	/* Clean up the hashmap */
	bpf_map_delete_elem(&maps_unlink, &pid);
	return 0;
}

#if 0
/* Cannot easily trace this call, dunno what the $PWD is. Tracing relative
 * openat calls is non-trivial and involves tracking chdir by PID in a
 * syscall_enter_chdir() function, then looking up that PID in the
 * syscall_enter_open() function, and then cleaning that chdir map in
 * a syscall_enter_process_exit() function.
 *
 * For now, let it get indexed by the filetree walker. It'll still show up
 * in the results, it just won't show up immediately.
 */
SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
{
	return trace_open_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx)
{
	return trace_open_exit(ctx);
}
#endif

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
	return trace_open_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
	return trace_open_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int tracepoint__syscalls__sys_enter_unlink(struct trace_event_raw_sys_enter* ctx)
{
	return trace_unlink_enter(ctx, (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int tracepoint__syscalls__sys_exit_unlink(struct trace_event_raw_sys_exit* ctx)
{
	return trace_unlink_exit(ctx);
}


SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter* ctx)
{
	return trace_unlink_enter(ctx, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int tracepoint__syscalls__sys_exit_unlinkat(struct trace_event_raw_sys_exit* ctx)
{
	return trace_unlink_exit(ctx);
}



char LICENSE[] SEC("license") = "GPL";
