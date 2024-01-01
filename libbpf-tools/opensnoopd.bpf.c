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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} maps_chdir SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} maps_mkdir SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline
int trace_syscall_enter(struct trace_event_raw_sys_enter* ctx,
		const char *fname, int flags,
		void *map)
{
   // bpf_trace_printk("1:%s:%i\n", 9, fname, flags);
	struct args_t args = {};
	args.fname = fname;
	args.flags = flags;
	if (args.flags & targ_oflags) {
		// bpf_trace_printk("E:%s:%i\n", 9, fname, flags);
		u32 pid = bpf_get_current_pid_tgid();
		bpf_map_update_elem((struct bpf_map *)map, &pid, &args, 0);
	}
	return 0;
}

static __always_inline
int trace_syscall_exit(struct trace_event_raw_sys_exit* ctx,
		int action,
		void *map)
{
	struct event event = {};
	struct args_t *ap;

	u32 pid = bpf_get_current_pid_tgid();
	ap = bpf_map_lookup_elem((struct bpf_map *)map, &pid);
	if (!ap)
		return 0;	/* missed entry */

	// bpf_trace_printk("e:%i:%i\n", 9, action, ctx->ret);
	/* On error, ignore the open call */
	if (ctx->ret >= 0) {
		/* Event data */
		bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
		event.flags = ap->flags;
		event.ret = ctx->ret;
		event.action = action;

		/* Emit event */

		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	}
	/* Clean up the hashmap */
	bpf_map_delete_elem((struct bpf_map *)map, &pid);
	return 0;
}

/* Cannot easily trace this call, dunno what the $PWD is. Tracing relative
 * fs calls is non-trivial and involves tracking chdir by PID in a
 * syscall_enter_chdir() function, then looking up that PID in the
 * syscall_enter_open() function, and then cleaning that chdir map in
 * a syscall_enter_process_exit() function.
 *
 * For now, let it get indexed by the filetree walker. It'll still show up
 * in the results, it just won't show up immediately.
 *
 * Due to watching chdir, rmdir and mkdir, the indexer at least has a clue
 * about the most recently changed and visited directories, so won't need
 * to walk the entire tree.
 */

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
{
	return trace_syscall_enter(ctx,
			(const char *)ctx->args[0],
			(int)ctx->args[1],
			&maps_open);
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx)
{
	return trace_syscall_exit(ctx, OPENSNOOPD_ACTION_OPEN, &maps_open);
}

/* ******************************************************************** */

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
	return trace_syscall_enter(ctx,
			(const char *)ctx->args[1],
			(int)ctx->args[2],
			&maps_open);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
	return trace_syscall_exit(ctx, OPENSNOOPD_ACTION_OPEN, &maps_open);
}

/* ******************************************************************** */

SEC("tracepoint/syscalls/sys_enter_unlink")
int tracepoint__syscalls__sys_enter_unlink(struct trace_event_raw_sys_enter* ctx)
{
	return trace_syscall_enter(ctx,
			(const char *)ctx->args[0],
			targ_oflags,
			&maps_unlink);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int tracepoint__syscalls__sys_exit_unlink(struct trace_event_raw_sys_exit* ctx)
{
	return trace_syscall_exit(ctx, OPENSNOOPD_ACTION_UNLINK, &maps_unlink);
}

/* ******************************************************************** */

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter* ctx)
{
	return trace_syscall_enter(ctx,
			(const char *)ctx->args[1],
			targ_oflags,
			&maps_unlink);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int tracepoint__syscalls__sys_exit_unlinkat(struct trace_event_raw_sys_exit* ctx)
{
	return trace_syscall_exit(ctx, OPENSNOOPD_ACTION_UNLINK, &maps_unlink);
}

/* ******************************************************************** */

SEC("tracepoint/syscalls/sys_enter_chdir")
int tracepoint__syscalls__sys_enter_chdir(struct trace_event_raw_sys_enter* ctx)
{
	return trace_syscall_enter(ctx,
			(const char *)ctx->args[0],
			targ_oflags,
			&maps_chdir);
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int tracepoint__syscalls__sys_exit_chdir(struct trace_event_raw_sys_exit* ctx)
{
	return trace_syscall_exit(ctx, OPENSNOOPD_ACTION_CHDIR, &maps_chdir);
}

/* ******************************************************************** */

SEC("tracepoint/syscalls/sys_enter_mkdir")
int tracepoint__syscalls__sys_enter_mkdir(struct trace_event_raw_sys_enter* ctx)
{
	return trace_syscall_enter(ctx,
			(const char *)ctx->args[0],
			targ_oflags,
			&maps_mkdir);
}

SEC("tracepoint/syscalls/sys_exit_mkdir")
int tracepoint__syscalls__sys_exit_mkdir(struct trace_event_raw_sys_exit* ctx)
{
	return trace_syscall_exit(ctx, OPENSNOOPD_ACTION_MKDIR, &maps_mkdir);
}

/* ******************************************************************** */

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int tracepoint__syscalls__sys_enter_mkdirat(struct trace_event_raw_sys_enter* ctx)
{
	return trace_syscall_enter(ctx,
			(const char *)ctx->args[1],
			targ_oflags,
			&maps_mkdir);
}

SEC("tracepoint/syscalls/sys_exit_mkdirat")
int tracepoint__syscalls__sys_exit_mkdirat(struct trace_event_raw_sys_exit* ctx)
{
	return trace_syscall_exit(ctx, OPENSNOOPD_ACTION_MKDIR, &maps_mkdir);
}

/* ******************************************************************** */

SEC("tracepoint/syscalls/sys_enter_rmdir")
int tracepoint__syscalls__sys_enter_rmdir(struct trace_event_raw_sys_enter* ctx)
{
	return trace_syscall_enter(ctx,
			(const char *)ctx->args[0],
			targ_oflags,
			&maps_mkdir);
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int tracepoint__syscalls__sys_exit_rmdir(struct trace_event_raw_sys_exit* ctx)
{
	return trace_syscall_exit(ctx, OPENSNOOPD_ACTION_RMDIR, &maps_mkdir);
}

/* ******************************************************************** */




char LICENSE[] SEC("license") = "GPL";
