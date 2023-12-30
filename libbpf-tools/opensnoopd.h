/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OPENSNOOPD_H
#define __OPENSNOOPD_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t)-1)

struct args_t {
	const char *fname;
	int flags;
};

struct event {
#if 0
	/* user terminology for pid: */
	__u64 ts;
	pid_t pid;
	uid_t uid;
#endif
	int ret;
#if 0
	int flags;
	__u64 callers[2];
	char comm[TASK_COMM_LEN];
#endif
	char fname[NAME_MAX];
   int flags;
};

#endif /* __OPENSNOOPD_H */
