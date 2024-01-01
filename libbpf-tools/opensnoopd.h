// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Rundata Systems, Gauteng, South Africa.
//
// Derived from opensnoop from https://github.com/iovisor/bcc
#ifndef __OPENSNOOPD_H
#define __OPENSNOOPD_H

#define TASK_COMM_LEN 16
#define NAME_LEN 384
#define INVALID_UID ((uid_t)-1)

#define OPENSNOOPD_ACTION_ERROR     (0)
#define OPENSNOOPD_ACTION_OPEN      (1)
#define OPENSNOOPD_ACTION_UNLINK    (2)
#define OPENSNOOPD_ACTION_RENAME    (3)
#define OPENSNOOPD_ACTION_CHDIR     (4)

struct args_t {
	const char *fname;
	int flags;
};

struct event {
   int action;
	int ret;
	char fname[NAME_LEN];
	int flags;
};

struct exclusion_list {
	const char *prefix;
	const size_t len;
};

#endif /* __OPENSNOOPD_H */
