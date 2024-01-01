// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Rundata Systems, Gauteng, South Africa.
//
// Derived from opensnoop from https://github.com/iovisor/bcc
#ifndef __SNOOPD_H
#define __SNOOPD_H

#define TASK_COMM_LEN 16
#define NAME_LEN 384
#define INVALID_UID ((uid_t)-1)

#define SNOOPD_ACTION_ERROR     (0)
#define SNOOPD_ACTION_OPEN      (1)
#define SNOOPD_ACTION_UNLINK    (2)
#define SNOOPD_ACTION_RENAME    (3) // TODO
#define SNOOPD_ACTION_CHDIR     (4)
#define SNOOPD_ACTION_MKDIR     (5)
#define SNOOPD_ACTION_RMDIR     (6)

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

#endif /* __SNOOPD_H */
