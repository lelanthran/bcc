// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Rundata Systems, Gauteng, South Africa.
//
// Derived from opensnoop from https://github.com/iovisor/bcc
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "opensnoopd.h"
#include "opensnoopd.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

/* *********************************************************************
 * All the includes that aren't in the original opensnoop sources.
 */
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>


/* *********************************************************************
 * We keep the patterns as compiled regexes. The array must be freed
 * on program exit. The number of elements in the array is stored
 * so that reallocation is a little easier.
 */
static regex_t *regexes;
static size_t nregexes;

static bool regexes_add(const char *re_string)
{
	bool error = true;
	static char errmsg[1024];

	regex_t *tmp = realloc(regexes, (nregexes + 1) * sizeof *regexes);
	if (!tmp) {
		fprintf(stderr, "OOM error allocating %zu elements for regexes\n",
				nregexes + 1);
		goto cleanup;
	}
	regexes = tmp;

	int errcode = regcomp(&regexes[nregexes], re_string, REG_NOSUB);
	if (errcode) {
		regerror(errcode, &regexes[nregexes], errmsg, sizeof errmsg);
		errmsg[(sizeof errmsg) - 1] = 0;
		fprintf(stderr, "Failed to compile regular expression '%s': %s\n",
				re_string, errmsg);
		goto cleanup;
	}
	nregexes++;

	error = false;
cleanup:
	return !error;
}

static void regexes_free(void)
{
	for (size_t i=0; i<nregexes; i++) {
		regfree(&regexes[i]);
	}
	free (regexes);
	regexes = NULL;
}

static bool regexes_exclude(const char *fname)
{
	for (size_t i=0; i<nregexes; i++) {
		if ((regexec(&regexes[i], fname, 0, NULL, 0)) == 0) {
			return true;
		}
	}
	return false;
}



/* *********************************************************************
 * Some general housekeeping stuff.
 */

static int oflags_lookup(const char *s)
{
#define FLAG(x)   { x, #x }
	static const struct {
		int iflag;
		const char *sflag;
	} flags[] = {
		// FLAG (O_EXEC),
		FLAG (O_RDONLY),
		FLAG (O_RDWR),
		// FLAG (O_SEARCH),
		FLAG (O_WRONLY),
		FLAG (O_APPEND),
		FLAG (O_CLOEXEC),
		FLAG (O_CREAT),
		FLAG (O_DIRECTORY),
		FLAG (O_DSYNC),
		FLAG (O_EXCL),
		FLAG (O_NOCTTY),
		FLAG (O_NOFOLLOW),
		FLAG (O_NONBLOCK),
		FLAG (O_RSYNC),
		FLAG (O_SYNC),
		FLAG (O_TRUNC),
		// FLAG (O_TTY_INIT),
	};

	static const size_t nflags = sizeof flags/sizeof flags[0];

	for (size_t i=0; i<nflags; i++) {
		if ((strcmp(s, flags[i].sflag)) == 0) {
			return flags[i].iflag;
		}
	}

	return -1;
}

static int g_oflags = 0;

static bool configure (const char *key, char *value,
		const char *fname, size_t line)
{
	bool error = true;
	bool valid = false;

	if ((strcmp(key, "exclude")) == 0) {
		valid = true;
		printf("Adding regex to exclusions '%s'\n", value);
		if (!(regexes_add(value))) {
			fprintf(stderr, "[%s:%zu] Failed to add exclusion [%s]\n",
					fname, line, value);
			goto cleanup;
		}
	}

	if ((strcmp(key, "oflags")) == 0) {
		valid = true;
		char *tok = NULL;
		char *src = value;
		while ((tok = strtok (src, " "))) {
			src = NULL;
			if (!tok || tok[0] == 0) {
				continue;
			}
			int flags = oflags_lookup(tok);
			if (flags < 0) {
				fprintf(stderr, "[%s:%zu] Unrecognised open flag [%s]\n",
						fname, line, tok);
				goto cleanup;
			}
			g_oflags |= flags;
			printf("Added %s to oflag filter\n", tok);
		}
	}

	if (!valid) {
		fprintf(stderr, "Unrecognised key/value pair in [%s:%zu]\n",
				fname, line);
		goto cleanup;
	}

	error = false;
cleanup:
	return !error;
}


/* Locations for the files we need. Maybe some later version will allow
 * specifying these on the command line but for now they're constants.
 */
#define DIR_CONFIG      "/etc/opensnoopd"
#define FILE_CONFIG     DIR_CONFIG "/" "opensnoopd.conf"
#define DIR_LOG         "/var/log/opensnoopd"
#define FILE_OUT        DIR_LOG "/" "output.log"
#define FILE_ERR        DIR_LOG "/" "error.log"
#define FILE_BIN        "/sbin/opensnoopd"

static void print_remove_message(void)
{
	static const char *all[] = {
		DIR_CONFIG, FILE_CONFIG,
		DIR_LOG, FILE_OUT, FILE_ERR
	};

	fprintf(stderr, "Please remove the following files and directories:\n");
	for (size_t i=0; i<sizeof all / sizeof *all; i++) {
		fprintf(stderr, "%s\n", all[i]);
	}
}

static bool files_create(void)
{
	/* ********************************************************************
	 * TODO: Need an init file here as well:
	 * 1. SystemD
	 * 2. SysV
	 * 3. Busybox-init
	 * 4. OpenRC
	 * 5. Runit
	 *
	 * Creation of init file in a separate function that determines which
	 * one to use.
	 */
	static const struct {
		const char *fname;
		const char *content;
	} files[] = {
		{ FILE_CONFIG, "# Default configuration for opensnoopd.\n"
				"\n"
				"# Only files opened with any of the following flags will be monitored\n"
				" oflags = O_WRONLY O_RDWR  O_CREAT O_APPEND\n"
				"\n"
				"# Specify which patterns to exclude. Repeat the key for each pattern\n"
				" exclude = ^/proc \n"
				" exclude = ^/sys \n"
				" exclude = ^/tmp \n"
				" exclude = ^/dev \n" },
		{ FILE_OUT, " Installing opensnoopd ...\n" },
		{ FILE_ERR, " Installing opensnoopd ...\n" },
	};

	for (size_t i=0; i<sizeof files/sizeof *files; i++) {
		FILE *outf = fopen(files[i].fname, "r");
		if (outf) {
			fprintf(stderr, "File [%s] already exists, aborting\n", files[i].fname);
			fclose(outf);
			return false;
		}

		if (!(outf = fopen(files[i].fname, "w"))) {
			fprintf(stderr, "Failed to open [%s] for reading: %m\n", files[i].fname);
			return false;
		}
		printf("Creating file %s ... ", files[i].fname);
		fprintf(outf, "%s\n", files[i].content);
		printf("done\n");
		fclose(outf);
	}

	return true;
}

static bool dirs_create(void)
{
	static const char *dirs[] = {
		DIR_CONFIG, DIR_LOG,
	};
	static const int mode = S_IRWXU | S_IRGRP | S_IROTH;

	for (size_t i=0; i<sizeof dirs/sizeof *dirs; i++) {
		errno = 0;
		printf("Creating directory %s ... ", dirs[i]);
		if ((mkdir(dirs[i], mode)) != 0) {
			if (errno != EEXIST) {
				fprintf(stderr, "Failed to create [%s]: %m\n", dirs[i]);
				return false;
			}
		}
		printf("done\n");
	}
	return true;
}


static const char *program = "/unknown/argv/0";

static bool copy_program(void)
{
	bool error = true;
	static uint8_t buffer[1024];
	printf("Copying %s -> %s\n", program, FILE_BIN);
	FILE *inf = fopen(program, "r"),
		*outf = fopen(FILE_BIN, "w");

	if (!inf || !outf) {
		fprintf(stderr, "Failed to open files[%s->%s]: [%s:%s]: %m\n",
				program, FILE_BIN,
				inf ? "opened" : "unopened",
				outf ? "opened" : "unopened");
		goto cleanup;
	}

	errno = 0;
	size_t nbytes = 0;
	while (!feof(inf) && !ferror(inf)) {
		size_t bytes_read = fread(buffer, 1, sizeof buffer, inf);
		if (!bytes_read)
			break;
		if ((fwrite(buffer, 1, bytes_read, outf)) != bytes_read) {
			fprintf(stderr, "Error copying file: %m\n");
			goto cleanup;
		}
		nbytes += bytes_read;
		printf("\rCopied [%zu] bytes", nbytes);
		fflush(stdout);
	}
	puts("\n");
	if (ferror(inf) || ferror(outf)) {
		fprintf(stderr, "Copy failure: %m\n");
		goto cleanup;
	}

	error = false;

cleanup:
	fclose(inf);
	fclose(outf);
	return !error;
}

static bool config_read(void)
{
	bool error = true;
	FILE *inf = NULL;
	static char line[1024];
	size_t lineno = 0;

	if (!(inf = fopen(FILE_CONFIG, "r"))) {
		fprintf(stderr, "Failed to read config file [%s]: %m\n", FILE_CONFIG);
		goto cleanup;
	}

	while (!feof(inf) && !ferror(inf) && fgets(line, sizeof line, inf)) {
		lineno++;
		// Strip comments and newlines
		char *tmp = strchr(line, '#');
		if (tmp)
			*tmp = 0;
		if ((tmp = strchr(line, '\n')))
			*tmp = 0;

		// Find the delimiter, if none, ignore this line
		if ((tmp = strchr(line, '=')) == NULL) {
			// fprintf(stderr, "Mangled input on line %zu (ignoring)\n", lineno);
			continue;
		}
		*tmp++ = 0;

		char *key = line;
		char *value = tmp;

		// Strip leading and trailing whitespace
#define TRIM(s)		do {\
		char *start = s;\
		char *end = &start[strlen(start) - 1];\
		while (isspace(*start))\
			start++;\
		s = start;\
		while (isspace(*end) && end > start)\
			*end-- = 0;\
} while (0)
		TRIM(key);
		TRIM(value);
		configure(key, value, FILE_CONFIG, lineno);
	}


	error = false;
cleanup:
	if (inf) {
		fclose(inf);
	}
	return !error;
}


static void daemonize(void)
{
	/* fork: exit if parent, do nothing if child */
	switch ((fork())) {
		case 0:
			break;// We're the child, do nothing
		case -1:
			fprintf(stderr, "Failed to fork(): %m\n");
			exit(EXIT_FAILURE);
		default:
			printf("Daemonized successfully, exiting\n");
			exit(EXIT_SUCCESS);
	}

	/* Open output files and log files, set stdout and stderr to those
	 * files.
	 */
	int outfile = -1, errfile = -1;
	outfile = open(FILE_OUT, O_WRONLY | O_CREAT | O_APPEND, 0666);
	errfile = open(FILE_ERR, O_WRONLY | O_CREAT | O_APPEND, 0666);

	if (outfile < 0 || errfile < 0) {
		fprintf(stderr, "Failed to open [%s:%s] [%i:%i]: %m]\n",
				FILE_OUT, FILE_ERR, outfile, errfile);
		close(outfile);
		close(errfile);
		exit(EXIT_FAILURE);
	}

	dup2(outfile, STDOUT_FILENO);
	dup2(errfile, STDERR_FILENO);
}

/* Tune the buffer size and wakeup rate. These settings cope with roughly
 * 50k opens/sec.
 */
#define PERF_BUFFER_PAGES	64
#define PERF_BUFFER_TIME_MS	10

/* Set the poll timeout when no events occur. This can affect -d accuracy. */
#define PERF_POLL_TIMEOUT_MS	100

#define NSEC_PER_SEC		1000000000ULL

static volatile sig_atomic_t exiting = 0;

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#endif

static struct env {
	bool daemonize;
	bool verbose;
} env = {
	.daemonize = false,
	.verbose = false,
};

const char *argp_program_version = "opensnoopd 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace open family syscalls\n"
"\n"
"USAGE: opensnoopd [-d] [-v] [-I]\n"
"\n"
"EXAMPLES:\n"
"    ./opensnoopd           # log all open() syscalls.\n"
"    ./opensnoopd -d        # Daemonize, then log all open() syscalls.\n"
"    ./opensnoopd -v        # Don't be the soul of wit.\n"
"    ./opensnoopd -I        # Install opensnoopd to the local machine.\n"
"";

static const struct argp_option opts[] = {
	{ "daemon", 'd', NULL, 0, "Daemonize", 0},
	{ "verbose", 'v', NULL, 0, "Verbose", 0},
	{ "install", 'I', NULL, 0, "Install", 0},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	(void)arg;
	switch (key) {

		case 'h':
			argp_usage(state);
			break;

		case 'd':
			daemonize();
			break;

		case 'I':
			if (!(dirs_create())
					|| !(files_create())
					|| !(copy_program())) {
				fprintf(stderr, "Failed to install opensnoopd, aborting\n");
				print_remove_message();
				exit(EXIT_FAILURE);
			}
			printf("Program installed successfully\n");
			printf("Modify the init system files to run /sbin/opensnoopd on bootup\n");
			exit(EXIT_SUCCESS);

		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	switch (signo) {
		case SIGINT:
			printf("Received SIGINT, exiting\n");
			exiting = 1;
		default:
			printf("Received unexpected signal, ignoring\n");
			break;
	}
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	(void)ctx;
	(void)cpu;
	struct event e;

	if (data_sz < sizeof(e)) {
 	 	fprintf(stderr, "Error: packet too small\n");
 	 	return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

#if 1
	if (regexes_exclude(e.fname))
		return;
#endif

	printf("%i:%i:%i:[%s]\n", e.action, e.ret, e.flags, e.fname);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	(void)ctx;
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	program = argv[0];
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct opensnoopd_bpf *obj = NULL;
	int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;


	if (!(config_read())) {
		fprintf(stderr, "Failed to read configuration, aborting\n");
		goto cleanup;
	}

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %m\n");
		return 1;
	}

	obj = opensnoopd_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_oflags = g_oflags;

	/* aarch64 and riscv64 don't have open syscall */
	if (!tracepoint_exists("syscalls", "sys_enter_open")) {
		bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_enter_openat, false);
		bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_exit_openat, false);
	}

	err = opensnoopd_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = opensnoopd_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

#ifdef USE_BLAZESYM
	if (env.callers)
		symbolizer = blazesym_new();
#endif

	/* setup event callbacks */
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %m\n");
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %m\n");
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	opensnoopd_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
#ifdef USE_BLAZESYM
	blazesym_free(symbolizer);
#endif

	regexes_free();
	return err != 0;
}
