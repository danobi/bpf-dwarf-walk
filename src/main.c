#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>

#include "bpf/dwarf_walk.h"
#include "dwarf_walk.skel.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static struct env {
	bool verbose;
	unsigned long stack_to_copy;
} env;

const char *argp_program_version = "dwarf_walk 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF DWARF-based stack walking demo.\n"
"\n"
"USAGE: ./dwarf_walk [-s <stack_to_copy>] [-v] [-h]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "stack-to-copy", 's', "BYTES", 0, "Bytes of stack to copy (default: 8K)" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 's':
		errno = 0;
		env.stack_to_copy = strtol(arg, NULL, 10);
		if (errno || env.stack_to_copy <= 0) {
			fprintf(stderr, "Invalid size: %s\n", arg);
			argp_usage(state);
		}

		if (env.stack_to_copy > MAX_STACK_SIZE) {
			fprintf(stderr, "Size too big, max is: %d\n", MAX_STACK_SIZE);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}


int main(int argc, char **argv)
{
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *perf = NULL;
	struct dwarf_walk_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = dwarf_walk_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	skel->rodata->stack_to_copy = env.stack_to_copy;

	err = dwarf_walk_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = dwarf_walk_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}


	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	perf = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
				&pb_opts);
	err = libbpf_get_error(perf);
	if (err) {
		perf = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	while (1) {
		if ((err = perf_buffer__poll(perf, PERF_POLL_TIMEOUT_MS)) < 0)
			break;

		if (exiting)
			goto cleanup;
	}
	printf("error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(perf);
	dwarf_walk_bpf__destroy(skel);
	return err != 0;
}
