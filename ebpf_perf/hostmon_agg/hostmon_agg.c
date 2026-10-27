// SPDX-License-Identifier: GPL-2.0
/* hostmon_agg: drop-in replacement for hostmon with in-kernel aggregation.
 *
 * Same command line, start-time protocol and output as hostmon:
 *   hostmon_agg WINDOW_SEC DEDICATED_CGROUP_V2_PATH
 * prints HOSTMON_READY,<cgroup id>, reads the shared monotonic start time (s) on
 * stdin, prints one "==== HOST WINDOW" block per window with the same CSV columns,
 * and on SIGINT/SIGTERM prints the last partial window and HOSTMON_HEALTH.
 *
 * The kernel side keeps one entry per (process, window). This program sleeps until
 * a window has ended (plus a short grace period), marks it closed, reads its
 * entries, prints them and deletes them. It does no per-event work, so its cost
 * does not grow with the syscall rate. Differences from hostmon:
 *  - rows within a window are sorted by PID (hostmon prints them in its table order);
 *  - no 128-process limit (AGG_MAX_ENTRIES live entries);
 *  - an event is timestamped when its syscall enters the kernel, not when the
 *    ring-buffer record is submitted, which can move an event that lands within
 *    a few hundred ns of a window boundary to the other side;
 *  - "lost" is always 0 (there is no ring buffer); events that find no free map
 *    entry are reported as capacity errors, like hostmon's full process table.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "hostmon_agg.h"
#include "hostmon_agg_fmt.h"
#include "hostmon_agg.skel.h"

#define GRACE_NS 50000000ULL /* read a window 50 ms after it ends */

struct row {
	__u32 pid;
	struct agg_val val;
};

struct totals {
	unsigned long capacity_errors;
	unsigned long late_events;
	int failed;
};

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static double now_monotonic_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + ((double)ts.tv_nsec / 1e9);
}

static __u64 now_monotonic_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static int cmp_row(const void *a, const void *b)
{
	const struct row *x = a, *y = b;

	return x->pid < y->pid ? -1 : x->pid > y->pid;
}

static unsigned long entry_events(const struct agg_val *v)
{
	return v->total + v->exec + v->open + v->rename + v->unlink + v->connect;
}

/* Print window w from the map and delete what was read. With final != 0 every
 * other entry left in the map is also removed and counted as late. */
static void flush_window(int fd, unsigned long w, double start_sec, double end_sec,
			 int final, struct totals *t)
{
	struct agg_key key, next, *keys = NULL;
	struct row *rows;
	size_t nkeys = 0, cap = 0, nrows = 0, i;
	int err;

	err = bpf_map_get_next_key(fd, NULL, &next);
	while (!err) {
		if (final || next.window <= w) {
			if (nkeys == cap) {
				struct agg_key *grown;

				cap = cap ? 2 * cap : 256;
				grown = realloc(keys, cap * sizeof(*keys));
				if (!grown) {
					t->failed = 1;
					break;
				}
				keys = grown;
			}
			keys[nkeys++] = next;
		}
		key = next;
		err = bpf_map_get_next_key(fd, &key, &next);
	}
	if (err && err != -ENOENT)
		t->failed = 1;

	rows = calloc(nkeys ? nkeys : 1, sizeof(*rows));
	if (!rows) {
		t->failed = 1;
		nkeys = 0;
	}
	for (i = 0; i < nkeys; i++) {
		struct agg_val *v = &rows[nrows].val;

		err = bpf_map_lookup_elem_flags(fd, &keys[i], v, BPF_F_LOCK);
		if (err) {
			if (err != -ENOENT)
				t->failed = 1;
			continue;
		}
		err = bpf_map_delete_elem(fd, &keys[i]);
		if (err && err != -ENOENT)
			t->failed = 1;
		if (keys[i].window != w) {
			/* Created after its window was read, or (final) after the stop. */
			t->late_events += entry_events(v);
			continue;
		}
		rows[nrows++].pid = keys[i].pid;
	}
	qsort(rows, nrows, sizeof(*rows), cmp_row);

	agg_print_header(w, start_sec, end_sec);
	for (i = 0; i < nrows; i++) {
		agg_print_row(rows[i].pid, &rows[i].val);
		t->capacity_errors += rows[i].val.cap_errors;
	}
	fflush(stdout);
	free(rows);
	free(keys);
}

static void close_windows(struct hostmon_agg_bpf *skel, __u32 closed)
{
	__atomic_store_n(&skel->bss->closed_windows, closed, __ATOMIC_SEQ_CST);
}

int main(int argc, char **argv)
{
	struct hostmon_agg_bpf *skel;
	struct stat cgroup_stat;
	struct sigaction sa;
	struct totals t = {0};
	double window_sec, collector_start, now, relative;
	unsigned long long lost = 0;
	unsigned long w = 0;
	__u64 window_ns, origin_ns;
	int fd;

	if (argc != 3 || stat(argv[2], &cgroup_stat)) {
		fprintf(stderr, "Usage: hostmon_agg WINDOW_SEC DEDICATED_CGROUP_V2_PATH\n");
		return 1;
	}
	window_sec = atof(argv[1]);
	if (!isfinite(window_sec) || window_sec <= 0.0) {
		fprintf(stderr, "Invalid window_sec: %s\n", argv[1]);
		return 1;
	}
	window_ns = (__u64)llround(window_sec * 1e9);
	if (window_ns < 1000) {
		fprintf(stderr, "window_sec must be at least 1e-6: %s\n", argv[1]);
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal; /* no SA_RESTART: the sleep returns on a signal */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	skel = hostmon_agg_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open hostmon_agg\n");
		return 1;
	}
	skel->rodata->workload_cgroup_id = cgroup_stat.st_ino;
	skel->rodata->window_ns = window_ns;
	skel->rodata->self_tgid = (__u32)getpid();
	if (hostmon_agg_bpf__load(skel)) {
		fprintf(stderr, "Failed to load scoped hostmon_agg\n");
		hostmon_agg_bpf__destroy(skel);
		return 1;
	}
	if (hostmon_agg_bpf__attach(skel)) {
		fprintf(stderr, "Failed to attach hostmon_agg\n");
		hostmon_agg_bpf__destroy(skel);
		return 1;
	}
	fd = bpf_map__fd(skel->maps.stats);

	printf("HOSTMON_READY,%llu\n", (unsigned long long)cgroup_stat.st_ino);
	fflush(stdout);

	if (scanf("%lf", &collector_start) != 1 || !isfinite(collector_start) ||
	    collector_start <= now_monotonic_sec()) {
		fprintf(stderr, "Expected a future shared monotonic start on stdin\n");
		hostmon_agg_bpf__destroy(skel);
		return 1;
	}
	origin_ns = (__u64)llround(collector_start * 1e9);
	__atomic_store_n(&skel->bss->origin_ns, origin_ns, __ATOMIC_SEQ_CST);

	while (!stop) {
		__u64 deadline = origin_ns + (w + 1) * window_ns + GRACE_NS;

		if (now_monotonic_ns() < deadline) {
			struct timespec ts = {
				.tv_sec = (time_t)(deadline / 1000000000ULL),
				.tv_nsec = (long)(deadline % 1000000000ULL),
			};

			clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
			continue;
		}
		close_windows(skel, (__u32)(w + 1));
		flush_window(fd, w, w * window_sec, (w + 1) * window_sec, 0, &t);
		w++;
	}

	/* Like hostmon on exit: print every window that has ended, then the
	 * current partial window. Nothing is accepted after this point. */
	now = now_monotonic_sec();
	relative = now - collector_start;
	while (relative >= (w + 1) * window_sec) {
		close_windows(skel, (__u32)(w + 1));
		flush_window(fd, w, w * window_sec, (w + 1) * window_sec, 0, &t);
		w++;
	}
	close_windows(skel, 0xffffffffU);
	if (relative > w * window_sec) {
		flush_window(fd, w, w * window_sec, relative, 1, &t);
	} else {
		/* No partial window to print; anything left arrived after the stop. */
		struct agg_key key;
		struct agg_val v;
		int err;

		while (!bpf_map_get_next_key(fd, NULL, &key)) {
			if (!bpf_map_lookup_elem_flags(fd, &key, &v, BPF_F_LOCK))
				t.late_events += entry_events(&v);
			err = bpf_map_delete_elem(fd, &key);
			if (err && err != -ENOENT) {
				t.failed = 1;
				break;
			}
		}
	}
	t.capacity_errors += __atomic_load_n(&skel->bss->no_slot_events, __ATOMIC_SEQ_CST);
	t.late_events += __atomic_load_n(&skel->bss->late_events, __ATOMIC_SEQ_CST);

	printf("HOSTMON_HEALTH,%llu,%lu,%lu,%d\n", lost, t.capacity_errors, t.late_events, t.failed);
	fflush(stdout);

	hostmon_agg_bpf__destroy(skel);
	return t.failed || lost || t.capacity_errors || t.late_events ? 1 : 0;
}
