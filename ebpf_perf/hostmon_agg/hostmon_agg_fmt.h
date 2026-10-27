/* User-space output of hostmon_agg, shared with the offline equivalence test.
 * Prints exactly what hostmon.c's print_and_reset() prints for one process
 * (same columns, formats and quoting), computed from one struct agg_val.
 */
#ifndef __HOSTMON_AGG_FMT_H
#define __HOSTMON_AGG_FMT_H

#include <math.h>
#include <stdio.h>
#include <string.h>

#include "hostmon_agg.h"

/* hostmon.c count_unique_prefix(). */
static int agg_count_unique_prefix(const __u32 *arr, int n)
{
	int i, j, unique = 0;

	for (i = 0; i < n; i++) {
		int seen = 0;

		for (j = 0; j < i; j++) {
			if (arr[j] == arr[i]) {
				seen = 1;
				break;
			}
		}
		if (!seen)
			unique++;
	}
	return unique;
}

static void agg_print_header(unsigned long window_id, double start_sec, double end_sec)
{
	printf("\n==== HOST WINDOW %lu START=%.6f END=%.6f DUR=%.6f ====\n",
	       window_id, start_sec, end_sec, end_sec - start_sec);
	printf("COMM,PID,EXEC,OPEN,REN,DEL,CONN,UNIQIP,UNIQPRT,"
	       "TOTAL_SYSCALLS,UNIQUE_SYSCALLS,ENTROPY,TOP_SYSCALL_FREQ,"
	       "AVG_RUN_LENGTH,MAX_RUN_LENGTH,TRANSITION_COUNT,"
	       "RARE_SYSCALL_RATIO,FIRST50_UNIQUE,FIRST100_UNIQUE\n");
}

static int agg_row_active(const struct agg_val *v)
{
	return v->exec || v->open || v->rename || v->unlink || v->connect || v->total;
}

static void agg_print_row(__u32 pid, const struct agg_val *v)
{
	unsigned long max_freq = 0, singleton_count = 0, unique_syscalls = 0;
	unsigned long total = v->total, run_count, effective_max_run;
	double entropy = 0.0, top_syscall_freq = 0.0, avg_run_length = 0.0, rare_syscall_ratio = 0.0;
	int first50_n, first100_n, first50_unique, first100_unique, s;
	char comm[16];

	if (!agg_row_active(v))
		return;

	for (s = 0; s < AGG_MAX_SYSCALL_ID; s++) {
		if (v->hist[s] > 0)
			unique_syscalls++;
		if (v->hist[s] > 0 && total > 0) {
			double p = (double)v->hist[s] / (double)total;

			entropy -= p * (log(p) / log(2.0));
			if (v->hist[s] > max_freq)
				max_freq = v->hist[s];
			if (v->hist[s] == 1)
				singleton_count++;
		}
	}

	effective_max_run = v->max_run;
	if (v->cur_run > effective_max_run)
		effective_max_run = v->cur_run;
	/* Every syscall belongs to one run, so hostmon's run_length_sum_closed plus
	 * the open run is the total, and run_count is the transitions plus one. */
	run_count = total ? v->transitions + 1 : 0;

	if (total > 0) {
		top_syscall_freq = (double)max_freq / (double)total;
		rare_syscall_ratio = (double)singleton_count / (double)total;
	}
	if (run_count > 0)
		avg_run_length = (double)total / (double)run_count;

	first50_n = v->first_cnt < 50 ? (int)v->first_cnt : 50;
	first100_n = v->first_cnt < 100 ? (int)v->first_cnt : 100;
	first50_unique = agg_count_unique_prefix(v->first_ids, first50_n);
	first100_unique = agg_count_unique_prefix(v->first_ids, first100_n);

	/* hostmon keeps at most 15 characters (strncpy into a zeroed 16-byte field). */
	memcpy(comm, v->comm, sizeof(comm));
	comm[sizeof(comm) - 1] = 0;

	putchar('"');
	for (const char *character = comm; *character; character++) {
		if (*character == '"')
			putchar('"');
		putchar(*character == '\n' || *character == '\r' ? '?' : *character);
	}
	printf("\",%u,%lu,%lu,%lu,%lu,%lu,%d,%d,"
	       "%lu,%lu,%.6f,%.6f,%.6f,%lu,%lu,%.6f,%d,%d\n",
	       pid,
	       (unsigned long)v->exec,
	       (unsigned long)v->open,
	       (unsigned long)v->rename,
	       (unsigned long)v->unlink,
	       (unsigned long)v->connect,
	       (int)v->nips,
	       (int)v->nports,
	       total,
	       unique_syscalls,
	       entropy,
	       top_syscall_freq,
	       avg_run_length,
	       effective_max_run,
	       (unsigned long)v->transitions,
	       rare_syscall_ratio,
	       first50_unique,
	       first100_unique);
}

#endif
