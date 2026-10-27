/* Offline equivalence test: the original hostmon consumer against hostmon_agg's
 * per-syscall update and output code, on the same event streams.
 *
 * The original hostmon.c is compiled unchanged into this file (with main()
 * renamed) and receives the events hostmon's BPF programs would send: one raw
 * syscall record per call plus a named record for execve/openat/renameat/
 * unlinkat/connect of 64-bit tasks, in either order. The same calls go through
 * agg_kind() and agg_account(), the code the hostmon_agg BPF program runs, and
 * agg_print_row(). Each scenario is one window; the printed rows must be
 * identical (compared as sorted lines, since hostmon prints in table-slot order
 * and hostmon_agg by PID), and so must the capacity-error counts.
 *
 * Window assignment and multi-threaded ordering depend on timing and are checked
 * live by check_agg.sh instead.
 */
#define main hostmon_original_main
#include "hostmon.c"
#undef main

#include "hostmon_agg.h"
#include "hostmon_agg_logic.h"
#include "hostmon_agg_fmt.h"

#define MAX_PROCS 24

struct sim_proc {
	unsigned int pid;
	int compat;
	char comm[16];
	__u32 last_id;
	struct agg_val agg;
};

static struct sim_proc procs[MAX_PROCS];
static int nprocs;
static unsigned long long rng = 0x9e3779b97f4a7c15ULL;
static unsigned long scenarios, rows_compared, syscalls_fed;

static unsigned int rnd(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (unsigned int)(rng >> 16);
}

static const char *comm_pool[] = {
	"bash", "python3", "a\"b", "x\ny", "cr\rlf", "fifteen_chars15", "nginx", "",
};

static void set_comm(struct sim_proc *p, const char *name)
{
	memset(p->comm, 0, sizeof(p->comm));
	strncpy(p->comm, name, sizeof(p->comm) - 1);
}

static __u32 pick_id(struct sim_proc *p)
{
	static const __u32 hot[] = { 0, 1, 3, 9, 11, 39, 42, 59, 110, 257, 263, 264 };
	unsigned int r = rnd() % 100;

	if (r < 30)
		return p->last_id;
	if (r < 60)
		return hot[rnd() % (sizeof(hot) / sizeof(hot[0]))];
	if (r < 85)
		return rnd() % 1024;
	if (r < 95)
		return rnd() % 2048;
	return (rnd() & 1) ? 0x40000000U + rnd() % 600 : 0xffffffffU;
}

static void feed_original(const struct sim_proc *p, __u32 sid, __u32 kind, __u32 ip, __u16 port)
{
	struct event raw, named;

	memset(&raw, 0, sizeof(raw));
	raw.monotonic_ns = 1000;
	raw.type = EVENT_SYSCALL;
	raw.pid = p->pid;
	memcpy(raw.comm, p->comm, sizeof(raw.comm));
	raw.syscall_id = sid;
	if (kind == AGG_NONE) {
		handle_event(NULL, &raw, sizeof(raw));
		return;
	}
	named = raw;
	named.type = kind; /* AGG_EXEC..AGG_CONNECT == EVENT_EXEC..EVENT_CONNECT */
	named.syscall_id = 0;
	named.addr = ip;
	named.port = htons(port);
	if (rnd() & 1) {
		handle_event(NULL, &raw, sizeof(raw));
		handle_event(NULL, &named, sizeof(named));
	} else {
		handle_event(NULL, &named, sizeof(named));
		handle_event(NULL, &raw, sizeof(raw));
	}
}

/* Which named record hostmon's BPF side emits, written independently of
 * agg_kind(): its tracepoints are syscalls:sys_enter_{execve,openat,renameat,
 * unlinkat,connect}, and syscalls:* events skip 32-bit (compat) calls. */
static unsigned int reference_named_type(__u32 sid, int compat)
{
	if (compat)
		return 0;
	if (sid == 59)
		return EVENT_EXEC;
	if (sid == 257)
		return EVENT_OPEN;
	if (sid == 264)
		return EVENT_RENAME;
	if (sid == 263)
		return EVENT_UNLINK;
	if (sid == 42)
		return EVENT_CONNECT;
	return 0;
}

static void feed(struct sim_proc *p, __u32 sid, __u32 ip, __u16 port)
{
	unsigned int named = reference_named_type(sid, p->compat);
	__u32 kind = agg_kind(sid, p->compat);
	__u64 comm[2];

	/* hostmon reads the address only in handle_connect(); hostmon_agg only when
	 * agg_kind() says connect. */
	feed_original(p, sid, named, named == EVENT_CONNECT ? ip : 0,
		      named == EVENT_CONNECT ? port : 0);
	memcpy(comm, p->comm, sizeof(comm));
	agg_account(&p->agg, sid, kind, kind == AGG_CONNECT ? ip : 0,
		    kind == AGG_CONNECT ? port : 0, comm[0], comm[1]);
	p->last_id = sid;
	syscalls_fed++;
}

static char *capture_original(void)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *mem = open_memstream(&buf, &len), *saved = stdout;

	stdout = mem;
	print_and_reset(0, 0.0, 1.0);
	fflush(stdout);
	stdout = saved;
	fclose(mem);
	return buf;
}

static int cmp_proc(const void *a, const void *b)
{
	const struct sim_proc *x = a, *y = b;

	return x->pid < y->pid ? -1 : x->pid > y->pid;
}

static char *capture_agg(void)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *mem = open_memstream(&buf, &len), *saved = stdout;
	int i;

	qsort(procs, nprocs, sizeof(procs[0]), cmp_proc);
	stdout = mem;
	agg_print_header(0, 0.0, 1.0);
	for (i = 0; i < nprocs; i++)
		agg_print_row(procs[i].pid, &procs[i].agg);
	fflush(stdout);
	stdout = saved;
	fclose(mem);
	return buf;
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Split into lines; the first three ("", window header, column header) must be
 * equal, the rest are compared as sorted sets. */
static int split(char *text, char **lines, int max)
{
	int n = 0;
	char *s = text, *nl;

	while (*s && n < max) {
		nl = strchr(s, '\n');
		if (nl)
			*nl = 0;
		lines[n++] = s;
		if (!nl)
			break;
		s = nl + 1;
	}
	return n;
}

static void finish_scenario(const char *label)
{
	static char *a[MAX_PROCS + 8], *b[MAX_PROCS + 8];
	char *orig = capture_original(), *agg = capture_agg();
	char *orig_copy = strdup(orig), *agg_copy = strdup(agg);
	unsigned long agg_capacity = 0;
	int na = split(orig_copy, a, MAX_PROCS + 8), nb = split(agg_copy, b, MAX_PROCS + 8), i;

	for (i = 0; i < nprocs; i++)
		agg_capacity += procs[i].agg.cap_errors;
	if (na == nb && na >= 3) {
		qsort(a + 3, na - 3, sizeof(char *), cmp_str);
		qsort(b + 3, nb - 3, sizeof(char *), cmp_str);
	}
	for (i = 0; na == nb && i < na; i++) {
		if (strcmp(a[i], b[i]))
			break;
	}
	if (na != nb || i < na || capacity_errors != agg_capacity) {
		fprintf(stderr, "MISMATCH in scenario %lu (%s): capacity %lu vs %lu\n--- hostmon\n%s--- hostmon_agg\n%s",
			scenarios, label, capacity_errors, agg_capacity, orig, agg);
		exit(1);
	}
	rows_compared += na - 3;
	scenarios++;
	free(orig);
	free(agg);
	free(orig_copy);
	free(agg_copy);
}

static void start_scenario(int n, int compat_every)
{
	int i;

	memset(table, 0, sizeof(table));
	capacity_errors = 0;
	late_events = 0;
	collector_start = 0.0;
	window_sec = 1e12;
	window_id = 0;
	self_pid = 1;
	nprocs = n;
	for (i = 0; i < nprocs; i++) {
		memset(&procs[i], 0, sizeof(procs[i]));
		procs[i].pid = 1000 + 7 * (unsigned int)i + rnd() % 5;
		procs[i].compat = compat_every && rnd() % compat_every == 0;
		set_comm(&procs[i], comm_pool[rnd() % (sizeof(comm_pool) / sizeof(comm_pool[0]))]);
		procs[i].last_id = rnd() % 400;
	}
}

static __u32 pool_ip(void)
{
	/* 0 (ignored by hostmon) plus 80 addresses, enough to overflow the 64-entry set. */
	unsigned int k = rnd() % 81;

	return k ? htonl(0x7f000000U + k) : 0;
}

static __u16 pool_port(void)
{
	unsigned int k = rnd() % 81;

	return k ? (__u16)(1000 + k) : 0;
}

int main(void)
{
	int s, i, k;

	/* Fixed cases. */
	start_scenario(1, 0);
	finish_scenario("no events");

	start_scenario(1, 0);
	feed(&procs[0], 39, 0, 0);
	finish_scenario("one syscall");

	start_scenario(2, 0);
	for (k = 0; k < 200000; k++)
		feed(&procs[0], 110, 0, 0);
	for (k = 0; k < 5000; k++)
		feed(&procs[1], k % 3 ? 0 : 1, 0, 0);
	finish_scenario("long runs");

	start_scenario(1, 0);
	for (k = 0; k < 300; k++)
		feed(&procs[0], 1024 + (unsigned int)k, 0, 0);
	finish_scenario("ids >= 1024 only");

	start_scenario(2, 0);
	procs[1].compat = 1;
	for (k = 0; k < 150; k++) {
		feed(&procs[0], 42, htonl(0x0a000000U + k), (__u16)(2000 + k));
		feed(&procs[1], 42, htonl(0x0a000000U + k), (__u16)(2000 + k));
		feed(&procs[0], 257, 0, 0);
		feed(&procs[1], 257, 0, 0);
	}
	finish_scenario("connect set overflow, compat named ids");

	start_scenario(1, 0);
	for (k = 0; k < 120; k++) {
		set_comm(&procs[0], comm_pool[k % 8]);
		feed(&procs[0], (__u32)(k % 7), 0, 0);
	}
	finish_scenario("comm changes, including empty");

	/* Random cases. */
	for (s = 0; s < 3000; s++) {
		int nev;

		start_scenario(1 + (int)(rnd() % MAX_PROCS), 4);
		nev = (int)(rnd() % 4000);
		for (i = 0; i < nev; i++) {
			struct sim_proc *p = &procs[rnd() % nprocs];

			if (rnd() % 100 == 0)
				set_comm(p, comm_pool[rnd() % (sizeof(comm_pool) / sizeof(comm_pool[0]))]);
			feed(p, pick_id(p), pool_ip(), pool_port());
		}
		finish_scenario("random");
	}

	printf("PASS: %lu scenarios, %lu rows identical, %lu syscalls\n", scenarios, rows_compared, syscalls_fed);
	return 0;
}
