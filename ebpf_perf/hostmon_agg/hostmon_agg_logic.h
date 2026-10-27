/* Per-syscall update, compiled into the BPF program and into the offline
 * equivalence test (test_agg_equiv.c). It mirrors hostmon.c: record_syscall(),
 * add_unique_ip(), add_unique_port() and the per-type counters in handle_event().
 *
 * In the BPF program agg_account() runs with the entry's spin lock held, so it
 * must not call helpers or other BPF functions; everything here is inlined.
 * Array indexes are masked after their bounds check so the verifier can prove
 * them in range however the compiler orders the instructions.
 */
#ifndef __HOSTMON_AGG_LOGIC_H
#define __HOSTMON_AGG_LOGIC_H

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define AGG_TS_COMPAT 0x0002 /* x86 thread_info.status: 32-bit syscall in progress */

/* hostmon counts these from the syscalls:sys_enter_<name> tracepoints, which do
 * not fire for 32-bit (compat) system calls, so compat calls get AGG_NONE. */
static __always_inline __u32 agg_kind(__u32 sid, int compat)
{
	__u32 kind;

	switch (sid) {
	case 59:  kind = AGG_EXEC; break;    /* execve */
	case 257: kind = AGG_OPEN; break;    /* openat */
	case 264: kind = AGG_RENAME; break;  /* renameat */
	case 263: kind = AGG_UNLINK; break;  /* unlinkat */
	case 42:  kind = AGG_CONNECT; break; /* connect */
	default:  kind = AGG_NONE; break;
	}
	return compat ? AGG_NONE : kind;
}

static __always_inline void agg_add_ip(struct agg_val *v, __u32 ip)
{
	__u32 i, n = v->nips;

	if (!ip)
		return;
	for (i = 0; i < AGG_MAX_UNIQUE; i++) {
		if (i >= n)
			break;
		if (v->ips[i] == ip)
			return;
	}
	if (n < AGG_MAX_UNIQUE) {
		v->ips[n & (AGG_MAX_UNIQUE - 1)] = ip;
		v->nips = n + 1;
	} else {
		v->cap_errors++;
	}
}

static __always_inline void agg_add_port(struct agg_val *v, __u16 port)
{
	__u32 i, n = v->nports;

	if (!port)
		return;
	for (i = 0; i < AGG_MAX_UNIQUE; i++) {
		if (i >= n)
			break;
		if (v->ports[i] == port)
			return;
	}
	if (n < AGG_MAX_UNIQUE) {
		v->ports[n & (AGG_MAX_UNIQUE - 1)] = port;
		v->nports = n + 1;
	} else {
		v->cap_errors++;
	}
}

static __always_inline void agg_account(struct agg_val *v, __u32 sid, __u32 kind,
					__u32 ip, __u16 port, __u64 comm0, __u64 comm1)
{
	__u32 n;

	/* hostmon keeps the previous comm when an event's comm is empty (first byte
	 * is the low byte on little-endian x86). */
	if (comm0 & 0xff) {
		v->comm[0] = comm0;
		v->comm[1] = comm1;
	}

	switch (kind) {
	case AGG_EXEC:
		v->exec++;
		break;
	case AGG_OPEN:
		v->open++;
		break;
	case AGG_RENAME:
		v->rename++;
		break;
	case AGG_UNLINK:
		v->unlink++;
		break;
	case AGG_CONNECT:
		v->connect++;
		agg_add_ip(v, ip);
		agg_add_port(v, port);
		break;
	default:
		break;
	}

	/* Runs and transitions, as record_syscall(); a new entry starts each window. */
	if (v->total == 0) {
		v->last_syscall = sid;
		v->cur_run = 1;
	} else if (v->last_syscall == sid) {
		v->cur_run++;
	} else {
		v->transitions++;
		if (v->cur_run > v->max_run)
			v->max_run = v->cur_run;
		v->last_syscall = sid;
		v->cur_run = 1;
	}
	v->total++;

	if (sid < AGG_MAX_SYSCALL_ID) {
		__u32 *slot = &v->hist[sid & (AGG_MAX_SYSCALL_ID - 1)];

		if (*slot != 0xffffffffU)
			(*slot)++;
		else
			v->cap_errors++; /* would need > 4.29e9 calls of one id in one window */
	} else {
		v->cap_errors++;
	}

	n = v->first_cnt;
	if (n < AGG_FIRST_N) {
		v->first_ids[n & (AGG_FIRST_SLOTS - 1)] = sid;
		v->first_cnt = n + 1;
	}
}

#endif
