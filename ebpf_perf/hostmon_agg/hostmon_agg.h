/* Shared between hostmon_agg.bpf.c (kernel side) and hostmon_agg.c (user space).
 *
 * hostmon_agg computes the same per-window, per-process features as hostmon, but
 * keeps the per-process state in a BPF hash map keyed by (process, window)
 * instead of sending every system call to user space through a ring buffer.
 * Sizes match the constants in libbpf-bootstrap/examples/c/hostmon.c.
 */
#ifndef __HOSTMON_AGG_H
#define __HOSTMON_AGG_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#include <linux/bpf.h>
#endif

#define AGG_MAX_SYSCALL_ID 1024   /* hostmon.c MAX_SYSCALL_ID (power of two) */
#define AGG_FIRST_N        100    /* hostmon.c FIRST_N_STORE */
#define AGG_FIRST_SLOTS    128    /* storage for the first ids, power of two >= AGG_FIRST_N */
#define AGG_MAX_UNIQUE     64     /* hostmon.c MAX_UNIQUE (power of two) */
#define AGG_MAX_ENTRIES    65536  /* live (process, window) entries */

/* Syscalls hostmon also counts by name (from syscalls:sys_enter_<name>). */
enum {
	AGG_NONE = 0,
	AGG_EXEC,
	AGG_OPEN,
	AGG_RENAME,
	AGG_UNLINK,
	AGG_CONNECT,
};

struct agg_key {
	__u32 pid;    /* thread-group id, as hostmon's PID column */
	__u32 window; /* (event time - start) / window length */
};

struct agg_val {
	struct bpf_spin_lock lock;  /* orders the syscalls of a multi-threaded process */
	__u32 last_syscall;
	__u64 total;                /* TOTAL_SYSCALLS */
	__u64 transitions;          /* TRANSITION_COUNT */
	__u64 cur_run;              /* length of the run still open */
	__u64 max_run;              /* longest closed run */
	__u64 exec;
	__u64 open;
	__u64 rename;
	__u64 unlink;
	__u64 connect;
	__u64 cap_errors;           /* hostmon capacity errors: ids >= 1024, full IP/port sets */
	__u32 first_cnt;
	__u32 nips;
	__u32 nports;
	__u32 pad;
	__u64 comm[2];              /* comm of the thread that made the last syscall */
	__u32 ips[AGG_MAX_UNIQUE];  /* unique IPv4 connect destinations, network order */
	__u16 ports[AGG_MAX_UNIQUE];/* unique connect ports, host order */
	__u32 first_ids[AGG_FIRST_SLOTS];
	__u32 hist[AGG_MAX_SYSCALL_ID];
};

/* Same size as struct agg_val but without the lock, used as the zero template for
 * new entries (the verifier rejects helper access to a value that holds a lock). */
struct agg_zero {
	__u8 bytes[sizeof(struct agg_val)];
};

#endif
