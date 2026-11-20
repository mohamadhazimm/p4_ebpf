// SPDX-License-Identifier: GPL-2.0
/* hostmon_agg kernel side: one BTF raw tracepoint on sys_enter that updates the
 * (process, window) entry of the calling process. Compared with hostmon this
 * removes the perf trace-buffer copy of the classic tracepoint, the five
 * syscalls:sys_enter_<name> programs, the 568-byte ring-buffer record and its
 * path copies, and the user-space per-event work. The features hostmon derives
 * from those events are computed here instead (see hostmon_agg_logic.h).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "hostmon_agg.h"
#include "hostmon_agg_logic.h"

#ifndef AF_INET
#define AF_INET 2
#endif

char LICENSE[] SEC("license") = "GPL";

/* Set before load. */
const volatile __u64 workload_cgroup_id = 0;
const volatile __u64 window_ns = 1000000000ULL;
const volatile __u32 self_tgid = 0;

/* Set by user space after load (mmapped .bss). */
volatile __u64 origin_ns;      /* shared start time; 0 = not started yet */
volatile __u32 closed_windows; /* windows below this index have been printed */

/* Counted per hostmon event: a named syscall (execve, openat, ...) is two events,
 * the raw one and the named one, as in hostmon's ring buffer. */
__u64 late_events;    /* arrived for a window that was already printed */
__u64 no_slot_events; /* no map entry could be created (hostmon: capacity error) */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, AGG_MAX_ENTRIES);
	__type(key, struct agg_key);
	__type(value, struct agg_val);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct agg_zero);
} zero_val SEC(".maps");

/* Destination of connect(), read like hostmon's handle_connect(). */
static __always_inline void read_ipv4(struct pt_regs *regs, __u32 *ip, __u16 *port)
{
	const struct sockaddr *uservaddr = (const struct sockaddr *)regs->si;
	__u16 family = 0;

	if (!uservaddr)
		return;
	bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);
	if (family == AF_INET) {
		struct sockaddr_in sa4 = {};

		bpf_probe_read_user(&sa4, sizeof(sa4), uservaddr);
		*ip = sa4.sin_addr.s_addr;
		*port = bpf_ntohs(sa4.sin_port);
	}
}

SEC("tp_btf/sys_enter")
int BPF_PROG(handle_sys_enter, struct pt_regs *regs, long id)
{
	struct task_struct *task;
	const __u64 *comm;
	struct agg_key key;
	struct agg_val *v;
	__u64 now, origin, window, events, comm0, comm1;
	__u32 sid = (__u32)id, kind, ip = 0, zero = 0;
	__u16 port = 0;
	int late = 0;

	if (!workload_cgroup_id || bpf_get_current_cgroup_id() != workload_cgroup_id)
		return 0;
	origin = origin_ns;
	if (!origin)
		return 0;
	now = bpf_ktime_get_ns();
	if (now < origin)
		return 0;
	key.pid = bpf_get_current_pid_tgid() >> 32;
	if (key.pid == self_tgid)
		return 0;

	task = bpf_get_current_task_btf();
	kind = agg_kind(sid, task->thread_info.status & AGG_TS_COMPAT);
	events = kind == AGG_NONE ? 1 : 2;

	window = (now - origin) / window_ns;
	if (window >= 0xffffffffULL) {
		__sync_fetch_and_add(&no_slot_events, events);
		return 0;
	}
	key.window = (__u32)window;
	if (key.window < closed_windows) {
		__sync_fetch_and_add(&late_events, events);
		return 0;
	}
	if (kind == AGG_CONNECT)
		read_ipv4(regs, &ip, &port);

	v = bpf_map_lookup_elem(&stats, &key);
	if (!v) {
		struct agg_zero *z = bpf_map_lookup_elem(&zero_val, &zero);

		if (z)
			bpf_map_update_elem(&stats, &key, z, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&stats, &key);
		if (!v) {
			__sync_fetch_and_add(&no_slot_events, events);
			return 0;
		}
	}

	comm = (const __u64 *)task->comm;
	comm0 = comm[0];
	comm1 = comm[1];
	bpf_spin_lock(&v->lock);
	/* Recheck under the lock: user space marks a window closed before it reads
	 * the window's entries with BPF_F_LOCK, so an update is either in what it
	 * read or counted here as late, never lost. */
	if (key.window < closed_windows)
		late = 1;
	else
		agg_account(v, sid, kind, ip, port, comm0, comm1);
	bpf_spin_unlock(&v->lock);
	if (late)
		__sync_fetch_and_add(&late_events, events);
	return 0;
}
