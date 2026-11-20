/* Shared between sockowner.bpf.c (kernel side) and sockowner.c (user space).
 *
 * sockowner records which socket, process and cgroup each TCP/UDP flow belongs to,
 * at the point where the host's packets leave or reach a local socket. A flow is
 * keyed by its 5-tuple, the key the switch's flow table uses, so the collector can
 * join switch flows to processes per flow instead of per time window.
 */
#ifndef __SOCKOWNER_H
#define __SOCKOWNER_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define SO_MAX_FLOWS (1 << 18)   /* 5-tuples remembered for de-duplication (LRU) */

enum so_kind {
	SO_SOCK = 1,    /* a socket was created (process context: owner known) */
	SO_RELEASE = 2, /* a socket was released */
	SO_FLOW = 3,    /* first packet of a 5-tuple on a socket (or the 5-tuple moved socket) */
};

/* Direction-independent 5-tuple: the (address, port) pair that compares lower first. */
struct so_flow_key {
	__u32 addr_lo;  /* network byte order */
	__u32 addr_hi;
	__u16 port_lo;  /* host byte order */
	__u16 port_hi;
	__u8 proto;
	__u8 pad[3];
};

struct so_event {
	__u64 ts_ns;      /* bpf_ktime_get_ns(): CLOCK_MONOTONIC */
	__u64 cookie;     /* socket cookie (0: packet without a socket) */
	__u64 cgroup_id;  /* FLOW: cgroup v2 id of the socket; SOCK: of the creating task */
	__u32 tgid;       /* SOCK: creating process */
	__u32 tid;        /* SOCK: creating thread */
	__u32 saddr;      /* FLOW: the packet's own addresses, network byte order */
	__u32 daddr;
	__u16 sport;      /* FLOW: host byte order */
	__u16 dport;
	__u8 kind;        /* enum so_kind */
	__u8 proto;       /* FLOW: IPPROTO_TCP/UDP; SOCK: socket protocol */
	__u8 dir;         /* FLOW: 0 egress, 1 ingress; SOCK: socket type */
	__u8 family;      /* SOCK: address family */
	char comm[16];    /* SOCK/REL: comm of the calling task */
};

#endif
