// SPDX-License-Identifier: GPL-2.0
/* sockowner kernel side. Four cgroup programs, attached to one cgroup v2 (the root
 * for the whole host, or a workload's cgroup):
 *  - cgroup_skb/egress and cgroup_skb/ingress see every IPv4 packet that a socket
 *    of that cgroup sends or receives (TCP, UDP and raw sockets alike). The first
 *    packet of each 5-tuple on a socket emits a FLOW event with the socket cookie
 *    and the socket's cgroup. Later packets of the same 5-tuple on the same socket
 *    cost one hash lookup and emit nothing.
 *  - cgroup/sock_create runs in the creating process's context and emits a SOCK
 *    event (cookie -> process and thread); cgroup/sock_release emits REL.
 * Accepted TCP sockets are created by the kernel, not by socket(): they have no
 * SOCK event, but their FLOW events carry the listener's cgroup (inherited).
 * Inbound copies delivered to raw sockets are ignored (see so_ingress).
 * Packets the kernel sends without a full socket (RSTs for closed ports, ICMP,
 * TIME_WAIT replies) are not seen; they belong to no local process.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "sockowner.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#define SO_IPPROTO_TCP 6
#define SO_IPPROTO_UDP 17
#define SO_IP_OFFMASK 0x1fff
#define SO_SOCK_RAW 3

char LICENSE[] SEC("license") = "GPL";

/* Set before load. */
const volatile __u32 self_tgid = 0;

/* Read by user space at exit (mmapped .bss). */
__u64 ringbuf_drops;   /* events not delivered: ring buffer full */
__u64 flow_map_errors; /* 5-tuples that could not be remembered */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SO_MAX_FLOWS);
	__type(key, struct so_flow_key);
	__type(value, __u64); /* cookie of the socket last seen with this 5-tuple */
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 << 20);
} events SEC(".maps");

static __always_inline int on_packet(struct __sk_buff *skb, __u8 dir)
{
	struct so_flow_key key = {};
	struct so_event *e;
	struct iphdr iph;
	__be16 ports[2];
	__u64 cookie, *seen;
	__u32 l4;
	__u16 sport, dport;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return 1;
	if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)))
		return 1;
	if (iph.protocol != SO_IPPROTO_TCP && iph.protocol != SO_IPPROTO_UDP)
		return 1;
	if (iph.frag_off & bpf_htons(SO_IP_OFFMASK))
		return 1; /* later fragment: no ports */
	l4 = (__u32)iph.ihl * 4;
	if (l4 < sizeof(iph) || bpf_skb_load_bytes(skb, l4, ports, sizeof(ports)))
		return 1;
	sport = bpf_ntohs(ports[0]);
	dport = bpf_ntohs(ports[1]);

	key.proto = iph.protocol;
	if (iph.saddr < iph.daddr || (iph.saddr == iph.daddr && sport <= dport)) {
		key.addr_lo = iph.saddr; key.port_lo = sport;
		key.addr_hi = iph.daddr; key.port_hi = dport;
	} else {
		key.addr_lo = iph.daddr; key.port_lo = dport;
		key.addr_hi = iph.saddr; key.port_hi = sport;
	}
	cookie = bpf_get_socket_cookie(skb);
	seen = bpf_map_lookup_elem(&flows, &key);
	if (seen && *seen == cookie)
		return 1;
	if (bpf_map_update_elem(&flows, &key, &cookie, BPF_ANY))
		__sync_fetch_and_add(&flow_map_errors, 1);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&ringbuf_drops, 1);
		return 1;
	}
	e->ts_ns = bpf_ktime_get_ns();
	e->cookie = cookie;
	e->cgroup_id = bpf_skb_cgroup_id(skb);
	e->tgid = 0;
	e->tid = 0;
	e->saddr = iph.saddr;
	e->daddr = iph.daddr;
	e->sport = sport;
	e->dport = dport;
	e->kind = SO_FLOW;
	e->proto = iph.protocol;
	e->dir = dir;
	e->family = 2;
	__builtin_memset(e->comm, 0, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 1;
}

SEC("cgroup_skb/egress")
int so_egress(struct __sk_buff *skb)
{
	return on_packet(skb, 0);
}

SEC("cgroup_skb/ingress")
int so_ingress(struct __sk_buff *skb)
{
	struct bpf_sock *sk = skb->sk;

	/* A raw socket receives a copy of every inbound packet of its protocol: those
	 * copies say nothing about who owns the flow, so only the socket the packet
	 * was meant for counts. (Raw sockets' own outbound packets are kept.) */
	if (sk) {
		sk = bpf_sk_fullsock(sk);
		if (sk && sk->type == SO_SOCK_RAW)
			return 1;
	}
	return on_packet(skb, 1);
}

static __always_inline int on_sock(struct bpf_sock *sk, __u8 kind)
{
	struct so_event *e;
	__u64 id = bpf_get_current_pid_tgid();

	if ((__u32)(id >> 32) == self_tgid)
		return 1;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&ringbuf_drops, 1);
		return 1;
	}
	e->ts_ns = bpf_ktime_get_ns();
	e->cookie = bpf_get_socket_cookie(sk);
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->tgid = (__u32)(id >> 32);
	e->tid = (__u32)id;
	e->saddr = 0;
	e->daddr = 0;
	e->sport = 0;
	e->dport = 0;
	e->kind = kind;
	e->proto = (__u8)sk->protocol;
	e->dir = (__u8)sk->type;
	e->family = (__u8)sk->family;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 1;
}

SEC("cgroup/sock_create")
int so_sock_create(struct bpf_sock *sk)
{
	return on_sock(sk, SO_SOCK);
}

SEC("cgroup/sock_release")
int so_sock_release(struct bpf_sock *sk)
{
	return on_sock(sk, SO_RELEASE);
}
