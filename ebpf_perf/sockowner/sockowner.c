// SPDX-License-Identifier: GPL-2.0
/* sockowner: which process, socket and cgroup each TCP/UDP flow belongs to.
 *
 *   sockowner [CGROUP_V2_PATH]     (default /sys/fs/cgroup: every process)
 *
 * Attaches the four cgroup programs of sockowner.bpf.c to CGROUP_V2_PATH, prints
 * SOCKOWNER_READY,<cgroup id>, then one line per event until SIGINT/SIGTERM:
 *   SOCK,<ns>,<cookie>,<tgid>,<tid>,<cgroup id>,<family>,<type>,<protocol>,<comm>
 *   REL,<ns>,<cookie>,<tgid>,<tid>,<cgroup id>,<comm>
 *   FLOW,<ns>,<cookie>,<socket cgroup id>,<egress|ingress>,<tcp|udp>,<saddr>,<sport>,<daddr>,<dport>
 * <ns> is CLOCK_MONOTONIC, the clock hostmon_agg's windows use. FLOW is printed
 * for the first packet of each 5-tuple on a socket (and again if the 5-tuple
 * appears on another socket). On exit it drains the ring buffer and prints
 * SOCKOWNER_HEALTH,<ring-buffer drops>,<flow-map errors>,<failed>
 * and exits 1 if any of them is non-zero.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "sockowner.h"
#include "sockowner.skel.h"

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static void clean_comm(char *dst, const char *src)
{
	size_t i;

	for (i = 0; i < 15 && src[i]; i++)
		dst[i] = (src[i] == ',' || src[i] < 32 || src[i] > 126) ? '_' : src[i];
	dst[i] = '\0';
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct so_event *e = data;
	char comm[16], sa[INET_ADDRSTRLEN], da[INET_ADDRSTRLEN];

	(void)ctx;
	if (size < sizeof(*e))
		return 0;
	switch (e->kind) {
	case SO_SOCK:
		clean_comm(comm, e->comm);
		printf("SOCK,%llu,%llu,%u,%u,%llu,%u,%u,%u,%s\n", (unsigned long long)e->ts_ns,
		       (unsigned long long)e->cookie, e->tgid, e->tid, (unsigned long long)e->cgroup_id,
		       e->family, e->dir, e->proto, comm);
		break;
	case SO_RELEASE:
		clean_comm(comm, e->comm);
		printf("REL,%llu,%llu,%u,%u,%llu,%s\n", (unsigned long long)e->ts_ns,
		       (unsigned long long)e->cookie, e->tgid, e->tid, (unsigned long long)e->cgroup_id, comm);
		break;
	case SO_FLOW:
		inet_ntop(AF_INET, &e->saddr, sa, sizeof(sa));
		inet_ntop(AF_INET, &e->daddr, da, sizeof(da));
		printf("FLOW,%llu,%llu,%llu,%s,%s,%s,%u,%s,%u\n", (unsigned long long)e->ts_ns,
		       (unsigned long long)e->cookie, (unsigned long long)e->cgroup_id,
		       e->dir ? "ingress" : "egress", e->proto == 6 ? "tcp" : "udp", sa, e->sport, da, e->dport);
		break;
	default:
		break;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *cg = argc > 1 ? argv[1] : "/sys/fs/cgroup";
	struct sockowner_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct bpf_link *links[4] = {0};
	struct sigaction sa;
	struct stat st;
	unsigned long long drops, map_errors;
	int cgfd, failed = 0, i, n, attempt;

	if (argc > 2 || stat(cg, &st) || !S_ISDIR(st.st_mode)) {
		fprintf(stderr, "Usage: sockowner [CGROUP_V2_PATH]\n");
		return 1;
	}
	cgfd = open(cg, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cgfd < 0) {
		fprintf(stderr, "open %s: %s\n", cg, strerror(errno));
		return 1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal; /* no SA_RESTART: the poll returns on a signal */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	setvbuf(stdout, NULL, _IOFBF, 1 << 16);

	for (attempt = 0; attempt < 2; attempt++) {
		skel = sockowner_bpf__open();
		if (!skel) {
			fprintf(stderr, "Failed to open sockowner\n");
			return 1;
		}
		skel->rodata->self_tgid = (__u32)getpid();
		if (attempt == 1) {
			/* The socket programs need the current task's ids; a kernel that refuses
			 * them still gets the per-packet programs (cgroup-level attribution). */
			bpf_program__set_autoload(skel->progs.so_sock_create, false);
			bpf_program__set_autoload(skel->progs.so_sock_release, false);
		}
		if (!sockowner_bpf__load(skel))
			break;
		sockowner_bpf__destroy(skel);
		skel = NULL;
	}
	if (!skel) {
		fprintf(stderr, "Failed to load sockowner\n");
		return 1;
	}
	if (attempt == 1)
		printf("SOCKOWNER_WARNING,no-socket-programs\n");
	else {
		links[0] = bpf_program__attach_cgroup(skel->progs.so_sock_create, cgfd);
		links[1] = bpf_program__attach_cgroup(skel->progs.so_sock_release, cgfd);
	}
	links[2] = bpf_program__attach_cgroup(skel->progs.so_egress, cgfd);
	links[3] = bpf_program__attach_cgroup(skel->progs.so_ingress, cgfd);
	for (i = attempt == 1 ? 2 : 0; i < 4; i++) {
		if (!links[i]) {
			fprintf(stderr, "Failed to attach sockowner program %d to %s: %s\n", i, cg, strerror(errno));
			failed = 1;
		}
	}
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to open the ring buffer\n");
		failed = 1;
	}
	if (failed)
		goto out;

	printf("SOCKOWNER_READY,%llu\n", (unsigned long long)st.st_ino);
	fflush(stdout);
	while (!stop) {
		n = ring_buffer__poll(rb, 100);
		if (n < 0 && n != -EINTR) {
			failed = 1;
			break;
		}
		fflush(stdout);
	}
	/* Detach first so that no event arrives after the final drain. */
	for (i = 0; i < 4; i++) {
		bpf_link__destroy(links[i]);
		links[i] = NULL;
	}
	if (ring_buffer__consume(rb) < 0)
		failed = 1;
out:
	drops = __atomic_load_n(&skel->bss->ringbuf_drops, __ATOMIC_SEQ_CST);
	map_errors = __atomic_load_n(&skel->bss->flow_map_errors, __ATOMIC_SEQ_CST);
	printf("SOCKOWNER_HEALTH,%llu,%llu,%d\n", drops, map_errors, failed);
	fflush(stdout);
	for (i = 0; i < 4; i++)
		bpf_link__destroy(links[i]);
	ring_buffer__free(rb);
	sockowner_bpf__destroy(skel);
	close(cgfd);
	return failed || drops || map_errors ? 1 : 0;
}
