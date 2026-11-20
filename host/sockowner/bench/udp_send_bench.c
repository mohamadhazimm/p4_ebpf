/* Benign micro-benchmark for the socket tracer's cost (PC1.md Part 5): COUNT datagrams of 64 B on one
 * unconnected UDP socket (sendto, so ICMP errors of a closed port are not returned) to DST, destination
 * port cycling over PORTS values from PORT (PORTS 1: every datagram has the same 5-tuple, so the tracer
 * does one hash lookup per packet; PORTS 50000: the first 50,000 datagrams each open a new 5-tuple, so the
 * tracer emits one FLOW event each). Timed with CLOCK_MONOTONIC; prints one JSON line.
 *   udp_send_bench DST PORT COUNT LABEL [PORTS] */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	struct sockaddr_in dst;
	char payload[64];
	long count, ports = 1, i, failed = 0;
	long long start, end;
	int s, port0;

	if (argc != 5 && argc != 6) {
		fprintf(stderr, "usage: udp_send_bench DST PORT COUNT LABEL [PORTS]\n");
		return 2;
	}
	count = atol(argv[3]);
	port0 = atoi(argv[2]);
	if (argc == 6)
		ports = atol(argv[5]);
	if (count <= 0 || ports <= 0 || port0 <= 0 || port0 + ports - 1 > 65535)
		return 2;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	if (inet_pton(AF_INET, argv[1], &dst.sin_addr) != 1)
		return 2;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return 1;
	memset(payload, 'b', sizeof(payload));
	start = now_ns();
	for (i = 0; i < count; i++) {
		dst.sin_port = htons((unsigned short)(port0 + i % ports));
		if (sendto(s, payload, sizeof(payload), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
			failed++;
	}
	end = now_ns();
	close(s);
	printf("{\"label\": \"%s\", \"count\": %ld, \"ports\": %ld, \"failed\": %ld, \"ns_total\": %lld, "
	       "\"ns_per_send\": %.1f}\n", argv[4], count, ports, failed, end - start, (double)(end - start) / (double)count);
	return 0;
}
