#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "execmon.h"
#include "execmon.skel.h"

static volatile sig_atomic_t stop = 0;

static void sig_handler(int sig)
{
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;

    printf("PID=%u COMM=%s FILE=%s\n",
           e->pid, e->comm, e->filename);

    return 0;
}

int main(void)
{
    struct execmon_bpf *skel;
    struct ring_buffer *rb;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = execmon_bpf__open_and_load();
    if (!skel) {
        printf("Failed to load\n");
        return 1;
    }

    err = execmon_bpf__attach(skel);
    if (err) {
        printf("Attach failed\n");
        return 1;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL);

    printf("Tracing execve...\n");

    while (!stop)
        ring_buffer__poll(rb, 100);

    return 0;
}