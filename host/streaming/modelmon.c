#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "modelmon.h"
#include "modelmon.skel.h"

struct window_counts {
    uint64_t connect_count;
    uint64_t openat_success_count;
    uint64_t openat2_success_count;
    uint64_t sendto_count;
    uint64_t socket_count;
    uint64_t write_success_count;
    uint64_t pwrite64_success_count;
    uint64_t writev_success_count;
    uint64_t write_bytes;
    uint64_t event_count;
};

static volatile sig_atomic_t stop;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stop = 1;
}

static double monotonic_seconds(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int handle_event(void *context, void *data, size_t data_size)
{
    struct window_counts *counts = context;
    const struct model_event *event = data;

    if (data_size < sizeof(*event)) {
        fprintf(stderr, "Received undersized eBPF event: %zu bytes\n", data_size);
        return 0;
    }

    counts->event_count++;
    switch (event->type) {
    case MODEL_EVENT_CONNECT:
        counts->connect_count++;
        break;
    case MODEL_EVENT_OPENAT:
        counts->openat_success_count++;
        break;
    case MODEL_EVENT_OPENAT2:
        counts->openat2_success_count++;
        break;
    case MODEL_EVENT_SENDTO:
        counts->sendto_count++;
        break;
    case MODEL_EVENT_SOCKET:
        counts->socket_count++;
        break;
    case MODEL_EVENT_WRITE:
        counts->write_success_count++;
        counts->write_bytes += event->value;
        break;
    case MODEL_EVENT_PWRITE64:
        counts->pwrite64_success_count++;
        counts->write_bytes += event->value;
        break;
    case MODEL_EVENT_WRITEV:
        counts->writev_success_count++;
        counts->write_bytes += event->value;
        break;
    default:
        fprintf(stderr, "Received unknown eBPF event type: %u\n", event->type);
        break;
    }
    return 0;
}

static int read_ringbuf_losses(int map_fd, uint64_t *total)
{
    int cpu_count = libbpf_num_possible_cpus();
    uint64_t *values;
    uint32_t key = 0;
    int cpu;

    if (cpu_count < 1)
        return cpu_count;
    values = calloc((size_t)cpu_count, sizeof(*values));
    if (!values)
        return -ENOMEM;
    if (bpf_map_lookup_elem(map_fd, &key, values) != 0) {
        int error = -errno;
        free(values);
        return error;
    }

    *total = 0;
    for (cpu = 0; cpu < cpu_count; cpu++)
        *total += values[cpu];
    free(values);
    return 0;
}

static void print_window(
    unsigned long window_id,
    double start,
    double end,
    uint64_t lost_total,
    uint64_t previous_lost,
    const struct window_counts *counts)
{
    printf(
        "{\"record_type\":\"host_window\",\"window_id\":%lu,"
        "\"start_monotonic_sec\":%.9f,\"end_monotonic_sec\":%.9f,"
        "\"duration_sec\":%.9f,\"counts\":{"
        "\"host__ebpf_connect_count\":%llu,"
        "\"host__ebpf_file_pwrite64_success_count\":%llu,"
        "\"host__ebpf_file_write_bytes\":%llu,"
        "\"host__ebpf_file_write_success_count\":%llu,"
        "\"host__ebpf_file_writev_success_count\":%llu,"
        "\"host__ebpf_openat2_success_count\":%llu,"
        "\"host__ebpf_openat_success_count\":%llu,"
        "\"host__ebpf_sendto_count\":%llu,"
        "\"host__ebpf_socket_count\":%llu},"
        "\"event_count\":%llu,\"ringbuf_lost_window\":%llu,"
        "\"ringbuf_lost_total\":%llu}\n",
        window_id,
        start,
        end,
        end - start,
        (unsigned long long)counts->connect_count,
        (unsigned long long)counts->pwrite64_success_count,
        (unsigned long long)counts->write_bytes,
        (unsigned long long)counts->write_success_count,
        (unsigned long long)counts->writev_success_count,
        (unsigned long long)counts->openat2_success_count,
        (unsigned long long)counts->openat_success_count,
        (unsigned long long)counts->sendto_count,
        (unsigned long long)counts->socket_count,
        (unsigned long long)counts->event_count,
        (unsigned long long)(lost_total - previous_lost),
        (unsigned long long)lost_total);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    struct modelmon_bpf *skeleton = NULL;
    struct ring_buffer *ring = NULL;
    struct window_counts counts = {0};
    char *end = NULL;
    unsigned long target_pid;
    double window_seconds = 1.0;
    double start;
    double next_cut;
    double now;
    uint64_t lost_total = 0;
    uint64_t previous_lost = 0;
    unsigned long window_id = 0;
    uint32_t key = 0;
    uint8_t value = 1;
    int error = 0;
    int result = EXIT_FAILURE;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s TARGET_PID WINDOW_SECONDS\n", argv[0]);
        return EXIT_FAILURE;
    }
    errno = 0;
    target_pid = strtoul(argv[1], &end, 10);
    if (errno || !end || *end || target_pid == 0 || target_pid > UINT32_MAX) {
        fprintf(stderr, "Invalid target PID: %s\n", argv[1]);
        return EXIT_FAILURE;
    }
    errno = 0;
    window_seconds = strtod(argv[2], &end);
    if (errno || !end || *end || !isfinite(window_seconds) || window_seconds <= 0.0) {
        fprintf(stderr, "Invalid window duration: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skeleton = modelmon_bpf__open_and_load();
    if (!skeleton) {
        fprintf(stderr, "Failed to open/load modelmon BPF program\n");
        goto cleanup;
    }

    key = (uint32_t)target_pid;
    if (bpf_map_update_elem(
            bpf_map__fd(skeleton->maps.tracked_tgids),
            &key,
            &value,
            BPF_ANY) != 0) {
        perror("Track target PID");
        goto cleanup;
    }

    if (modelmon_bpf__attach(skeleton) != 0) {
        fprintf(stderr, "Failed to attach modelmon probes\n");
        goto cleanup;
    }

    ring = ring_buffer__new(
        bpf_map__fd(skeleton->maps.events),
        handle_event,
        &counts,
        NULL);
    if (!ring) {
        fprintf(stderr, "Failed to create modelmon ring buffer\n");
        goto cleanup;
    }

    error = read_ringbuf_losses(
        bpf_map__fd(skeleton->maps.ringbuf_lost),
        &lost_total);
    if (error) {
        fprintf(stderr, "Could not read ring-buffer loss counter: %d\n", error);
        goto cleanup;
    }
    previous_lost = lost_total;

    start = monotonic_seconds();
    next_cut = start + window_seconds;
    fprintf(
        stderr,
        "modelmon attached target_pid=%lu window_sec=%.3f clock=CLOCK_MONOTONIC\n",
        target_pid,
        window_seconds);

    while (!stop) {
            int poll_result = ring_buffer__poll(ring, 50);

        if (poll_result < 0 && poll_result != -EINTR) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", poll_result);
            goto cleanup;
        }
        now = monotonic_seconds();
        if (now < next_cut)
            continue;

        error = read_ringbuf_losses(
            bpf_map__fd(skeleton->maps.ringbuf_lost),
            &lost_total);
        if (error) {
            fprintf(stderr, "Could not read ring-buffer loss counter: %d\n", error);
            goto cleanup;
        }
        print_window(
            window_id++,
            start,
            now,
            lost_total,
            previous_lost,
            &counts);
        counts = (struct window_counts){0};
        previous_lost = lost_total;
        start = now;
        next_cut = start + window_seconds;
    }

    now = monotonic_seconds();
    error = read_ringbuf_losses(
        bpf_map__fd(skeleton->maps.ringbuf_lost),
        &lost_total);
    if (error) {
        fprintf(stderr, "Could not read ring-buffer loss counter: %d\n", error);
        goto cleanup;
    }
    if (now > start || counts.event_count || lost_total > previous_lost)
        print_window(
            window_id,
            start,
            now,
            lost_total,
            previous_lost,
            &counts);
    result = EXIT_SUCCESS;

cleanup:
    if (ring)
        ring_buffer__free(ring);
    if (skeleton)
        modelmon_bpf__destroy(skeleton);
    return result;
}
