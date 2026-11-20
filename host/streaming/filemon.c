#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "filemon.h"
#include "filemon.skel.h"

#define MAX_TRACKED 256

struct proc_stats {
    int used;
    char comm[16];

    unsigned long open_count;
    unsigned long rename_count;
    unsigned long unlink_count;
    unsigned long total_events;

    int score;
};

static volatile sig_atomic_t stop = 0;
static struct proc_stats stats_table[MAX_TRACKED];

static void sig_handler(int sig)
{
    stop = 1;
}

static int interesting_path(const char *p)
{
    if (!p || !p[0])
        return 0;

    if (!strncmp(p, "/proc/", 6)) return 0;
    if (!strncmp(p, "/sys/", 5)) return 0;
    if (!strncmp(p, "/dev/", 5)) return 0;
    if (!strncmp(p, "/run/", 5)) return 0;
    if (!strncmp(p, "/snap/", 6)) return 0;
    if (!strncmp(p, "/usr/", 5)) return 0;
    if (!strncmp(p, "/lib/", 5)) return 0;

    if (!strncmp(p, "/home/", 6)) return 1;
    if (!strncmp(p, "/tmp/", 5)) return 1;
    if (!strncmp(p, "/var/tmp/", 9)) return 1;
    if (!strncmp(p, "/dev/shm/", 9)) return 1;

    return 0;
}

static int noisy_comm(const char *comm)
{
    if (!comm || !comm[0])
        return 1;

    if (!strcmp(comm, "Cache2 I/O")) return 1;
    if (!strcmp(comm, "gnome-shell")) return 1;
    if (!strcmp(comm, "tracker-miner-f")) return 1;
    if (!strcmp(comm, "tracker-extract")) return 1;
    if (!strcmp(comm, "libuv-worker")) return 1;
    if (!strcmp(comm, "command-not-fou")) return 1;

    return 0;
}

static struct proc_stats *get_proc_stats(const char *comm)
{
    int i;
    int free_idx = -1;

    for (i = 0; i < MAX_TRACKED; i++) {
        if (stats_table[i].used &&
            strcmp(stats_table[i].comm, comm) == 0)
            return &stats_table[i];

        if (!stats_table[i].used && free_idx == -1)
            free_idx = i;
    }

    if (free_idx == -1)
        return NULL;

    stats_table[free_idx].used = 1;
    strncpy(stats_table[free_idx].comm, comm, sizeof(stats_table[free_idx].comm) - 1);
    stats_table[free_idx].comm[sizeof(stats_table[free_idx].comm) - 1] = '\0';
    stats_table[free_idx].open_count = 0;
    stats_table[free_idx].rename_count = 0;
    stats_table[free_idx].unlink_count = 0;
    stats_table[free_idx].total_events = 0;
    stats_table[free_idx].score = 0;

    return &stats_table[free_idx];
}

static int compute_score(struct proc_stats *ps)
{
    int score = 0;

    if (ps->open_count > 20)
        score += 1;

    if (ps->rename_count > 2)
        score += 3;

    if (ps->unlink_count > 2)
        score += 3;

    if (ps->total_events > 10)
        score += 2;

    return score;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct proc_stats *ps;

    if (!interesting_path(e->path1) && !interesting_path(e->path2))
        return 0;

    if (noisy_comm(e->comm))
        return 0;

    ps = get_proc_stats(e->comm);
    if (!ps)
        return 0;

    ps->total_events++;

    switch (e->type) {
    case EVENT_OPEN:
        ps->open_count++;
        break;
    case EVENT_RENAME:
        ps->rename_count++;
        break;
    case EVENT_UNLINK:
        ps->unlink_count++;
        break;
    default:
        break;
    }

    return 0;
}

static void print_stats(void)
{
    int i;

    printf("\n===== Per-command file activity =====\n");
    printf("%-16s %-6s %-6s %-6s %-6s %-6s %-6s\n",
           "COMM", "OPEN", "REN", "DEL", "TOT", "SCR", "ALERT");

    for (i = 0; i < MAX_TRACKED; i++) {
        if (!stats_table[i].used)
            continue;

        if (stats_table[i].total_events == 0)
            continue;

        stats_table[i].score = compute_score(&stats_table[i]);

        printf("%-16s %-6lu %-6lu %-6lu %-6lu %-6d %-6s\n",
               stats_table[i].comm,
               stats_table[i].open_count,
               stats_table[i].rename_count,
               stats_table[i].unlink_count,
               stats_table[i].total_events,
               stats_table[i].score,
               stats_table[i].score >= 5 ? "YES" : "-");
    }

    printf("=====================================\n");
}

static void reset_stats(void)
{
    int i;

    for (i = 0; i < MAX_TRACKED; i++) {

        if (!stats_table[i].used)
            continue;

        stats_table[i].open_count = 0;
        stats_table[i].rename_count = 0;
        stats_table[i].unlink_count = 0;
        stats_table[i].total_events = 0;
        stats_table[i].score = 0;
    }
}

int main(void)
{
    struct filemon_bpf *skel;
    struct ring_buffer *rb;
    int err;
    time_t last_print, now;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    memset(stats_table, 0, sizeof(stats_table));

    skel = filemon_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load filemon\n");
        return 1;
    }

    err = filemon_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach filemon: %d\n", err);
        filemon_bpf__destroy(skel);
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        filemon_bpf__destroy(skel);
        return 1;
    }

    printf("Tracking file activity by command... Press Ctrl+C to stop.\n");

    last_print = time(NULL);

    while (!stop) {
        err = ring_buffer__poll(rb, 200);
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            break;
        }

        now = time(NULL);
        if (now - last_print >= 3) {

            print_stats();

            reset_stats();   // <-- add this

            last_print = now;
        }
    }

    print_stats();

    ring_buffer__free(rb);
    filemon_bpf__destroy(skel);
    return 0;
}