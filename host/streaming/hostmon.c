#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#include "hostmon.h"
#include "hostmon.skel.h"

#define MAX_TRACKED     128
#define MAX_UNIQUE      64
#define MAX_SYSCALL_ID  1024
#define FIRST_N_STORE   100

struct proc_stats {
    int used;
    unsigned int pid;
    char comm[16];

    unsigned long exec_count;
    unsigned long open_count;
    unsigned long rename_count;
    unsigned long unlink_count;
    unsigned long connect_count;

    unsigned int seen_ips[MAX_UNIQUE];
    int seen_ips_cnt;

    unsigned short seen_ports[MAX_UNIQUE];
    int seen_ports_cnt;

    unsigned long total_syscalls;
    unsigned long unique_syscalls;

    unsigned long transition_count;

    unsigned int last_syscall;
    int last_syscall_valid;

    unsigned long current_run_length;
    unsigned long run_count;
    unsigned long run_length_sum_closed;
    unsigned long max_run_length;

    unsigned long syscall_hist[MAX_SYSCALL_ID];

    unsigned int first_ids[FIRST_N_STORE];
    int first_ids_cnt;
};

static struct proc_stats table[MAX_TRACKED];
static volatile sig_atomic_t stop = 0;
static unsigned int self_pid = 0;

static double now_monotonic_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ((double)ts.tv_nsec / 1e9);
}

static void sig_handler(int sig)
{
    (void)sig;
    stop = 1;
}

static int starts_with(const char *s, const char *prefix)
{
    return s && prefix && strncmp(s, prefix, strlen(prefix)) == 0;
}

static int noisy_comm(const char *c)
{
    if (!c)
        return 1;

    /* self / launcher */
    if (!strcmp(c, "hostmon")) return 1;
    if (!strcmp(c, "sudo")) return 1;

    /* desktop / obvious background */
    if (!strcmp(c, "systemd-oomd")) return 1;
    if (!strcmp(c, "gnome-shell")) return 1;
    if (!strcmp(c, "dbus-daemon")) return 1;
    if (!strcmp(c, "MemoryPoller")) return 1;
    if (!strcmp(c, "irqbalance")) return 1;
    if (!strcmp(c, "Cache2 I/O")) return 1;
    if (!strcmp(c, "pool-gnome-shel")) return 1;
    if (!strcmp(c, "tracker-miner-f")) return 1;
    if (!strcmp(c, "tracker-extract")) return 1;
    if (!strcmp(c, "Indexed~ IO #18")) return 1;
    if (!strcmp(c, "BigIonThr-Pool #")) return 1;
    if (!strcmp(c, "systemd-journal")) return 1;
    if (!strcmp(c, "VBoxService")) return 1;

    /* extra obvious workstation noise from your logs */
    if (!strcmp(c, "code")) return 1;
    if (!strcmp(c, "gedit")) return 1;
    if (!strcmp(c, "nautilus")) return 1;
    if (!strcmp(c, "VBoxDRMClient")) return 1;
    if (!strcmp(c, "VBoxClient")) return 1;
    if (!strcmp(c, "packagekitd")) return 1;
    if (!strcmp(c, "WaylandProxy")) return 1;
    if (!strcmp(c, "Inotify~tThread")) return 1;

    /* prefix-based filters */
    if (starts_with(c, "gnome-terminal")) return 1;
    if (starts_with(c, "llvmpipe-")) return 1;
    if (starts_with(c, "Web Content")) return 1;
    if (starts_with(c, "Isolated Web Co")) return 1;
    if (starts_with(c, "Backgro")) return 1;

    if (!strcmp(c, "IPDL Background")) return 1;
    if (!strcmp(c, "Chrome_IOThread")) return 1;
    if (!strcmp(c, "Chrome_ChildIOT")) return 1;
    if (!strcmp(c, "GpuWatchdog")) return 1;
    if (!strcmp(c, "Socket Thread")) return 1;
    if (!strcmp(c, "libuv-worker")) return 1;
    if (!strcmp(c, "gsd-housekeepin")) return 1;
    if (!strcmp(c, "gvfs-afc-volume")) return 1;
    if (!strcmp(c, "ibus-daemon")) return 1;
    if (!strcmp(c, "ibus-extension-")) return 1;
    if (!strcmp(c, "gdbus")) return 1;
    if (!strcmp(c, "alsa-sink-Intel")) return 1;

    if (!strcmp(c, "firefox")) return 1;
    if (!strcmp(c, "Xwayland")) return 1;
    if (!strcmp(c, "ThreadPoolForeg")) return 1;
    if (!strcmp(c, "IPC I/O Child")) return 1;
    if (!strcmp(c, "IPC I/O Parent")) return 1;
    if (!strcmp(c, "VizCompositorTh")) return 1;
    if (!strcmp(c, "WebExtensions")) return 1;
    if (!strcmp(c, "JS Helper")) return 1;
    if (!strcmp(c, "pulseaudio")) return 1;
    if (!strcmp(c, "ibus-engine-sim")) return 1;
    if (!strcmp(c, "gmain")) return 1;
    if (!strcmp(c, "gsd-media-keys")) return 1;
    if (!strcmp(c, "xdg-desktop-por")) return 1;

    return 0;
}

static int interesting_path(const char *p)
{
    if (!p || !p[0])
        return 0;

    if (!strncmp(p, "/proc/", 6)) return 0;
    if (!strncmp(p, "/sys/", 5)) return 0;
    if (!strncmp(p, "/dev/", 5)) return 0;
    if (!strncmp(p, "/run/", 5)) return 0;
    if (!strncmp(p, "/usr/", 5)) return 0;
    if (!strncmp(p, "/lib/", 5)) return 0;
    if (!strncmp(p, "/snap/", 6)) return 0;

    return 1;
}

static void clear_metrics(struct proc_stats *ps)
{
    ps->exec_count = 0;
    ps->open_count = 0;
    ps->rename_count = 0;
    ps->unlink_count = 0;
    ps->connect_count = 0;

    ps->seen_ips_cnt = 0;
    ps->seen_ports_cnt = 0;

    ps->total_syscalls = 0;
    ps->unique_syscalls = 0;
    ps->transition_count = 0;

    ps->last_syscall = 0;
    ps->last_syscall_valid = 0;

    ps->current_run_length = 0;
    ps->run_count = 0;
    ps->run_length_sum_closed = 0;
    ps->max_run_length = 0;

    memset(ps->syscall_hist, 0, sizeof(ps->syscall_hist));
    memset(ps->first_ids, 0, sizeof(ps->first_ids));
    ps->first_ids_cnt = 0;
}

static int slot_is_inactive(const struct proc_stats *ps)
{
    return ps->used &&
           ps->exec_count == 0 &&
           ps->open_count == 0 &&
           ps->rename_count == 0 &&
           ps->unlink_count == 0 &&
           ps->connect_count == 0 &&
           ps->total_syscalls == 0;
}

static struct proc_stats *get_stats(unsigned int pid, const char *comm)
{
    int i;

    for (i = 0; i < MAX_TRACKED; i++) {
        if (table[i].used && table[i].pid == pid) {
            if (comm && comm[0]) {
                memset(table[i].comm, 0, sizeof(table[i].comm));
                strncpy(table[i].comm, comm, sizeof(table[i].comm) - 1);
            }
            return &table[i];
        }
    }

    for (i = 0; i < MAX_TRACKED; i++) {
        if (!table[i].used) {
            memset(&table[i], 0, sizeof(table[i]));
            table[i].used = 1;
            table[i].pid = pid;
            if (comm)
                strncpy(table[i].comm, comm, sizeof(table[i].comm) - 1);
            return &table[i];
        }
    }

    for (i = 0; i < MAX_TRACKED; i++) {
        if (slot_is_inactive(&table[i])) {
            memset(&table[i], 0, sizeof(table[i]));
            table[i].used = 1;
            table[i].pid = pid;
            if (comm)
                strncpy(table[i].comm, comm, sizeof(table[i].comm) - 1);
            return &table[i];
        }
    }

    return NULL;
}

static int add_unique_ip(struct proc_stats *ps, unsigned int ip)
{
    int i;

    if (ip == 0)
        return 0;

    for (i = 0; i < ps->seen_ips_cnt; i++) {
        if (ps->seen_ips[i] == ip)
            return 0;
    }

    if (ps->seen_ips_cnt < MAX_UNIQUE) {
        ps->seen_ips[ps->seen_ips_cnt++] = ip;
        return 1;
    }

    return 0;
}

static int add_unique_port(struct proc_stats *ps, unsigned short port)
{
    int i;

    if (port == 0)
        return 0;

    for (i = 0; i < ps->seen_ports_cnt; i++) {
        if (ps->seen_ports[i] == port)
            return 0;
    }

    if (ps->seen_ports_cnt < MAX_UNIQUE) {
        ps->seen_ports[ps->seen_ports_cnt++] = port;
        return 1;
    }

    return 0;
}

static void record_syscall(struct proc_stats *ps, unsigned int syscall_id)
{
    if (!ps)
        return;

    ps->total_syscalls++;

    if (!ps->last_syscall_valid) {
        ps->last_syscall_valid = 1;
        ps->last_syscall = syscall_id;
        ps->current_run_length = 1;
        ps->run_count = 1;
    } else if (ps->last_syscall == syscall_id) {
        ps->current_run_length++;
    } else {
        ps->transition_count++;
        ps->run_length_sum_closed += ps->current_run_length;
        if (ps->current_run_length > ps->max_run_length)
            ps->max_run_length = ps->current_run_length;

        ps->last_syscall = syscall_id;
        ps->current_run_length = 1;
        ps->run_count++;
    }

    if (syscall_id < MAX_SYSCALL_ID) {
        if (ps->syscall_hist[syscall_id] == 0)
            ps->unique_syscalls++;

        ps->syscall_hist[syscall_id]++;
    }

    if (ps->first_ids_cnt < FIRST_N_STORE)
        ps->first_ids[ps->first_ids_cnt++] = syscall_id;
}

static int count_unique_prefix(const unsigned int *arr, int n)
{
    int i, j;
    int unique = 0;

    for (i = 0; i < n; i++) {
        int seen = 0;
        for (j = 0; j < i; j++) {
            if (arr[j] == arr[i]) {
                seen = 1;
                break;
            }
        }
        if (!seen)
            unique++;
    }

    return unique;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct proc_stats *ps;

    (void)ctx;
    (void)data_sz;

    if (e->pid == self_pid)
        return 0;
    if (noisy_comm(e->comm))
        return 0;

    if (e->type != EVENT_CONNECT && e->type != EVENT_SYSCALL) {
        if (!interesting_path(e->path1))
            return 0;
    }

    ps = get_stats(e->pid, e->comm);
    if (!ps)
        return 0;

    switch (e->type) {
    case EVENT_EXEC:
        ps->exec_count++;
        break;
    case EVENT_OPEN:
        ps->open_count++;
        break;
    case EVENT_RENAME:
        ps->rename_count++;
        break;
    case EVENT_UNLINK:
        ps->unlink_count++;
        break;
    case EVENT_CONNECT:
        ps->connect_count++;
        add_unique_ip(ps, e->addr);
        add_unique_port(ps, ntohs(e->port));
        break;
    case EVENT_SYSCALL:
        record_syscall(ps, e->syscall_id);
        break;
    default:
        break;
    }

    return 0;
}

static void print_and_reset(unsigned long window_id, double start_sec, double end_sec)
{
    int i;

    printf("\n==== HOST WINDOW %lu START=%.3f END=%.3f DUR=%.3f ====\n",
           window_id, start_sec, end_sec, end_sec - start_sec);
    printf("COMM,PID,EXEC,OPEN,REN,DEL,CONN,UNIQIP,UNIQPRT,"
           "TOTAL_SYSCALLS,UNIQUE_SYSCALLS,ENTROPY,TOP_SYSCALL_FREQ,"
           "AVG_RUN_LENGTH,MAX_RUN_LENGTH,TRANSITION_COUNT,"
           "RARE_SYSCALL_RATIO,FIRST50_UNIQUE,FIRST100_UNIQUE\n");

    for (i = 0; i < MAX_TRACKED; i++) {
        struct proc_stats *ps = &table[i];
        unsigned long max_freq = 0;
        unsigned long singleton_count = 0;
        unsigned long effective_max_run;
        unsigned long effective_run_sum;
        double entropy = 0.0;
        double top_syscall_freq = 0.0;
        double avg_run_length = 0.0;
        double rare_syscall_ratio = 0.0;
        int first50_n;
        int first100_n;
        int first50_unique;
        int first100_unique;
        int s;

        if (!ps->used)
            continue;

        if (ps->exec_count == 0 &&
            ps->open_count == 0 &&
            ps->rename_count == 0 &&
            ps->unlink_count == 0 &&
            ps->connect_count == 0 &&
            ps->total_syscalls == 0)
            continue;

        for (s = 0; s < MAX_SYSCALL_ID; s++) {
            if (ps->syscall_hist[s] > 0 && ps->total_syscalls > 0) {
                double p = (double)ps->syscall_hist[s] / (double)ps->total_syscalls;
                entropy -= p * (log(p) / log(2.0));

                if (ps->syscall_hist[s] > max_freq)
                    max_freq = ps->syscall_hist[s];
                if (ps->syscall_hist[s] == 1)
                    singleton_count++;
            }
        }

        effective_max_run = ps->max_run_length;
        if (ps->current_run_length > effective_max_run)
            effective_max_run = ps->current_run_length;

        effective_run_sum = ps->run_length_sum_closed;
        if (ps->current_run_length > 0)
            effective_run_sum += ps->current_run_length;

        if (ps->total_syscalls > 0) {
            top_syscall_freq = (double)max_freq / (double)ps->total_syscalls;
            rare_syscall_ratio = (double)singleton_count / (double)ps->total_syscalls;
        }

        if (ps->run_count > 0)
            avg_run_length = (double)effective_run_sum / (double)ps->run_count;

        first50_n = ps->first_ids_cnt < 50 ? ps->first_ids_cnt : 50;
        first100_n = ps->first_ids_cnt < 100 ? ps->first_ids_cnt : 100;
        first50_unique = count_unique_prefix(ps->first_ids, first50_n);
        first100_unique = count_unique_prefix(ps->first_ids, first100_n);

        printf("%s,%u,%lu,%lu,%lu,%lu,%lu,%d,%d,"
               "%lu,%lu,%.6f,%.6f,%.6f,%lu,%lu,%.6f,%d,%d\n",
               ps->comm,
               ps->pid,
               ps->exec_count,
               ps->open_count,
               ps->rename_count,
               ps->unlink_count,
               ps->connect_count,
               ps->seen_ips_cnt,
               ps->seen_ports_cnt,
               ps->total_syscalls,
               ps->unique_syscalls,
               entropy,
               top_syscall_freq,
               avg_run_length,
               effective_max_run,
               ps->transition_count,
               rare_syscall_ratio,
               first50_unique,
               first100_unique);

        clear_metrics(ps);
    }

    fflush(stdout);
}

int main(int argc, char **argv)
{
    self_pid = (unsigned int)getpid();
    struct hostmon_bpf *skel;
    struct ring_buffer *rb;
    double collector_start;
    double last_cut;
    double now;
    double window_sec = 5.0;
    unsigned long window_id = 0;

    if (argc >= 2) {
        window_sec = atof(argv[1]);
        if (window_sec <= 0.0) {
            fprintf(stderr, "Invalid window_sec: %s\n", argv[1]);
            return 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    memset(table, 0, sizeof(table));

    skel = hostmon_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load hostmon\n");
        return 1;
    }

    if (hostmon_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach hostmon\n");
        hostmon_bpf__destroy(skel);
        return 1;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        hostmon_bpf__destroy(skel);
        return 1;
    }

    printf("Tracking host features... window_sec=%.3f Press Ctrl+C to stop.\n", window_sec);
    fflush(stdout);

    collector_start = now_monotonic_sec();
    last_cut = collector_start;

    while (!stop) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            break;
        }

        now = now_monotonic_sec();
        if ((now - last_cut) >= window_sec) {
            print_and_reset(window_id, last_cut - collector_start, now - collector_start);
            last_cut = now;
            window_id++;
        }
    }

    now = now_monotonic_sec();
    print_and_reset(window_id, last_cut - collector_start, now - collector_start);

    ring_buffer__free(rb);
    hostmon_bpf__destroy(skel);
    return 0;
}