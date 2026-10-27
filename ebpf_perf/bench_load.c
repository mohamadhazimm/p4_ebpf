/* Known-answer syscall load for HostMon performance tests.
 *
 * Usage: bench_load CGROUP_PROCS|- MODE COUNT RATE [PATH]
 *   CGROUP_PROCS  cgroup.procs file to join before timing, or "-" to stay put
 *   MODE          getppid | openclose | openonly | fstat | rdwr | forkexec
 *   COUNT         number of operations
 *   RATE          target operations per second, 0 = unlimited
 *   PATH          file for openclose/openonly/fstat (default /etc/hostname);
 *                 for rdwr, "IN:OUT" = 1-byte read from IN, 1-byte write to OUT
 *
 * openclose = openat+read+close, openonly = openat+close (LMbench open/close),
 * fstat = fstat on an open descriptor (LMbench fstat), rdwr = one-byte read +
 * write per operation (the eAudit rdwr workload).
 *
 * Pacing busy-waits on the vDSO clock, so it adds no syscalls. After the
 * cgroup join, a getppid run issues exactly COUNT getppid calls plus a few
 * fixed calls (close, the result write, exit_group).
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void join_cgroup(const char *procs)
{
    char buf[32];
    int fd, len;

    if (!strcmp(procs, "-"))
        return;
    fd = open(procs, O_WRONLY);
    if (fd < 0) {
        perror("open cgroup.procs");
        exit(2);
    }
    len = snprintf(buf, sizeof(buf), "%d\n", getpid());
    if (write(fd, buf, len) != len) {
        perror("write cgroup.procs");
        exit(2);
    }
    close(fd);
}

int main(int argc, char **argv)
{
    const char *mode, *path = "/etc/hostname";
    long long count, rate, start, end, i, failures = 0;
    char buf[64];
    struct stat st;
    int keep_fd = -1, out_fd = -1;

    if (argc < 5 || argc > 6) {
        fprintf(stderr, "usage: bench_load CGROUP_PROCS|- MODE COUNT RATE [PATH]\n");
        return 2;
    }
    mode = argv[2];
    count = atoll(argv[3]);
    rate = atoll(argv[4]);
    if (argc == 6)
        path = argv[5];
    if (count <= 0 || rate < 0) {
        fprintf(stderr, "COUNT must be > 0 and RATE >= 0\n");
        return 2;
    }

    if (!strcmp(mode, "fstat") && (keep_fd = open(path, O_RDONLY)) < 0) {
        perror(path);
        return 2;
    }
    if (!strcmp(mode, "rdwr")) {
        char in[4096], *colon = strchr(path, ':');
        if (!colon || (size_t)(colon - path) >= sizeof(in)) {
            fprintf(stderr, "rdwr needs PATH=IN:OUT\n");
            return 2;
        }
        memcpy(in, path, colon - path);
        in[colon - path] = 0;
        keep_fd = open(in, O_RDONLY);
        out_fd = open(colon + 1, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (keep_fd < 0 || out_fd < 0) {
            perror("rdwr open");
            return 2;
        }
    }

    join_cgroup(argv[1]);
    start = now_ns();
    for (i = 0; i < count; i++) {
        if (rate && (i & 255) == 0) {
            long long due = start + i * 1000000000LL / rate;
            while (now_ns() < due)
                ;
        }
        if (!strcmp(mode, "getppid")) {
            syscall(SYS_getppid);
        } else if (!strcmp(mode, "openclose")) {
            int fd = openat(AT_FDCWD, path, O_RDONLY);
            if (fd < 0 || read(fd, buf, sizeof(buf)) < 0)
                failures++;
            if (fd >= 0)
                close(fd);
        } else if (!strcmp(mode, "openonly")) {
            int fd = openat(AT_FDCWD, path, O_RDONLY);
            if (fd < 0)
                failures++;
            else
                close(fd);
        } else if (!strcmp(mode, "fstat")) {
            if (fstat(keep_fd, &st) < 0)
                failures++;
        } else if (!strcmp(mode, "rdwr")) {
            if (read(keep_fd, buf, 1) != 1 || write(out_fd, buf, 1) != 1)
                failures++;
        } else if (!strcmp(mode, "forkexec")) {
            pid_t pid = fork();
            int status;
            if (pid == 0) {
                execl("/bin/true", "true", (char *)NULL);
                _exit(127);
            }
            if (pid < 0 || waitpid(pid, &status, 0) < 0 || status != 0)
                failures++;
        } else {
            fprintf(stderr, "unknown mode: %s\n", mode);
            return 2;
        }
    }
    end = now_ns();
    printf("{\"mode\":\"%s\",\"count\":%lld,\"rate\":%lld,\"elapsed_ns\":%lld,"
           "\"ops_per_sec\":%.1f,\"failures\":%lld,\"pid\":%d}\n",
           mode, count, rate, end - start,
           count * 1e9 / (double)(end - start), failures, getpid());
    return failures ? 1 : 0;
}
