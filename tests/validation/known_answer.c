#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef VALIDATION_LIBURING
#include <liburing.h>
#endif

static int failed(const char *operation)
{
    int error = errno;
    perror(operation);
    return error == ENOSYS || error == EPERM ? 77 : 1;
}

static int run_operation(const char *operation, int descriptor, const char *path)
{
    if (!strcmp(operation, "open") || !strcmp(operation, "openat") || !strcmp(operation, "openat2")) {
        int opened = -1;
        if (!strcmp(operation, "open"))
            opened = syscall(SYS_open, path, O_RDONLY, 0);
        else if (!strcmp(operation, "openat"))
            opened = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
#ifdef SYS_openat2
        else {
            struct { uint64_t flags, mode, resolve; } how = { .flags = O_RDONLY };
            opened = syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
        }
#endif
        if (opened < 0) return -1;
        return close(opened);
    }
    if (!strcmp(operation, "write")) return write(descriptor, "x", 1) == 1 ? 0 : -1;
    if (!strcmp(operation, "pwrite")) return pwrite(descriptor, "x", 1, 0) == 1 ? 0 : -1;
    if (!strcmp(operation, "writev")) {
        struct iovec vector = { .iov_base = "x", .iov_len = 1 };
        return writev(descriptor, &vector, 1) == 1 ? 0 : -1;
    }
    if (!strcmp(operation, "mmap_write")) {
        char *mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, 0);
        if (mapped == MAP_FAILED) return -1;
        mapped[0] = 'x';
        int result = msync(mapped, 4096, MS_SYNC);
        munmap(mapped, 4096);
        return result;
    }
    if (!strcmp(operation, "execve") || !strcmp(operation, "execveat") || !strcmp(operation, "memfd_fexecve")) {
        char *arguments[] = { "known-answer", "--done", NULL };
        char *environment[] = { NULL };
        if (!strcmp(operation, "execve")) return execve("/proc/self/exe", arguments, environment);
#ifdef SYS_execveat
        if (!strcmp(operation, "execveat"))
            return syscall(SYS_execveat, AT_FDCWD, "/proc/self/exe", arguments, environment, 0);
#endif
        int memory = memfd_create("validation-fixture", 0);
        int executable = open("/proc/self/exe", O_RDONLY);
        if (memory < 0 || executable < 0) return -1;
        char buffer[8192];
        ssize_t length;
        while ((length = read(executable, buffer, sizeof(buffer))) > 0)
            if (write(memory, buffer, length) != length) return -1;
        close(executable);
        if (length < 0) return -1;
        return fexecve(memory, arguments, environment);
    }
    if (!strcmp(operation, "fork") || !strcmp(operation, "vfork") || !strcmp(operation, "clone3")) {
        pid_t child;
        if (!strcmp(operation, "fork")) child = fork();
        else if (!strcmp(operation, "vfork")) child = vfork();
        else {
#ifdef SYS_clone3
            struct clone_args arguments = { .exit_signal = SIGCHLD };
            child = syscall(SYS_clone3, &arguments, sizeof(arguments));
#else
            errno = ENOSYS;
            return -1;
#endif
        }
        if (child == 0) _exit(0);
        if (child < 0) return -1;
        int status;
        return waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
    }
    if (!strcmp(operation, "double_fork")) {
        int synchronization[2];
        if (pipe(synchronization)) return -1;
        pid_t child = fork();
        if (child < 0) return -1;
        if (child == 0) {
            if (setsid() < 0) _exit(1);
            pid_t intermediate = getpid();
            pid_t grandchild = fork();
            if (grandchild < 0) _exit(1);
            if (grandchild > 0) _exit(0);
            close(synchronization[0]);
            while (getppid() == intermediate) sched_yield();
            int result = write(descriptor, "x", 1) == 1 ? 0 : 1;
            write(synchronization[1], "x", 1);
            _exit(result);
        }
        close(synchronization[1]);
        int status;
        waitpid(child, &status, 0);
        char acknowledgement;
        int result = read(synchronization[0], &acknowledgement, 1) == 1 ? 0 : -1;
        close(synchronization[0]);
        return result;
    }
    if (!strcmp(operation, "tcp_connect") || !strcmp(operation, "udp_sendto") || !strcmp(operation, "raw_syn")) {
        int type = !strcmp(operation, "tcp_connect") ? SOCK_STREAM : SOCK_DGRAM;
        int protocol = 0;
        if (!strcmp(operation, "raw_syn")) { type = SOCK_RAW; protocol = IPPROTO_TCP; }
        int connection = socket(AF_INET, type, protocol);
        if (connection < 0) return -1;
        struct sockaddr_in destination = { .sin_family = AF_INET, .sin_port = htons(9099),
                                           .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
        int result;
        if (type == SOCK_STREAM) result = connect(connection, (void *)&destination, sizeof(destination));
        else if (type == SOCK_DGRAM)
            result = sendto(connection, "x", 1, 0, (void *)&destination, sizeof(destination)) == 1 ? 0 : -1;
        else {
            struct tcphdr header = { .source = htons(32000), .dest = htons(9099), .doff = 5, .syn = 1 };
            result = sendto(connection, &header, sizeof(header), 0, (void *)&destination, sizeof(destination)) == sizeof(header) ? 0 : -1;
        }
        close(connection);
        return result;
    }
    if (!strcmp(operation, "dns")) {
        struct __res_state resolver = {0};
        unsigned char answer[512];
        if (res_ninit(&resolver)) return -1;
        resolver.nscount = 1;
        resolver.nsaddr_list[0].sin_family = AF_INET;
        resolver.nsaddr_list[0].sin_port = htons(53);
        resolver.nsaddr_list[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int result = res_nquery(&resolver, "validation.invalid", ns_c_in, ns_t_a, answer, sizeof(answer));
        res_nclose(&resolver);
        return result >= 0 ? 0 : -1;
    }
    if (!strcmp(operation, "io_uring")) {
#ifdef VALIDATION_LIBURING
        struct io_uring queue;
        if (io_uring_queue_init(2, &queue, 0)) return -1;
        struct io_uring_sqe *submission = io_uring_get_sqe(&queue);
        io_uring_prep_write(submission, descriptor, "x", 1, 0);
        if (io_uring_submit(&queue) < 0) return -1;
        struct io_uring_cqe *completion;
        int result = io_uring_wait_cqe(&queue, &completion);
        if (!result) result = completion->res == 1 ? 0 : -1;
        io_uring_queue_exit(&queue);
        return result;
#else
        errno = ENOSYS;
        return -1;
#endif
    }
    errno = EINVAL;
    return -1;
}

int main(int count, char **arguments)
{
    if (count == 2 && !strcmp(arguments[1], "--done")) return 0;
    if (count < 3) { fprintf(stderr, "operation scratch-path [--baseline]\n"); return 2; }
    int descriptor = open(arguments[2], O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (descriptor < 0 || ftruncate(descriptor, 4096)) return failed("setup");
    int baseline = count == 4 && !strcmp(arguments[3], "--baseline");
    if (!baseline && run_operation(arguments[1], descriptor, arguments[2])) return failed(arguments[1]);
    close(descriptor);
    return 0;
}