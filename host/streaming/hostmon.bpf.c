#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "hostmon.h"

#ifndef AF_INET
#define AF_INET 2
#endif

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* GENERIC SYSCALL STREAM */
SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct event *e;
    __u64 pid_tgid;
    unsigned long id;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_SYSCALL;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    id = ctx->args[1];
    e->syscall_id = (unsigned int)id;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* EXECVE */
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename;
    __u64 pid_tgid;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_EXEC;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->path1, sizeof(e->path1), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* OPENAT */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename;
    __u64 pid_tgid;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_OPEN;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->path1, sizeof(e->path1), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* RENAMEAT */
SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *oldname;
    const char *newname;
    __u64 pid_tgid;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_RENAME;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    oldname = (const char *)ctx->args[1];
    newname = (const char *)ctx->args[3];

    bpf_probe_read_user_str(e->path1, sizeof(e->path1), oldname);
    bpf_probe_read_user_str(e->path2, sizeof(e->path2), newname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* UNLINKAT */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *pathname;
    __u64 pid_tgid;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_UNLINK;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->path1, sizeof(e->path1), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* CONNECT */
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    __u64 pid_tgid;
    const struct sockaddr *uservaddr;
    __u16 family = 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_CONNECT;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    uservaddr = (const struct sockaddr *)ctx->args[1];
    if (!uservaddr) {
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in sa4 = {};
        bpf_probe_read_user(&sa4, sizeof(sa4), uservaddr);

        e->addr = sa4.sin_addr.s_addr;
        e->port = sa4.sin_port;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}