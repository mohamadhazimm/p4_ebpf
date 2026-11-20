#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "filemon.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename;
    __u64 pid_tgid;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_OPEN;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->path1, sizeof(e->path1), filename);
    e->path2[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

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

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *pathname;
    __u64 pid_tgid;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_UNLINK;
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->path1, sizeof(e->path1), pathname);
    e->path2[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}