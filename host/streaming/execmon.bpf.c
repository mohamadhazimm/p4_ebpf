#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execmon.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename;
    __u64 pid_tgid;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}