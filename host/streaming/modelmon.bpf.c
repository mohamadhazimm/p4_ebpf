#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "modelmon.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} tracked_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_lost SEC(".maps");

static __always_inline bool is_tracked(void)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    return bpf_map_lookup_elem(&tracked_tgids, &tgid) != 0;
}

static __always_inline void emit_event(__u32 type, __u64 value)
{
    __u32 key = 0;
    struct model_event *event;
    __u64 *lost;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        lost = bpf_map_lookup_elem(&ringbuf_lost, &key);
        if (lost)
            (*lost)++;
        return;
    }

    event->type = type;
    event->value = value;
    bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/sched/sched_process_fork")
int track_child(struct trace_event_raw_sched_process_fork *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 parent_tgid = pid_tgid >> 32;
    __u32 child_pid = ctx->child_pid;
    __u8 value = 1;

    if (bpf_map_lookup_elem(&tracked_tgids, &parent_tgid))
        bpf_map_update_elem(&tracked_tgids, &child_pid, &value, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int count_connect(void *ctx)
{
    (void)ctx;
    if (is_tracked())
        emit_event(MODEL_EVENT_CONNECT, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int count_openat_success(struct trace_event_raw_sys_exit *ctx)
{
    if (is_tracked() && ctx->ret >= 0)
        emit_event(MODEL_EVENT_OPENAT, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int count_openat2_success(struct trace_event_raw_sys_exit *ctx)
{
    if (is_tracked() && ctx->ret >= 0)
        emit_event(MODEL_EVENT_OPENAT2, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int count_sendto(void *ctx)
{
    (void)ctx;
    if (is_tracked())
        emit_event(MODEL_EVENT_SENDTO, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int count_socket(void *ctx)
{
    (void)ctx;
    if (is_tracked())
        emit_event(MODEL_EVENT_SOCKET, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int count_write_success(struct trace_event_raw_sys_exit *ctx)
{
    if (is_tracked() && ctx->ret > 0)
        emit_event(MODEL_EVENT_WRITE, ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int count_pwrite64_success(struct trace_event_raw_sys_exit *ctx)
{
    if (is_tracked() && ctx->ret > 0)
        emit_event(MODEL_EVENT_PWRITE64, ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int count_writev_success(struct trace_event_raw_sys_exit *ctx)
{
    if (is_tracked() && ctx->ret > 0)
        emit_event(MODEL_EVENT_WRITEV, ctx->ret);
    return 0;
}
