// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ARGS 6

struct syscall_event {
    __u32 pid;
    __u32 syscall_id;
    __u64 args[MAX_ARGS];
    __u64 ret;
    __u8 is_entry;
};

// Tracepoint context layouts for raw_syscalls
struct sys_enter_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[MAX_ARGS];
};

struct sys_exit_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    long ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pid_filter SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_ctx *ctx) {
    __u32 zero = 0;
    __u32 *target = bpf_map_lookup_elem(&pid_filter, &zero);
    if (!target) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (*target != 0 && pid != *target)
        return 0;

    struct syscall_event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid = pid;
    ev->syscall_id = ctx->id;
    ev->is_entry = 1;
    for (int i = 0; i < MAX_ARGS; i++)
        ev->args[i] = ctx->args[i];
    ev->ret = 0;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct sys_exit_ctx *ctx) {
    __u32 zero = 0;
    __u32 *target = bpf_map_lookup_elem(&pid_filter, &zero);
    if (!target) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (*target != 0 && pid != *target)
        return 0;

    struct syscall_event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid = pid;
    ev->syscall_id = ctx->id;
    ev->is_entry = 0;
    ev->ret = ctx->ret;
    for (int i = 0; i < MAX_ARGS; i++)
        ev->args[i] = 0;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";