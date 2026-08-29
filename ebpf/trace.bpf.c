/**
 * @file    trace.bpf.c
 * @brief   eBPF program for syscall tracing using raw_syscalls tracepoints.
 *
 * @author  Peter Magram
 * @date    2026-08-29
 *
 * This file is part of the RuntimeXRay project.
 * The eBPF program itself is licensed under GPL-2.0 (see LICENSE[] below).
 * The surrounding project is Apache-2.0.
 *
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

// Copyright 2026 Peter Magram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ARGS 6

struct syscall_event {
    __u32 pid;   // tgid
    __u32 tid;   // thread ID
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} pid_filter SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} enter_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} exit_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} clone_exit_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_reserve_fail SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_ctx *ctx) {
    __u32 zero = 0;
    __u64 *cnt = bpf_map_lookup_elem(&enter_counter, &zero);
    if (cnt) (*cnt)++;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xffffffff;

    __u32 *target = bpf_map_lookup_elem(&pid_filter, &pid);
    if (!target) return 0;

    if (*target != 0 && pid != *target)
        return 0;

    struct syscall_event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid = pid;
    ev->tid = tid;
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
    __u64 *cnt = bpf_map_lookup_elem(&exit_counter, &zero);
    if (cnt) (*cnt)++;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xffffffff;

    __u32 *target = bpf_map_lookup_elem(&pid_filter, &pid);
    if (!target) return 0;

    if (*target != 0 && pid != *target)
        return 0;

    // Count clone/clone3 exits (ARM64: 220, 435; x86_64: 56, 435)
    if (ctx->id == 220 || ctx->id == 435) {
        __u32 zero = 0;
        __u64 *cnt = bpf_map_lookup_elem(&clone_exit_counter, &zero);
        if (cnt) (*cnt)++;
    }

    // Try to reserve ring buffer
    struct syscall_event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        __u32 zero = 0;
        __u64 *fail = bpf_map_lookup_elem(&ringbuf_reserve_fail, &zero);
        if (fail) (*fail)++;
        return 0;
    }

    ev->pid = pid;
    ev->tid = tid;
    ev->syscall_id = ctx->id;
    ev->is_entry = 0;
    ev->ret = ctx->ret;
    for (int i = 0; i < MAX_ARGS; i++)
        ev->args[i] = 0;
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";