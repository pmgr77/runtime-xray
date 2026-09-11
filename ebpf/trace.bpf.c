/**
 * @file    trace.bpf.c
 * @brief   eBPF program for syscall tracing using raw_syscalls tracepoints.
 *
 * Memory-capture policy
 * ---------------------
 * The userspace side of the tracer cannot read target memory reliably after
 * a syscall has completed: the target keeps running and may reuse or free
 * the buffer before the read arrives. This program therefore performs the
 * memory reads itself, at tracepoint time, and ships the bytes in the
 * ring-buffer event. Userspace consumers get valid bytes regardless of how
 * slow they are.
 *
 * What is captured and when:
 *   - open / openat / execve / execveat : path string, on entry
 *   - connect                           : sockaddr bytes, on entry
 *   - write / sendto                    : payload bytes, on entry
 *   - writev                            : first iovec's payload, on entry
 *   - read / recvfrom                   : payload bytes, on exit, using the
 *                                         buffer pointer stashed on entry
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

#define MAX_ARGS      6
#define MAX_PATH      256
#define MAX_PAYLOAD   256
#define MAX_SOCKADDR  128

#ifndef _STRUCT_IOVEC
#define _STRUCT_IOVEC
/* Matches the kernel/userspace ABI for struct iovec:
 *   void  *iov_base;
 *   size_t iov_len;
 * On both x86_64 and arm64, sizeof(size_t) == 8, so the struct
 * is 16 bytes with no padding. */
struct iovec {
    __u64 iov_base;     /* Starting address */
    __u64 iov_len;      /* Number of bytes to transfer */
};
#endif

/* ------------------------------------------------------------------ */
/* Event layout sent to userspace                                     */
/* ------------------------------------------------------------------ */
struct syscall_event {
    __u32 pid;   // tgid
    __u32 tid;   // thread ID
    __u32 syscall_id;
    __u64 args[MAX_ARGS];
    __u64 ret;
    __u8 is_entry;
    
     /* Which captured fields are populated in this event */
    __u8  has_path;
    __u8  has_sockaddr;
    __u8  has_payload;
    __u32 payload_len;          /* valid iff has_payload */

    /* Captured bytes (zero-filled when not applicable) */
    char  path[MAX_PATH];
    __u8  sockaddr[MAX_SOCKADDR];
    __u8  payload[MAX_PAYLOAD];
};

// Tracepoint context layouts for raw_syscalls
struct sys_enter_ctx {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           id;
    unsigned long  args[MAX_ARGS];
};

struct sys_exit_ctx {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           id;
    long           ret;
};

/* ------------------------------------------------------------------ */
/* Maps                                                               */
/* ------------------------------------------------------------------ */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);   /* 1 MB: sized for full-payload events */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} pid_filter SEC(".maps");

/* Stash read()/recvfrom() buffer pointers on entry, consume on exit.
 * Key: TID. Value: userspace buffer address from syscall entry. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} pending_read_buf SEC(".maps");

/* Counters kept from the original program for debug visibility. */
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

/* ------------------------------------------------------------------ */
/* Syscall classification                                             */
/* ------------------------------------------------------------------ */

/*
 * Syscall numbers are given for x86_64 and ARM64. A single BPF object
 * covers both; the comparisons are cheap and the verifier folds them.
 */

static __always_inline int is_open_like(__u32 id) {
    return id == 2     /* open       (x86_64) */
        || id == 257   /* openat     (x86_64) */
        || id == 56;   /* openat     (arm64)  */
}

static __always_inline int is_exec_like(__u32 id) {
    return id == 59    /* execve      (x86_64) */
        || id == 322   /* execveat    (x86_64) */
        || id == 221   /* execve      (arm64)  */
        || id == 266;  /* execveat    (arm64)  */
}

static __always_inline int is_connect(__u32 id) {
    return id == 42    /* connect     (x86_64) */
        || id == 203;  /* connect     (arm64)  */
}

static __always_inline int is_write_like(__u32 id) {
    return id == 1     /* write       (x86_64) */
        || id == 20    /* writev      (x86_64) */
        || id == 44    /* sendto      (x86_64) */
        || id == 64    /* write       (arm64)  */
        || id == 66    /* writev      (arm64)  */
        || id == 206;  /* sendto      (arm64)  */
}

static __always_inline int is_read_like(__u32 id) {
    return id == 0     /* read        (x86_64) */
        || id == 45    /* recvfrom    (x86_64) */
        || id == 63    /* read        (arm64)  */
        || id == 207;  /* recvfrom    (arm64)  */
}

/*
 * Return the argument slot that holds the path pointer for an
 * open/openat/execve/execveat call:
 *   open(path, flags, ...)              path is arg0
 *   openat(dirfd, path, flags, ...)     path is arg1
 *   execve(path, argv, envp)            path is arg0
 *   execveat(dirfd, path, argv, ...)    path is arg1
 */
static __always_inline int path_arg_index(__u32 id) {
    if (id == 2)  return 0;   /* open     (x86_64) */
    if (id == 59) return 0;   /* execve   (x86_64) */
    if (id == 221) return 0;  /* execve   (arm64)  */
    return 1;                 /* openat / execveat */
}

/* ------------------------------------------------------------------ */
/* Entry-side capture helpers                                          */
/* ------------------------------------------------------------------ */

static __always_inline void fill_path(struct syscall_event *ev,
                                      struct sys_enter_ctx *ctx)
{
    int slot = path_arg_index((__u32)ctx->id);
    const char *upath = (const char *)ctx->args[slot];
    if (!upath)
        return;
    long n = bpf_probe_read_user_str(ev->path, sizeof(ev->path), upath);
    if (n > 0)
        ev->has_path = 1;
}

static __always_inline void fill_sockaddr(struct syscall_event *ev,
                                          struct sys_enter_ctx *ctx)
{
    const void *usa = (const void *)ctx->args[1];   /* connect(sockfd, addr, len) */
    __u64 addrlen = ctx->args[2];
    if (!usa || addrlen == 0)
        return;
    __u32 n = addrlen > MAX_SOCKADDR ? MAX_SOCKADDR : (__u32)addrlen;
    long rc = bpf_probe_read_user(ev->sockaddr, n, usa);
    if (rc == 0) {
        ev->has_sockaddr = 1;
        // (payload_len is not used for sockaddr; caller knows addrlen from arg2)
    }
}

static __always_inline void fill_payload_from_buf(struct syscall_event *ev,
                                                  const void *buf,
                                                  __u64 count)
{
    if (!buf || count == 0)
        return;
    __u32 n = count > MAX_PAYLOAD ? MAX_PAYLOAD : (__u32)count;
    long rc = bpf_probe_read_user(ev->payload, n, buf);
    if (rc == 0) {
        ev->has_payload = 1;
        ev->payload_len = n;
    }
}

static __always_inline void fill_payload_on_entry(struct syscall_event *ev,
                                                  struct sys_enter_ctx *ctx)
{
    __u32 id = (__u32)ctx->id;

    /* write(fd, buf, count)         -> buf=arg1, count=arg2
     * sendto(sockfd, buf, len, ...) -> buf=arg1, count=arg2  */
    if (id == 1 || id == 44 || id == 64 || id == 206) {
        fill_payload_from_buf(ev,
                              (const void *)ctx->args[1],
                              ctx->args[2]);
        return;
    }

    /* writev(fd, iov, iovcnt) -> read first iovec only.
     * Multi-iovec secrets beyond the first are not captured here. */
    if (id == 20 || id == 66) {
        struct iovec iov;
        const void *uiov = (const void *)ctx->args[1];
        if (!uiov)
            return;
        if (bpf_probe_read_user(&iov, sizeof(iov), uiov) != 0)
            return;
        fill_payload_from_buf(ev, (const void *)iov.iov_base, iov.iov_len);
        return;
    }
}

/* ------------------------------------------------------------------ */
/* Programs                                                           */
/* ------------------------------------------------------------------ */

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct sys_enter_ctx *ctx) {
    __u32 zero = 0;
    __u64 *cnt = bpf_map_lookup_elem(&enter_counter, &zero);
    if (cnt) (*cnt)++;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xffffffff;

    __u32 *target = bpf_map_lookup_elem(&pid_filter, &pid);
    if (!target)
        return 0;
    if (*target != 0 && pid != *target)
        return 0;

    __u32 id = (__u32)ctx->id;
    
    /* Stash read/recvfrom buffer pointer so the exit event can use it. */
    if (is_read_like(id)) {
        __u64 buf = ctx->args[1];
        if (buf)
            bpf_map_update_elem(&pending_read_buf, &tid, &buf, BPF_ANY);
    }

    struct syscall_event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    /* Zero-init the header portion we always fill; leave the captured
     * buffers as-is and rely on the has_* flags. */
    ev->pid        = pid;
    ev->tid        = tid;
    ev->syscall_id = id;
    ev->is_entry   = 1;
    ev->ret        = 0;
    ev->has_path     = 0;
    ev->has_sockaddr = 0;
    ev->has_payload  = 0;
    ev->payload_len  = 0;
    for (int i = 0; i < MAX_ARGS; i++)
        ev->args[i] = ctx->args[i];

    /* Capture userspace bytes now, while the target is on this CPU. */
    if (is_open_like(id) || is_exec_like(id)) {
        fill_path(ev, ctx);
    } else if (is_connect(id)) {
        fill_sockaddr(ev, ctx);
    } else if (is_write_like(id)) {
        fill_payload_on_entry(ev, ctx);
    }
    
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct sys_exit_ctx *ctx) {
    __u32 zero = 0;
    __u64 *cnt = bpf_map_lookup_elem(&exit_counter, &zero);
    if (cnt)
        (*cnt)++;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u32 *target = bpf_map_lookup_elem(&pid_filter, &pid);
    if (!target) 
        return 0;
    if (*target != 0 && pid != *target)
        return 0;

    __u32 id = (__u32)ctx->id;

    // Count clone/clone3 exits (ARM64: 220, 435; x86_64: 56, 435)
    if (id == 220 || id == 435) {
        __u64 *cnt = bpf_map_lookup_elem(&clone_exit_counter, &zero);
        if (cnt)
            (*cnt)++;
    }

    // Try to reserve ring buffer
    struct syscall_event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        __u64 *fail = bpf_map_lookup_elem(&ringbuf_reserve_fail, &zero);
        if (fail)
            (*fail)++;
        return 0;
    }

    ev->pid        = pid;
    ev->tid        = tid;
    ev->syscall_id = id;
    ev->is_entry   = 0;
    ev->ret        = ctx->ret;
    ev->has_path     = 0;
    ev->has_sockaddr = 0;
    ev->has_payload  = 0;
    ev->payload_len  = 0;
    for (int i = 0; i < MAX_ARGS; i++)
        ev->args[i] = 0;

    /*
     * read / recvfrom: consume the buffer pointer stashed on entry,
     * and read the returned byte count worth of data. The ret value is
     * the authoritative length: short reads are honored.
     */
    if (is_read_like(id) && ctx->ret > 0) {
        __u64 *bufp = bpf_map_lookup_elem(&pending_read_buf, &tid);
        if (bufp && *bufp) {
            __u32 n = (__u32)ctx->ret;
            if (n > MAX_PAYLOAD)
                n = MAX_PAYLOAD;

            // ctx->ret is a signed long. The cap above compiles to a signed
            // comparison, so the verifier cannot prove n is non-negative and
            // rejects bpf_probe_read_user's size argument. Masking with a
            // constant bounds n to [0, 0xffff]; the mask is wider than
            // MAX_PAYLOAD so it does not change n's value.
            n &= 0xffff;
            
            long rc = bpf_probe_read_user(ev->payload, n, (void *)*bufp);
            if (rc == 0) {
                ev->has_payload = 1;
                ev->payload_len = n;
            }
        }
        bpf_map_delete_elem(&pending_read_buf, &tid);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";