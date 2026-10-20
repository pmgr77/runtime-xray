/**
 * @file    fork_cow_mutation.c
 * @brief   Controlled read-sharing and bidirectional fork/COW regression fixture.
 *
 * Exercises two independent forked process pairs:
 *   1. Parent modifies a part of a MAP_PRIVATE anonymous page first.
 *   2. Child modifies the same part of its inherited mapping first.
 *
 * In both cases, both processes read the original page before any write,
 * verify isolation after the first write, then verify independent contents
 * after the second write. Synchronization lives on a DIFFERENT MAP_SHARED
 * mapping, so it cannot itself modify the private secret page.
 *
 * An optional /proc/<pid>/pagemap check verifies matching physical PFNs
 * after both reads and differing PFNs after the first COW write. Modern
 * kernels may mask PFNs without CAP_SYS_ADMIN; this is an explicit SKIP,
 * not an assertion that a physical page was observed.
 *
 * This fixture establishes Linux workload ground truth only. A separate
 * integration regression will validate RuntimeXRay's observations.
 *
 * Copyright 2026 Peter Magram
 * Licensed under the Apache License, Version 2.0 (see LICENSE).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
    kSecretOffset = 64,
    kPrefixLength = 9,
    kPasswordLength = 32,
    kMutationOffset = 8,
    kMutationLength = 8,
    kWaitSeconds = 30
};

enum WriterOrder { kParentFirst, kChildFirst };
enum SecretVariant { kOriginal, kParentEdited, kChildEdited };

struct SharedGate {
    _Atomic int parent_phase;
    _Atomic int child_phase;
};

static unsigned char expected_byte(size_t position, enum SecretVariant variant)
{
    static const unsigned char prefix[kPrefixLength] = {
        'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '='
    };

    if (position < kPrefixLength) {
        return prefix[position];
    }

    const size_t i = position - kPrefixLength;
    if (i >= kMutationOffset && i < kMutationOffset + kMutationLength) {
        if (variant == kParentEdited) return 'P';
        if (variant == kChildEdited) return 'C';
    }

    return (unsigned char)('a' + ((i * 11u + 7u) % 26u));
}

static void initialize_secret(volatile unsigned char *page)
{
    for (size_t i = 0; i < kPrefixLength + kPasswordLength; ++i) {
        page[kSecretOffset + i] = expected_byte(i, kOriginal);
    }
    page[kSecretOffset + kPrefixLength + kPasswordLength] = 0;
}

/* Modify only eight bytes WITHIN the password; all other bytes stay put. */
static void mutate_secret(volatile unsigned char *page, enum SecretVariant variant)
{
    for (size_t i = kMutationOffset; i < kMutationOffset + kMutationLength; ++i) {
        page[kSecretOffset + kPrefixLength + i] = expected_byte(kPrefixLength + i, variant);
    }
}

/* Volatile loads are real reads of the inherited virtual memory page. */
static int matches_secret(const volatile unsigned char *page, enum SecretVariant variant)
{
    unsigned mismatches = 0;

    for (size_t i = 0; i < kPrefixLength + kPasswordLength; ++i) {
        mismatches |= (unsigned)(page[kSecretOffset + i] != expected_byte(i, variant));
    }

    mismatches |= (unsigned)(page[kSecretOffset + kPrefixLength + kPasswordLength] != 0);
    return mismatches == 0;
}

/* Shared C11 atomics provide deterministic ordering without pipe read/write. */
static int wait_for_phase(_Atomic int *phase, int required)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    const time_t deadline = now.tv_sec + kWaitSeconds;
    unsigned long iterations = 0;

    while (atomic_load_explicit(phase, memory_order_acquire) < required) {
        /* Avoid enormous amounts of clock syscalls on unusual platforms. */
        if (++iterations % 1000000ul == 0ul) {
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
                now.tv_sec >= deadline) return 0;
        }
    }
    return 1;
}

/* Return 1 when a nonzero PFN is available, otherwise 0 (masked/denied). */
static int read_pfn(pid_t pid, const volatile unsigned char *page,
                    size_t page_size, uint64_t *pfn)
{
    /*
     * A remote scanner may trigger kernel-level COW unsharing
     * through FOLL_PIN before the application writes.
     *
     * Disable only physical PFN assertions for integration tests.
     * All content-isolation checks remain mandatory.
     */
    if (getenv("RXRAY_SKIP_PFN_CHECK") != NULL) {
        return 0;
    }

    char path[64];
    if (snprintf(path, sizeof(path), "/proc/%ld/pagemap", (long)pid) >= (int)sizeof(path)) {
        return 0;
    }

    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;

    const uint64_t virtual_page = (uint64_t)(uintptr_t)page / page_size;
    const off_t offset = (off_t)(virtual_page * sizeof(uint64_t));
    uint64_t entry = 0;
    const ssize_t size = pread(fd, &entry, sizeof(entry), offset);
    const int saved_errno = errno;
    close(fd);
    errno = saved_errno;

    /* bit 63: page present; bits 0-54: PFN (usually masked to zero). */
    if (size != (ssize_t)sizeof(entry) || (entry & (UINT64_C(1) << 63)) == 0) {
        return 0;
    }

    *pfn = entry & ((UINT64_C(1) << 55) - 1);
    return *pfn != 0;
}

/* If permitted by the OS, check shared PFNs before writing and split PFNs after. */
static int check_physical_pages(pid_t child, volatile unsigned char *page,
                                size_t page_size, int expect_shared,
                                int *pfn_available)
{
    uint64_t parent_pfn = 0, child_pfn = 0;
    const int have_both =
        read_pfn(getpid(), page, page_size, &parent_pfn) &&
        read_pfn(child, page, page_size, &child_pfn);

    if (!have_both) {
        *pfn_available = 0;
        return 1;
    }

    if (*pfn_available == 0)
        return 1;

    const int is_shared = (parent_pfn == child_pfn);
    fprintf(stderr,
            "PFN_CHECK stage=%s parent_pid=%ld child_pid=%ld "
            "virtual_address=%p parent_pfn=0x%" PRIx64
            " child_pfn=0x%" PRIx64 " equal=%d\n",
            expect_shared ? "before_write" : "after_first_write",
            (long)getpid(),
            (long)child,
            (void *)page,
            parent_pfn,
            child_pfn,
            parent_pfn == child_pfn);
    if (is_shared != expect_shared) {
        fprintf(stderr, "FAIL: physical PFN relationship unexpected (%s first write)\n",
                expect_shared ? "before" : "after");
        return 0;
    }
    return 1;
}

static void child_run(enum WriterOrder order, volatile unsigned char *page,
                      struct SharedGate *gate)
{
    /* First access after fork is a read: no COW write has occurred yet. */
    if (!matches_secret(page, kOriginal))
        _exit(10);
    atomic_store_explicit(&gate->child_phase, 1, memory_order_release);

    if (!wait_for_phase(&gate->parent_phase, 1))
        _exit(11);

    if (order == kParentFirst) {
        /* Parent wrote first; child MUST still see the old original. */
        if (!matches_secret(page, kOriginal))
            _exit(12);
        atomic_store_explicit(&gate->child_phase, 2, memory_order_release);
        if (!wait_for_phase(&gate->parent_phase, 2))
            _exit(13);

        mutate_secret(page, kChildEdited);
        if (!matches_secret(page, kChildEdited))
            _exit(14);
    } else {
        mutate_secret(page, kChildEdited);
        if (!matches_secret(page, kChildEdited))
            _exit(15);
        atomic_store_explicit(&gate->child_phase, 2, memory_order_release);
        if (!wait_for_phase(&gate->parent_phase, 2))
            _exit(16);

        /* Parent subsequently wrote its own mapping; ours is unchanged. */
        if (!matches_secret(page, kChildEdited))
            _exit(17);
    }

    atomic_store_explicit(&gate->child_phase, 3, memory_order_release);
    if (!wait_for_phase(&gate->parent_phase, 3))
        _exit(18);
    if (!matches_secret(page, kChildEdited))
        _exit(19);
    _exit(0);
}

static int run_one(enum WriterOrder order, int *all_pfns_verified)
{
    const long ps = sysconf(_SC_PAGESIZE);
    if (ps <= kSecretOffset + kPrefixLength + kPasswordLength + 1) {
        fputs("FAIL: unsupported system page size\n", stderr);
        return 1;
    }
    const size_t page_size = (size_t)ps;

    volatile unsigned char *page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct SharedGate *gate = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED || gate == MAP_FAILED) {
        perror("mmap");
        if (page != MAP_FAILED)
            munmap((void *)page, page_size);
        if (gate != MAP_FAILED)
            munmap(gate, page_size);
        return 1;
    }

    atomic_init(&gate->parent_phase, 0);
    atomic_init(&gate->child_phase, 0);
    if (!atomic_is_lock_free(&gate->parent_phase) ||
        !atomic_is_lock_free(&gate->child_phase)) {
        fputs("FAIL: shared atomics are not lock-free on this platform\n", stderr);
        munmap((void *)page, page_size);
        munmap(gate, page_size);
        return 1;
    }

    initialize_secret(page);
    const pid_t child = fork();
    if (child < 0) {
        perror("fork");
        munmap((void *)page, page_size);
        munmap(gate, page_size);
        return 1;
    }
    if (child == 0)
        child_run(order, page, gate);

    int ok = 1;
    int pfns_verified = 1;
    if (!wait_for_phase(&gate->child_phase, 1) || !matches_secret(page, kOriginal)) {
        fputs("FAIL: both processes did not read original page before writing\n", stderr);
        ok = 0;
        goto done;
    }

    if (!check_physical_pages(child, page, page_size, 1, &pfns_verified)) {
        ok = 0;
        goto done;
    }

    if (order == kParentFirst) {
        mutate_secret(page, kParentEdited);
        if (!matches_secret(page, kParentEdited)) {
            fputs("FAIL: parent first write did not take effect\n", stderr);
            ok = 0;
            goto done;
        }
        atomic_store_explicit(&gate->parent_phase, 1, memory_order_release);
        if (!wait_for_phase(&gate->child_phase, 2)) {
            fputs("FAIL: child lost original after parent COW write\n", stderr);
            ok = 0;
            goto done;
        }
        if (!check_physical_pages(child, page, page_size, 0, &pfns_verified)) {
            ok = 0;
            goto done;
        }
        atomic_store_explicit(&gate->parent_phase, 2, memory_order_release);
    } else {
        atomic_store_explicit(&gate->parent_phase, 1, memory_order_release);
        if (!wait_for_phase(&gate->child_phase, 2) || !matches_secret(page, kOriginal)) {
            fputs("FAIL: parent lost original after child COW write\n", stderr);
            ok = 0;
            goto done;
        }
        if (!check_physical_pages(child, page, page_size, 0, &pfns_verified)) {
            ok = 0;
            goto done;
        }
        mutate_secret(page, kParentEdited);
        if (!matches_secret(page, kParentEdited)) {
            fputs("FAIL: parent second write did not take effect\n", stderr);
            ok = 0;
            goto done;
        }
        atomic_store_explicit(&gate->parent_phase, 2, memory_order_release);
    }

    if (!wait_for_phase(&gate->child_phase, 3) ||
        !matches_secret(page, kParentEdited)) {
        fputs("FAIL: final parent memory differs from expected private copy\n", stderr);
        ok = 0;
    }

done:
    /* Release a blocked child even on failed assertions. */
    atomic_store_explicit(&gate->parent_phase, 3, memory_order_release);
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: child phase/validation failed (status=%d)\n", status);
        ok = 0;
    }
    munmap((void *)page, page_size);
    munmap(gate, page_size);

    if (ok) {
        puts(order == kParentFirst
             ? "PASS: parent-first COW preserves child's original, then isolates both edits"
             : "PASS: child-first COW preserves parent's original, then isolates both edits");
        if (!pfns_verified) *all_pfns_verified = 0;
    }
    return !ok;
}

int main(void)
{
    int all_pfns_verified = 1;
    if (run_one(kParentFirst, &all_pfns_verified) != 0) return 1;
    if (run_one(kChildFirst, &all_pfns_verified) != 0) return 1;

    if (all_pfns_verified) {
        puts("PASS: physical PFN shared after reads; PFNs diverged after first COW write");
    } else {
        puts("SKIP: physical PFN identity check (pagemap inaccessible or PFNs masked)");
    }
    return 0;
}
