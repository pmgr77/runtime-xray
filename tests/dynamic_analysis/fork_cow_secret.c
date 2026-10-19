/**
 * @file    fork_cow_secret.c
 * @brief   Controlled fork/COW fixture for initial process-memory inspection.
 *
 * The child inherits a private anonymous mapping containing a synthetic
 * password marker. The parent erases its own mapping after fork, then releases
 * the child through a separate shared mapping. The child's first syscall after
 * release is getpid(); it never opens, reads, or sends the credential.
 *
 * This fixture establishes ground truth about the workload. It does not, by
 * itself, assert anything about RuntimeXRay's observations or lineage graph.
 *
 * @author  Peter Magram
 * @date    2026-10-19
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

// Copyright 2026 Peter Magram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE
#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/** Length of the synthetic marker excluding its terminating NUL. */
enum { kPrefixLength = 9, kSuffixLength = 32, kSecretLength = 41 };

/** Shared only for parent-to-child synchronization, never for the secret. */
struct SharedGate {
    _Atomic int released;
};

/**
 * Populate the secret entirely at runtime. The complete credential is never
 * an argv/env value or a contiguous constant in the executable image.
 */
static void make_secret(char* destination)
{
    static const char prefix[kPrefixLength] = {
        'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '='
    };
    static const char alphabet[] = "0123456789abcdef";

    memcpy(destination, prefix, kPrefixLength);

    for (size_t i = 0; i < kSuffixLength; ++i) {
        destination[kPrefixLength + i] = alphabet[(i * 7U + 3U) & 15U];
    }

    destination[kSecretLength] = '\0';
}

/** Prevent the compiler from optimizing away the parent's secret erasure. */
static void erase_secret(char* destination)
{
    volatile unsigned char* bytes = (volatile unsigned char*)destination;

    for (size_t i = 0; i <= kSecretLength; ++i) {
        bytes[i] = 0;
    }
}

/**
 * Validate the inherited memory without constructing a second secret copy.
 * The child has no read(), recvfrom(), sendto(), or write() calls here.
 */
static int secret_is_intact(const char* secret)
{
    static const char prefix[kPrefixLength] = {
        'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '='
    };
    static const char alphabet[] = "0123456789abcdef";

    if (memcmp(secret, prefix, kPrefixLength) != 0) {
        return 0;
    }

    for (size_t i = 0; i < kSuffixLength; ++i) {
        if (secret[kPrefixLength + i] != alphabet[(i * 7U + 3U) & 15U]) {
            return 0;
        }
    }

    return secret[kSecretLength] == '\0';
}

int main(void)
{
    const long page_size = sysconf(_SC_PAGESIZE);

    if (page_size < kSecretLength + 1) {
        fputs("FAIL: unsupported page size\n", stderr);
        return 1;
    }

    char* secret = mmap(NULL, (size_t)page_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct SharedGate* gate = mmap(NULL, (size_t)page_size,
                                   PROT_READ | PROT_WRITE,
                                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (secret == MAP_FAILED || gate == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    atomic_init(&gate->released, 0);
    make_secret(secret);

    const pid_t child = fork();

    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        // Deliberately perform no syscalls until the parent has erased its
        // private copy. A separate MAP_SHARED page synchronizes the processes.
        while (atomic_load_explicit(&gate->released, memory_order_acquire) == 0) {
            // Spin briefly. The parent only erases 42 bytes before releasing.
        }

        if (!secret_is_intact(secret)) {
            _exit(2);
        }

        // First child syscall after the release is a deterministic inspection
        // opportunity. The child never consumes or transmits the credential.
        (void)syscall(SYS_getpid);
        _exit(0);
    }

    // MAP_PRIVATE creates distinct COW mappings after fork. This erases only
    // the parent's address space, preserving the inherited child contents.
    erase_secret(secret);
    atomic_store_explicit(&gate->released, 1, memory_order_release);

    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        perror("waitpid");
        return 1;
    }

    munmap(secret, (size_t)page_size);
    munmap(gate, (size_t)page_size);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: child did not retain private mapping (status=%d)\n", status);
        return 1;
    }

    puts("PASS: child retained private secret after parent erased its copy");
    return 0;
}
