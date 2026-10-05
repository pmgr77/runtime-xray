/**
 * @file    thread_lifecycle_test.c
 * @brief   Test program for process-instance lifetime across thread exit.
 *
 * Creates a worker thread using clone() with CLONE_THREAD. The process
 * leader exits while the worker remains alive and later performs a syscall.
 * Used to verify that RuntimeXRay preserves the same process instance while
 * any thread belonging to that process is still active.
 *
 * @author  Peter Magram
 * @date    2026-10-05
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

#define _GNU_SOURCE

/*
 * Process-instance lifetime regression fixture.
 *
 * A thread-group leader creates a CLONE_THREAD task and then exits with
 * SYS_exit, leaving the worker alive.
 *
 * The worker deliberately performs no syscall for a while. RuntimeXRay
 * must keep the original TGID mapped to the same process_instance_id
 * throughout the lifetime of the surviving worker.
 *
 * Expected invariant:
 *
 *     one Linux TGID lifetime
 *         ->
 *     one RuntimeXRay process_instance_id
 */

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define STACK_SIZE (1024 * 1024)

static int worker(void* arg)
{
    (void)arg;

    /*
     * Stay entirely in userspace for a while.
     *
     * This gives the original thread-group leader enough time to exit before
     * this worker generates its first traced syscall.
     */
    for (volatile unsigned long i = 0; i < 50000000UL; ++i) {
    }

    static const char msg[] = "surviving worker\n";

    if (write(STDOUT_FILENO, msg, sizeof(msg) - 1) < 0) {
        return 2;
    }

    return 0;
}

int main(void)
{
    void* stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        return 2;
    }

    void* stack_top = (char*)stack + STACK_SIZE;

    const int flags =
        CLONE_VM |
        CLONE_FS |
        CLONE_FILES |
        CLONE_SIGHAND |
        CLONE_THREAD |
        CLONE_SYSVSEM;

    pid_t tid = clone(worker, stack_top, flags, NULL);

    if (tid < 0) {
        perror("clone");
        return 3;
    }

    /*
     * Deliberately terminate only the leader thread.
     *
     * SYS_exit is important here; exit_group would kill the worker too.
     */
    syscall(SYS_exit, 0);

    return 0;
}