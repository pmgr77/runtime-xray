/**
 * @file    sensitive_pipe_chain_env.c
 * @brief   Regression fixture for sensitive pipe-chain flow with coincident
 *          environment and memory observations.
 *
 * The same exact sensitive value is:
 *
 *   - inherited through the environment,
 *   - written by the parent into pipe #1,
 *   - read and rewritten by a middle process into pipe #2,
 *   - read and retained in memory by a child process.
 *
 * The fixture validates that RuntimeXRay can distinguish value identity from
 * causal flow: environment and memory observations share the same fingerprint,
 * but only explicit pipe DataFlow edges may justify the pipe-chain narrative.
 *
 * @author  Peter Magram
 * @date    2026-10-12
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static ssize_t write_all(
    int fd,
    const void* buffer,
    size_t length)
{
    const unsigned char* data =
        (const unsigned char*)buffer;

    size_t offset = 0;

    while (offset < length) {
        const ssize_t n =
            write(fd, data + offset, length - offset);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        if (n == 0) {
            return -1;
        }

        offset += (size_t)n;
    }

    return (ssize_t)offset;
}

static ssize_t read_once_retry(
    int fd,
    void* buffer,
    size_t length)
{
    for (;;) {
        const ssize_t n =
            read(fd, buffer, length);

        if (n < 0 && errno == EINTR) {
            continue;
        }

        return n;
    }
}

int main(void)
{
    const char* secret = getenv("RXRAY_TEST_SECRET");

    if (!secret || secret[0] == '\0') {
        fprintf(
            stderr,
            "RXRAY_TEST_SECRET is not set\n");

        return 2;
    }

    const size_t secret_length = strlen(secret);

    if (secret_length == 0 ||
        secret_length >= 512) {
        return 3;
    }

    int first_pipe[2] = { -1 };
    int second_pipe[2] = { -1 };

    if (pipe(first_pipe) != 0) {
        perror("pipe first");
        return 4;
    }

    if (pipe(second_pipe) != 0) {
        perror("pipe second");
        return 5;
    }

    /*
     * Middle process:
     *
     *     first_pipe(read)
     *          ↓
     *       same bytes
     *          ↓
     *     second_pipe(write)
     */
    pid_t middle = fork();

    if (middle < 0) {
        perror("fork middle");
        return 6;
    }

    if (middle == 0) {
        close(first_pipe[1]);
        close(second_pipe[0]);

        char buffer[512] = {0};

        const ssize_t n =
            read_once_retry(
                first_pipe[0],
                buffer,
                sizeof(buffer));

        if (n <= 0) {
            _exit(20);
        }

        close(first_pipe[0]);

        if (write_all(
                second_pipe[1],
                buffer,
                (size_t)n) != n) {
            _exit(21);
        }

        close(second_pipe[1]);

        /*
         * Keep the received bytes resident briefly so the runtime scanner has
         * a stable opportunity to observe the middle-process copy as well.
         */
        sleep(1);

        _exit(0);
    }

    /*
     * Final child:
     *
     *     second_pipe(read)
     *          ↓
     *     resident memory
     */
    pid_t child = fork();

    if (child < 0) {
        perror("fork child");
        return 7;
    }

    if (child == 0) {
        close(first_pipe[0]);
        close(first_pipe[1]);
        close(second_pipe[1]);

        char buffer[512] = {0};

        const ssize_t n =
            read_once_retry(
                second_pipe[0],
                buffer,
                sizeof(buffer) - 1);

        if (n <= 0) {
            _exit(30);
        }

        close(second_pipe[0]);

        char* resident =
            malloc((size_t)n + 1);

        if (!resident) {
            _exit(31);
        }

        memcpy(resident, buffer, (size_t)n);

        resident[n] = '\0';

        /*
         * The child intentionally remains alive so --scan-memory can observe
         * both the inherited environment value and this independent resident
         * copy.
         */
        sleep(3);

        /*
         * Prevent the compiler from treating the resident copy as dead before
         * the scan window closes.
         */
        if (resident[0] == '\0') {
            free(resident);
            _exit(32);
        }

        free(resident);
        _exit(0);
    }

    /*
     * Parent only produces the first explicit transfer.
     */
    close(first_pipe[0]);
    close(second_pipe[0]);
    close(second_pipe[1]);

    if (write_all(
            first_pipe[1],
            secret,
            secret_length) !=
        (ssize_t)secret_length) {
        perror("write first pipe");
        return 8;
    }

    close(first_pipe[1]);

    int middle_status = 0;
    int child_status = 0;

    if (waitpid(
            middle,
            &middle_status,
            0) < 0) {
        perror("waitpid middle");
        return 9;
    }

    if (waitpid(
            child,
            &child_status,
            0) < 0) {
        perror("waitpid child");
        return 10;
    }

    if (!WIFEXITED(middle_status) ||
        WEXITSTATUS(middle_status) != 0) {
        return 11;
    }

    if (!WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0) {
        return 12;
    }

    return 0;
}