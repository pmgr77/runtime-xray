/**
 * @file    pipe_flow.c
 * @brief   Test program for cross-process sensitive-data flow through a pipe.
 *
 * Creates a pipe and forks a child process. The parent writes a known
 * sensitive value to the pipe, while the child reads it, retains a copy
 * in memory, and writes the same value to stdout. Used to validate pipe
 * resource identity and cross-process data-flow lineage.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    int pipefd[2];

    if (pipe(pipefd) != 0) {
        perror("pipe");
        return 2;
    }

    pid_t child = fork();

    if (child < 0) {
        perror("fork");
        return 3;
    }

    if (child == 0) {
        close(pipefd[1]);

        char buf[256] = {0};

        ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
        if (n <= 0) {
            perror("read");
            return 4;
        }

        close(pipefd[0]);

        /*
         * Independent resident copy so --scan-memory has a stable target.
         */
        char* resident = malloc((size_t)n + 1);
        if (!resident) {
            return 5;
        }

        memcpy(resident, buf, (size_t)n);
        resident[n] = '\0';

        /*
         * Output-side occurrence, but deliberately not a socket.
         */
        if (write(STDOUT_FILENO, resident, (size_t)n) != n) {
            perror("write");
            free(resident);
            return 6;
        }

        sleep(3);

        free(resident);
        return 0;
    }

    close(pipefd[0]);

    /*
     * Build the full credential at runtime rather than keeping one full
     * constant string in .rodata.
     */
    char payload[128] = {0};

    snprintf(
        payload,
        sizeof(payload),
        "password=%s%s",
        "RXRAY_PIPE_",
        "X7kQ2mNv8pLr4ZtW9yBc3");

    const size_t len = strlen(payload);

    ssize_t written = write(pipefd[1], payload, len);

    /*
     * Don't deliberately keep another long-lived parent copy around.
     */
    memset(payload, 0, sizeof(payload));

    close(pipefd[1]);

    if (written != (ssize_t)len) {
        perror("write");
        return 7;
    }

    int status = 0;

    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return 8;
    }

    if (!WIFEXITED(status)) {
        return 9;
    }

    return WEXITSTATUS(status);
}