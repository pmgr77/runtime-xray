/**
 * @file    fd_alias_flow.c
 * @brief   Test program for pipe resource identity across duplicated FDs.
 *
 * Creates a pipe, duplicates both pipe endpoints with dup(), closes the
 * original descriptors, then transfers a known sensitive value through
 * the duplicated descriptors. Used to verify that RuntimeXRay preserves
 * pipe resource identity and endpoint roles across FD aliases and can
 * derive a DataFlow edge from the aliased write to the aliased read.
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    int pipefd[2];

    if (pipe(pipefd) != 0) {
        perror("pipe");
        return 1;
    }

    /*
     * Duplicate both endpoints.
     *
     * Expected RuntimeXRay state:
     *
     *   pipefd[0]   -> resource X, role=read
     *   read_alias  -> resource X, role=read
     *
     *   pipefd[1]   -> resource X, role=write
     *   write_alias -> resource X, role=write
     */
    int read_alias = dup(pipefd[0]);
    if (read_alias < 0) {
        perror("dup read");
        close(pipefd[0]);
        close(pipefd[1]);
        return 2;
    }

    int write_alias = dup(pipefd[1]);
    if (write_alias < 0) {
        perror("dup write");
        close(read_alias);
        close(pipefd[0]);
        close(pipefd[1]);
        return 3;
    }

    /*
     * Deliberately close the original descriptors.
     *
     * The aliases must continue referring to the same pipe resource.
     */
    close(pipefd[0]);
    close(pipefd[1]);

    char payload[] =
        "password=RXRAY_FD_ALIAS_X7kQ2mNv8pLr4ZtW9yBc3";

    const size_t payload_len = sizeof(payload) - 1;

    ssize_t written = write(write_alias, payload, payload_len);
    if (written != (ssize_t)payload_len) {
        perror("write");
        close(read_alias);
        close(write_alias);
        return 4;
    }

    char buffer[128] = {0};

    ssize_t received = read(read_alias, buffer, sizeof(buffer));
    if (received != written) {
        fprintf(stderr,
                "read length mismatch: written=%zd received=%zd\n",
                written,
                received);

        close(read_alias);
        close(write_alias);
        return 5;
    }

    if (memcmp(payload, buffer, payload_len) != 0) {
        fprintf(stderr, "payload mismatch\n");

        close(read_alias);
        close(write_alias);
        return 6;
    }

    /*
     * Avoid leaving the synthetic credential around unnecessarily.
     */
    memset(payload, 0, sizeof(payload));
    memset(buffer, 0, sizeof(buffer));

    close(read_alias);
    close(write_alias);

    return 0;
}