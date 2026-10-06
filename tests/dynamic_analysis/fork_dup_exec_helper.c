/**
 * @file    fork_dup_exec_helper.c
 * @brief   Exec-side fixture for inherited pipe resource lineage.
 *
 * Reads a sensitive value from STDIN_FILENO after the parent fixture has
 * established the descriptor through pipe(), fork(), dup2(), and exec().
 *
 * RuntimeXRay should identify the read as using the same pipe resource that
 * the original parent process wrote to before this program was exec'd.
 *
 * @author  Peter Magram
 * @date    2026-10-06
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
    char buffer[128] = {0};

    ssize_t n = read(STDIN_FILENO, buffer, sizeof(buffer));

    if (n < 0) {
        perror("read");
        return 1;
    }

    if (n == 0) {
        fprintf(stderr, "unexpected EOF\n");
        return 2;
    }

    /*
     * Validate the fixture itself.
     *
     * We do not print the credential; the test only needs it to remain
     * byte-identical across the pipe boundary.
     */
    static const char prefix[] = "password=RXRAY_FORK_DUP_EXEC_";

    if ((size_t)n < sizeof(prefix) - 1 ||
        memcmp(buffer, prefix, sizeof(prefix) - 1) != 0) {
        fprintf(stderr, "unexpected payload\n");
        return 3;
    }

    /*
     * Clear the synthetic value before exiting.
     */
    memset(buffer, 0, sizeof(buffer));

    return 0;
}