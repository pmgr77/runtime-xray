/**
 * @file    fork_dup_exec_parent.c
 * @brief   Parent-side fixture for pipe lineage across fork, dup2, and exec.
 *
 * Creates a pipe and forks a child. The child remaps the pipe's read end
 * onto STDIN_FILENO using dup2(), closes the original descriptor, and
 * execs fork_dup_exec_helper. The parent writes a known sensitive value
 * through the pipe.
 *
 * The expected RuntimeXRay resource path is:
 *
 *   parent pipe write FD
 *          |
 *          | fork inheritance
 *          v
 *   child pipe read FD
 *          |
 *          | dup2(read_fd, STDIN_FILENO)
 *          v
 *   child fd 0
 *          |
 *          | exec(helper)
 *          v
 *   helper read(fd 0)
 *
 * The parent write and helper read must retain the same pipe resource_id.
 *
 * Usage:
 *   fork_dup_exec_parent <helper_path>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <helper_path>\n", argv[0]);
        return 2;
    }

    const char *helper_path = argv[1];

    int pipefd[2];

    if (pipe(pipefd) != 0) {
        perror("pipe");
        return 3;
    }

    pid_t child = fork();

    if (child < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return 4;
    }

    if (child == 0) {
        /*
         * Child consumes the pipe.
         *
         * It does not need the write endpoint.
         */
        close(pipefd[1]);

        /*
         * Remap the pipe read endpoint onto stdin.
         *
         * RuntimeXRay should preserve the pipe resource identity:
         *
         *   pipefd[0] -> resource X, read
         *   fd 0      -> resource X, read
         */
        if (dup2(pipefd[0], STDIN_FILENO) < 0) {
            perror("dup2");
            _exit(10);
        }

        /*
         * The original descriptor is no longer needed.
         *
         * This deliberately ensures that the helper can only access the
         * pipe through the duplicated fd 0 binding.
         */
        if (pipefd[0] != STDIN_FILENO) {
            close(pipefd[0]);
        }

        /*
         * Exec must not destroy the resource binding for fd 0.
         *
         * The helper should therefore read the same pipe resource after
         * RuntimeXRay advances the executable generation.
         */
        execl(helper_path, helper_path, (char *)NULL);

        perror("execl");
        _exit(11);
    }

    /*
     * Parent produces the sensitive value.
     *
     * It does not need the read endpoint.
     */
    close(pipefd[0]);

    char payload[] =
        "password=RXRAY_FORK_DUP_EXEC_X7kQ2mNv8pLr4ZtW9yBc3";

    const size_t payload_len = sizeof(payload) - 1;

    ssize_t written = write(pipefd[1], payload, payload_len);

    if (written != (ssize_t)payload_len) {
        if (written < 0) {
            perror("write");
        } else {
            fprintf(stderr,
                    "short write: expected=%zu actual=%zd\n",
                    payload_len,
                    written);
        }

        close(pipefd[1]);
        waitpid(child, NULL, 0);
        return 5;
    }

    /*
     * Closing the final parent write endpoint also gives the helper EOF
     * after it consumes the payload.
     */
    close(pipefd[1]);

    /*
     * Do not retain the synthetic credential longer than necessary.
     */
    memset(payload, 0, sizeof(payload));

    int status = 0;

    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return 6;
    }

    if (!WIFEXITED(status)) {
        fprintf(stderr, "helper did not exit normally\n");
        return 7;
    }

    if (WEXITSTATUS(status) != 0) {
        fprintf(stderr,
                "helper exited with status %d\n",
                WEXITSTATUS(status));
        return 8;
    }

    return 0;
}