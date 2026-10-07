/**
 * @file    cloexec_exec_flow.c
 * @brief   Tests FD_CLOEXEC resource-lineage behavior across exec.
 *
 * @author  Peter Magram
 * @date    2026-10-07
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * Verify whether a file descriptor survived exec().
 *
 * For a surviving pipe read endpoint whose write side has been closed,
 * read() must return EOF (0).
 *
 * For an FD_CLOEXEC descriptor, read() must fail with EBADF because the
 * descriptor was closed automatically by exec().
 */
static int check_fd(int fd, int should_survive)
{
    char byte = 0;
    errno = 0;

    const ssize_t rc = read(fd, &byte, 1);

    if (should_survive) {
        if (rc != 0) {
            fprintf(
                stderr,
                "fd %d should survive exec, read returned %zd errno=%d\n",
                fd,
                rc,
                errno);

            return 1;
        }
    } else {
        if (rc != -1 || errno != EBADF) {
            fprintf(
                stderr,
                "fd %d should be closed by exec, read returned %zd errno=%d\n",
                fd,
                rc,
                errno);

            return 1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    /*
     * Second execution image.
     *
     * Validate which descriptors survived exec().
     */
    if (argc == 5 && strcmp(argv[1], "--after-exec") == 0) {
        const int dup3_cloexec = atoi(argv[2]);
        const int dup3_survive = atoi(argv[3]);
        const int fcntl_cloexec = atoi(argv[4]);

        /*
         * dup3(..., O_CLOEXEC)
         *
         * Must be closed by exec().
         */
        if (check_fd(dup3_cloexec, 0) != 0) {
            return 20;
        }

        /*
         * dup3(..., 0)
         *
         * Must survive exec().
         */
        if (check_fd(dup3_survive, 1) != 0) {
            return 21;
        }

        /*
         * fcntl(F_DUPFD) followed by:
         *
         *     fcntl(fd, F_SETFD, FD_CLOEXEC)
         *
         * Must be closed by exec().
         */
        if (check_fd(fcntl_cloexec, 0) != 0) {
            return 22;
        }

        return 0;
    }

    /*
     * First execution image.
     *
     * Start with a pipe whose original descriptors are both CLOEXEC.
     */
    int pipefd[2];

    if (pipe2(pipefd, O_CLOEXEC) != 0) {
        perror("pipe2");
        return 2;
    }

    /*
     * Create two aliases of the same pipe read endpoint.
     *
     * fd 100:
     *     same pipe
     *     FD_CLOEXEC set
     *
     * fd 101:
     *     same pipe
     *     FD_CLOEXEC cleared
     */
    const int dup3_cloexec = 100;
    const int dup3_survive = 101;

    if (dup3(pipefd[0], dup3_cloexec, O_CLOEXEC) != dup3_cloexec) {
        perror("dup3 O_CLOEXEC");
        return 3;
    }

    if (dup3(pipefd[0], dup3_survive, 0) != dup3_survive) {
        perror("dup3");
        return 4;
    }

    /*
     * Exercise:
     *
     *     F_DUPFD
     *       +
     *     F_SETFD / FD_CLOEXEC
     */
    const int fcntl_cloexec =
        fcntl(pipefd[0], F_DUPFD, 110);

    if (fcntl_cloexec < 0) {
        perror("fcntl F_DUPFD");
        return 5;
    }

    if (fcntl(fcntl_cloexec, F_SETFD, FD_CLOEXEC) != 0) {
        perror("fcntl F_SETFD");
        return 6;
    }

    /*
     * Close the original pipe descriptors.
     *
     * The duplicated descriptors now represent all remaining references
     * to the pipe read endpoint. Closing the original write endpoint also
     * means a surviving read descriptor will observe EOF after exec().
     */
    if (close(pipefd[0]) != 0) {
        perror("close pipe read fd");
        return 7;
    }

    if (close(pipefd[1]) != 0) {
        perror("close pipe write fd");
        return 8;
    }

    char arg_dup3_cloexec[32];
    char arg_dup3_survive[32];
    char arg_fcntl_cloexec[32];

    snprintf(
        arg_dup3_cloexec,
        sizeof(arg_dup3_cloexec),
        "%d",
        dup3_cloexec);

    snprintf(
        arg_dup3_survive,
        sizeof(arg_dup3_survive),
        "%d",
        dup3_survive);

    snprintf(
        arg_fcntl_cloexec,
        sizeof(arg_fcntl_cloexec),
        "%d",
        fcntl_cloexec);

    char *const new_argv[] = {
        argv[0],
        "--after-exec",
        arg_dup3_cloexec,
        arg_dup3_survive,
        arg_fcntl_cloexec,
        NULL
    };

    execv(argv[0], new_argv);

    perror("execv");
    return 9;
}