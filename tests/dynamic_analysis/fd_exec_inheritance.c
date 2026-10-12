/*
 * Copyright 2026 Peter Magram
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
    KEEP_FD = 200,
    DROP_FD = 201
};

static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

static int child_main(void)
{
    const char *env = getenv("RXRAY_FD_TEST_ENV");

    if (env == NULL || strcmp(env, "present") != 0) {
        return 20;
    }

    /*
     * stdin must survive exec as a pipe.
     */
    char c = '\0';

    if (read(STDIN_FILENO, &c, 1) != 1 || c != 'I') {
        return 21;
    }

    /*
     * KEEP_FD must survive exec.
     *
     * It was opened by the parent before fork/exec. The child does not
     * reopen it. RuntimeXRay must therefore preserve the inherited FD
     * resource mapping across the process boundary.
     */
    c = '\0';

    if (read(KEEP_FD, &c, 1) != 1 || c != 'K') {
        return 22;
    }

    /*
     * DROP_FD was marked O_CLOEXEC and must not survive exec.
     *
     * A high fixed FD is used so that the dynamic loader is extremely
     * unlikely to reuse the descriptor number before main().
     */
    errno = 0;

    if (fcntl(DROP_FD, F_GETFD) != -1 || errno != EBADF) {
        return 23;
    }

    /*
     * stdout must survive exec as a pipe.
     */
    if (write(STDOUT_FILENO, "O", 1) != 1) {
        return 24;
    }

    /*
     * stderr must survive exec mapped to /dev/null.
     */
    if (write(STDERR_FILENO, "ignored\n", 8) != 8) {
        return 25;
    }

    return 0;
}

static void create_fixed_fd(
    const char *path,
    int target_fd,
    int cloexec)
{
    int raw_fd = open(path, O_RDONLY);

    if (raw_fd < 0) {
        die("open");
    }

    int flags = cloexec ? O_CLOEXEC : 0;

    if (dup3(raw_fd, target_fd, flags) < 0) {
        die("dup3");
    }

    close(raw_fd);
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--child") == 0) {
        return child_main();
    }

    if (argc != 3) {
        fprintf(
            stderr,
            "usage: %s <keep-file> <cloexec-file>\n",
            argv[0]);

        return 2;
    }

    const char *keep_path = argv[1];
    const char *drop_path = argv[2];

    /*
     * Positive inheritance control:
     *
     * KEEP_FD survives exec.
     */
    create_fixed_fd(
        keep_path,
        KEEP_FD,
        0);

    /*
     * Negative inheritance control:
     *
     * DROP_FD exists before exec but O_CLOEXEC removes it during exec.
     */
    create_fixed_fd(
        drop_path,
        DROP_FD,
        1);

    int stdin_pipe[2];
    int stdout_pipe[2];

    if (pipe(stdin_pipe) != 0) {
        die("pipe stdin");
    }

    if (pipe(stdout_pipe) != 0) {
        die("pipe stdout");
    }

    /*
     * Feed one deterministic byte to child's stdin.
     */
    if (write(stdin_pipe[1], "I", 1) != 1) {
        die("write stdin pipe");
    }

    close(stdin_pipe[1]);

    if (setenv(
            "RXRAY_FD_TEST_ENV",
            "present",
            1) != 0) {
        die("setenv");
    }

    pid_t pid = fork();

    if (pid < 0) {
        die("fork");
    }

    if (pid == 0) {
        /*
         * Child layout before exec:
         *
         *   stdin  -> pipe
         *   stdout -> pipe
         *   stderr -> /dev/null
         *   200    -> inherited regular file
         *   201    -> O_CLOEXEC regular file
         */

        if (dup2(
                stdin_pipe[0],
                STDIN_FILENO) < 0) {
            die("dup2 stdin");
        }

        if (dup2(
                stdout_pipe[1],
                STDOUT_FILENO) < 0) {
            die("dup2 stdout");
        }

        int null_fd = open(
            "/dev/null",
            O_WRONLY);

        if (null_fd < 0) {
            die("open /dev/null");
        }

        if (dup2(
                null_fd,
                STDERR_FILENO) < 0) {
            die("dup2 stderr");
        }

        if (null_fd != STDERR_FILENO) {
            close(null_fd);
        }

        close(stdin_pipe[0]);
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);

        char *child_argv[] = {
            "/proc/self/exe",
            "--child",
            NULL
        };

        execv(
            "/proc/self/exe",
            child_argv);

        _exit(127);
    }

    /*
     * Parent no longer needs inherited descriptors.
     */
    close(KEEP_FD);
    close(DROP_FD);

    close(stdin_pipe[0]);
    close(stdout_pipe[1]);

    /*
     * Child must prove stdout survived exec as a pipe.
     */
    char c = '\0';

    ssize_t n = read(
        stdout_pipe[0],
        &c,
        1);

    close(stdout_pipe[0]);

    if (n != 1 || c != 'O') {
        fprintf(
            stderr,
            "unexpected child stdout\n");

        return 30;
    }

    int status = 0;

    if (waitpid(
            pid,
            &status,
            0) < 0) {
        die("waitpid");
    }

    if (!WIFEXITED(status)) {
        fprintf(
            stderr,
            "child did not exit normally\n");

        return 31;
    }

    if (WEXITSTATUS(status) != 0) {
        fprintf(
            stderr,
            "child failed: %d\n",
            WEXITSTATUS(status));

        return WEXITSTATUS(status);
    }

    return 0;
}