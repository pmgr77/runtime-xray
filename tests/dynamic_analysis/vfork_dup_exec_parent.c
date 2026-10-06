/**
 * @file vfork_dup_exec_parent.c
 * @brief Exercises pipe resource inheritance across CLONE_VFORK, fd remap,
 *        and exec.
 *
 * The parent creates a pipe and then creates a child using
 * CLONE_VM | CLONE_VFORK | SIGCHLD. The child remaps the pipe read endpoint
 * to stdin and execs the supplied helper.
 *
 * CLONE_VFORK intentionally suspends the parent until the child execs or
 * exits. This reproduces the timing used by Docker credential-helper
 * process creation and verifies that RuntimeXRay establishes child FD
 * lineage before the child performs dup/exec.
 *
 * @author Peter Magram
 * @date 2026-10-06
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHILD_STACK_SIZE (64 * 1024)

struct child_args {
    int read_fd;
    int write_fd;
    const char *helper_path;
};

static unsigned char child_stack[CHILD_STACK_SIZE]
    __attribute__((aligned(16)));

static int child_main(void *opaque)
{
    struct child_args *args = (struct child_args *)opaque;

    close(args->write_fd);

    if (dup2(args->read_fd, STDIN_FILENO) < 0) {
        _exit(120);
    }

    if (args->read_fd != STDIN_FILENO) {
        close(args->read_fd);
    }

    execl(args->helper_path, args->helper_path, (char *)NULL);

    _exit(121);
}

static int write_all(int fd, const char *buf, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t n = write(fd, buf + offset, len - offset);

        if (n > 0) {
            offset += (size_t)n;
            continue;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    static const char payload[] =
        "password=RXRAY_FORK_DUP_EXEC_X7kQ2mNv8pLr4ZtW9yBc3";

    int pipefd[2];
    struct child_args args;
    pid_t child;
    int status;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <helper-path>\n", argv[0]);
        return 2;
    }

    if (pipe(pipefd) != 0) {
        perror("pipe");
        return 3;
    }

    args.read_fd = pipefd[0];
    args.write_fd = pipefd[1];
    args.helper_path = argv[1];

    child = clone(
        child_main,
        child_stack + sizeof(child_stack),
        CLONE_VM | CLONE_VFORK | SIGCHLD,
        &args);

    if (child < 0) {
        perror("clone");
        close(pipefd[0]);
        close(pipefd[1]);
        return 4;
    }

    /*
     * Because CLONE_VFORK is used, execution reaches here only after the
     * child has exec'd the helper or exited.
     */
    close(pipefd[0]);

    if (write_all(pipefd[1], payload, strlen(payload)) != 0) {
        perror("write");
        close(pipefd[1]);
        waitpid(child, &status, 0);
        return 5;
    }

    close(pipefd[1]);

    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        return 6;
    }

    if (!WIFEXITED(status)) {
        return 7;
    }

    return WEXITSTATUS(status);
}