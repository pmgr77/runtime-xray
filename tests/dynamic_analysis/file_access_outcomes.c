/**
 * @file    file_access_outcomes.c
 * @brief   Fixture that exercises all four file-access outcomes.
 *
 * Given a base directory as argv[1], attempts to open four paths:
 *
 *   <dir>/secret_opened        - pre-created mode 0644, readable
 *   <dir>/secret_denied        - pre-created mode 0000, unreadable
 *   <dir>/secret_missing       - not created
 *   <dir>/secret_notdir/child  - <dir>/secret_notdir is a regular file
 *
 * Expected analyzer outcomes:
 *   opened   , err=0
 *   denied   , err=EACCES   (13)
 *   failed   , err=ENOENT   (2)
 *   failed   , err=ENOTDIR  (20)
 *
 * When run as root, the fixture drops to uid/gid 65534 (nobody) so that
 * mode 0000 actually produces EACCES. When run as a non-root user the
 * drop is skipped and the underlying uid's permissions apply directly.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static void try_open(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        close(fd);
    }
    /* Result is observed by the tracer; no local handling needed. */
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <dir>\n", argv[0]);
        return 2;
    }

    const char* dir = argv[1];

    if (geteuid() == 0) {
        if (setgid(65534) != 0 || setuid(65534) != 0) {
            perror("setuid");
            return 3;
        }
    }

    char path[1024];

    snprintf(path, sizeof(path), "%s/secret_opened", dir);
    try_open(path);

    snprintf(path, sizeof(path), "%s/secret_denied", dir);
    try_open(path);

    snprintf(path, sizeof(path), "%s/secret_missing", dir);
    try_open(path);

    snprintf(path, sizeof(path), "%s/secret_notdir/child", dir);
    try_open(path);

    return 0;
}