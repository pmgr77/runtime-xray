/*
 * Minimal Linux COW / remote-read PFN experiment.
 *
 * Run as root (or with CAP_SYS_ADMIN to see real PFNs):
 *   cc -std=c11 -O2 -Wall -Wextra -Werror \
 *     test_process_vm_readv_cow.c -o /tmp/test_process_vm_readv_cow
 *   sudo /tmp/test_process_vm_readv_cow none
 *   sudo /tmp/test_process_vm_readv_cow vmread
 *   sudo /tmp/test_process_vm_readv_cow proc
 *
 * The two processes NEVER write to the private mapping after fork.
 * Their synchronization pipe is a separate kernel object.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static int page_pfn(pid_t pid, const void *address, size_t pagesize,
                    uint64_t *result)
{
    char path[64];
    if (snprintf(path, sizeof(path), "/proc/%ld/pagemap", (long)pid) < 0)
        return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    uint64_t entry = 0;
    uint64_t virtual_page = (uint64_t)(uintptr_t)address / pagesize;
    ssize_t n = pread(fd, &entry, sizeof(entry), (off_t)(virtual_page * 8));
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (n != (ssize_t)sizeof(entry))
        return -1;
    if (!(entry & (UINT64_C(1) << 63)) ||
        (entry & (UINT64_C(1) << 62))) {
        errno = EINVAL;
        return -1;
    }
    *result = entry & ((UINT64_C(1) << 55) - 1);
    if (*result == 0) {
        errno = EPERM;  /* PFN masked by kernel security policy */
        return -1;
    }
    return 0;
}

static int read_one_byte(const char *mode, pid_t child, const void *address)
{
    char byte = '\0';
    ssize_t n = 0;
    if (strcmp(mode, "none") == 0)
        return 0;
    if (strcmp(mode, "vmread") == 0) {
        struct iovec local = { .iov_base = &byte, .iov_len = 1 };
        struct iovec remote = {
            .iov_base = (void *)address, .iov_len = 1
        };
        n = process_vm_readv(child, &local, 1, &remote, 1, 0);
    } else if (strcmp(mode, "proc") == 0) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/mem", (long)child);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            perror("open /proc/pid/mem");
            return -1;
        }
        n = pread(fd, &byte, 1, (off_t)(uintptr_t)address);
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return -1;
    }
    if (n != 1) {
        perror("remote read");
        return -1;
    }
    printf("REMOTE_READ mode=%s bytes=%zd first_byte=%c\n", mode, n, byte);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "none") != 0 &&
                      strcmp(argv[1], "vmread") != 0 &&
                      strcmp(argv[1], "proc") != 0)) {
        fprintf(stderr, "Usage: %s none|vmread|proc\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0)
        return 2;
    size_t pagesize = (size_t)ps;
    char *page = mmap(NULL, pagesize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    memcpy(page, "password=synthetic-cow-demo-value", 34);
    int sync_pipe[2];
    if (pipe(sync_pipe) != 0) {
        perror("pipe");
        return 2;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 2;
    }
    if (child == 0) {
        close(sync_pipe[1]);
        char signal_byte;
        ssize_t n;
        do { n = read(sync_pipe[0], &signal_byte, 1); }
        while (n < 0 && errno == EINTR);
        close(sync_pipe[0]);
        _exit(n == 1 ? 0 : 1);
    }
    close(sync_pipe[0]);
    uint64_t p_before = 0, c_before = 0, p_after = 0, c_after = 0;
    int ok = 1;
    if (page_pfn(getpid(), page, pagesize, &p_before) ||
        page_pfn(child, page, pagesize, &c_before)) {
        perror("pagemap PFN (run with sudo on a host exposing PFNs)");
        ok = 0;
        goto cleanup;
    }
    printf("BEFORE parent=0x%" PRIx64 " child=0x%" PRIx64
           " equal=%d\n", p_before, c_before, p_before == c_before);
    if (p_before != c_before) {
        fprintf(stderr, "FAIL: pages not shared immediately after fork\n");
        ok = 0;
        goto cleanup;
    }
    if (read_one_byte(mode, child, page)) {
        ok = 0;
        goto cleanup;
    }
    if (page_pfn(getpid(), page, pagesize, &p_after) ||
        page_pfn(child, page, pagesize, &c_after)) {
        perror("pagemap PFN after read");
        ok = 0;
        goto cleanup;
    }
    printf("AFTER  parent=0x%" PRIx64 " child=0x%" PRIx64
           " equal=%d\n", p_after, c_after, p_after == c_after);
    if (strcmp(mode, "vmread") == 0 && p_after != c_after)
        puts("OBSERVED: process_vm_readv alone caused PFN divergence");
    else if (strcmp(mode, "none") == 0 && p_after == c_after)
        puts("OBSERVED: no read, PFNs remain shared");
    else if (strcmp(mode, "proc") == 0 && p_after == c_after)
        puts("OBSERVED: /proc/pid/mem read preserved shared PFN");
    else
        puts("OBSERVED: see BEFORE/AFTER PFNs; behavior depends on kernel");
cleanup:
    if (write(sync_pipe[1], "x", 1) != 1)
        ok = 0;
    close(sync_pipe[1]);
    int status;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        ok = 0;
    munmap(page, pagesize);
    return ok ? 0 : 1;
}

