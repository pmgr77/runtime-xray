/*
 * RuntimeXRay research: remote-memory read throughput and COW interference.
 *
 * Compare process_vm_readv() with pread(/proc/<pid>/mem) while a forked
 * child holds a private anonymous mapping shared with its parent.
 *
 * Each (method, block size) runs against a fresh child address space.
 * The measured mapping is populated BEFORE fork and never written after fork.
 * First-pass and warm-pass timings are reported separately.
 *
 * Compile: cc -std=c11 -O2 -Wall -Wextra -Werror \
 *              benchmark_remote_memory_cow.c -o benchmark_remote_memory_cow
 * Run:     sudo ./benchmark_remote_memory_cow --mb 32 --warm 5
 *
 * Research fixture, not production code. Linux only.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PFN_MASK ((UINT64_C(1) << 55) - 1)
#define PRESENT_BIT (UINT64_C(1) << 63)

enum method { METHOD_VMREAD, METHOD_PROC };

static double monotonic_seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static unsigned long parse_number(const char *s, unsigned long min,
                                  unsigned long max, const char *what)
{
    char *end = NULL;
    errno = 0;
    const unsigned long n = strtoul(s, &end, 10);
    if (errno || end == s || *end || n < min || n > max) {
        fprintf(stderr, "Invalid %s: %s (allowed %lu..%lu)\n",
                what, s, min, max);
        exit(2);
    }
    return n;
}

/* Read one process's pagemap entries in one contiguous batch. */
static bool pagemap_entries(pid_t pid, uintptr_t address, size_t page_size,
                            uint64_t *entries, size_t pages)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/pagemap", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    const uint64_t offset = ((uint64_t)address / page_size) * sizeof(uint64_t);
    const size_t bytes = pages * sizeof(uint64_t);
    size_t done = 0;
    while (done < bytes) {
        const ssize_t n = pread(fd, (char *)entries + done, bytes - done,
                                (off_t)(offset + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(fd);
            return false;
        }
        done += (size_t)n;
    }
    close(fd);
    return true;
}

/* -1 means PFN access was denied/masked or pagemap could not be read. */
static long count_shared_pfns(pid_t parent, pid_t child, uintptr_t address,
                              size_t page_size, size_t pages)
{
    uint64_t *p = malloc(pages * sizeof(uint64_t));
    uint64_t *c = malloc(pages * sizeof(uint64_t));
    if (!p || !c) {
        free(p); free(c);
        return -1;
    }
    bool valid = pagemap_entries(parent, address, page_size, p, pages) &&
                 pagemap_entries(child, address, page_size, c, pages);
    long shared = 0;
    if (valid) {
        for (size_t i = 0; i < pages; ++i) {
            const uint64_t ppfn = p[i] & PFN_MASK;
            const uint64_t cpfn = c[i] & PFN_MASK;
            if (!(p[i] & PRESENT_BIT) || !(c[i] & PRESENT_BIT) ||
                ppfn == 0 || cpfn == 0) {
                valid = false;
                break;
            }
            if (ppfn == cpfn) ++shared;
        }
    }
    free(p);
    free(c);
    return valid ? shared : -1;
}

/* Child's whole-process private dirty count: an approximate secondary metric. */
static long private_dirty_kb(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/smaps_rollup", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    long result = -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned long value;
        if (sscanf(line, "Private_Dirty: %lu kB", &value) == 1) {
            if (value <= LONG_MAX) result = (long)value;
            break;
        }
    }
    fclose(f);
    return result;
}

static int open_mem_file(pid_t child)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/mem", (long)child);
    return open(path, O_RDONLY | O_CLOEXEC);
}

static bool read_sweep(enum method method, pid_t child, int memfd,
                       uintptr_t address, size_t bytes, size_t block,
                       unsigned char *buffer, uint64_t *calls,
                       unsigned long *checksum)
{
    for (size_t offset = 0; offset < bytes; ) {
        size_t size = bytes - offset;
        if (size > block) size = block;
        ssize_t n;
        if (method == METHOD_VMREAD) {
            struct iovec local = { .iov_base = buffer, .iov_len = size };
            struct iovec remote = {
                .iov_base = (void *)(address + offset), .iov_len = size
            };
            n = process_vm_readv(child, &local, 1, &remote, 1, 0);
        } else {
            n = pread(memfd, buffer, size, (off_t)(address + offset));
        }
        ++*calls;
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            perror(method == METHOD_VMREAD ? "process_vm_readv" : "pread");
            return false;
        }
        /* Verify full data, but touch only one byte to minimize benchmark overhead. */
        if (buffer[0] != (unsigned char)'p' ||
            buffer[n - 1] != (unsigned char)'p') {
            fprintf(stderr, "Unexpected data from child at offset %zu\n", offset);
            return false;
        }
        *checksum += buffer[0];
        offset += (size_t)n;
    }
    return true;
}

static bool run_case(enum method method, size_t block, size_t bytes,
                     unsigned int warm_passes, unsigned char *mapping,
                     size_t page_size, unsigned char *buffer)
{
    int gate[2];
    if (pipe(gate) != 0) { perror("pipe"); return false; }
    pid_t child = fork();
    if (child < 0) { perror("fork"); close(gate[0]); close(gate[1]); return false; }
    if (child == 0) {
        close(gate[1]);
        char dummy;
        while (read(gate[0], &dummy, 1) < 0 && errno == EINTR) {}
        close(gate[0]);
        _exit(0);
    }
    close(gate[0]);

    const size_t pages = bytes / page_size;
    const long shared_before = count_shared_pfns(getpid(), child,
                                                  (uintptr_t)mapping,
                                                  page_size, pages);
    const long dirty_before = private_dirty_kb(child);
    int fd = -1;
    bool ok = true;
    if (method == METHOD_PROC) {
        fd = open_mem_file(child);
        if (fd < 0) { perror("open /proc/pid/mem"); ok = false; }
    }

    uint64_t cold_calls = 0;
    uint64_t warm_calls = 0;
    unsigned long checksum = 0;
    double cold_sec = 0.0;
    double warm_sec = 0.0;
    if (ok) {
        double start = monotonic_seconds();
        ok = read_sweep(method, child, fd, (uintptr_t)mapping, bytes,
                        block, buffer, &cold_calls, &checksum);
        cold_sec = monotonic_seconds() - start;
    }
    if (ok) {
        double start = monotonic_seconds();
        for (unsigned int pass = 0; pass < warm_passes && ok; ++pass) {
            ok = read_sweep(method, child, fd, (uintptr_t)mapping, bytes,
                            block, buffer, &warm_calls, &checksum);
        }
        warm_sec = monotonic_seconds() - start;
    }
    const long dirty_after = private_dirty_kb(child);
    const long shared_after = count_shared_pfns(getpid(), child,
                                                 (uintptr_t)mapping,
                                                 page_size, pages);
    if (fd >= 0) close(fd);
    close(gate[1]);
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) { perror("waitpid"); ok = false; break; }
    }
    if (!ok) return false;

    const double mib = (double)bytes / (1024.0 * 1024.0);
    const double cold_rate = cold_sec > 0 ? mib / cold_sec : 0;
    const double warm_rate = warm_sec > 0 ? mib * warm_passes / warm_sec : 0;
    printf("%-7s %6zu %9.2f %10.1f %8" PRIu64
           " %9.2f %10.1f %8" PRIu64,
           method == METHOD_VMREAD ? "vmread" : "proc",
           block / 1024, cold_sec * 1000, cold_rate, cold_calls,
           warm_sec * 1000, warm_rate, warm_calls);
    if (shared_before >= 0 && shared_after >= 0) {
        printf(" %7ld %7ld %8ld", shared_before, shared_after,
               shared_before - shared_after);
    } else {
        printf(" %7s %7s %8s", "N/A", "N/A", "N/A");
    }
    if (dirty_before >= 0 && dirty_after >= 0) {
        printf(" %10ld", dirty_after - dirty_before);
    } else {
        printf(" %10s", "N/A");
    }
    printf("  # checksum=%lu\n", checksum);
    fflush(stdout);
    return true;
}

int main(int argc, char **argv)
{
    unsigned long mb = 32;
    unsigned long warm = 5;
    int method_filter = -1; /* -1 = both */
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--mb") == 0 && i + 1 < argc) {
            mb = parse_number(argv[++i], 1, 256, "--mb");
        } else if (strcmp(argv[i], "--warm") == 0 && i + 1 < argc) {
            warm = parse_number(argv[++i], 1, 100, "--warm");
        } else if (strcmp(argv[i], "--method") == 0 && i + 1 < argc) {
            const char *choice = argv[++i];
            if (strcmp(choice, "vmread") == 0) method_filter = METHOD_VMREAD;
            else if (strcmp(choice, "proc") == 0) method_filter = METHOD_PROC;
            else if (strcmp(choice, "both") == 0) method_filter = -1;
            else {
                fprintf(stderr, "Invalid --method: %s\n", choice);
                return 2;
            }
        } else {
            fprintf(stderr, "Usage: %s [--mb 1..256] [--warm 1..100] [--method both|vmread|proc]\n", argv[0]);
            return 2;
        }
    }
    const long p = sysconf(_SC_PAGESIZE);
    if (p <= 0) { fprintf(stderr, "sysconf(_SC_PAGESIZE) failed\n"); return 2; }
    const size_t page_size = (size_t)p;
    if (page_size > 4096 || 4096 % page_size != 0) {
        fprintf(stderr, "This fixture currently expects a 4 KiB-or-smaller page size\n");
        return 2;
    }
    const size_t bytes = (size_t)mb * 1024 * 1024;
    unsigned char *mapping = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) { perror("mmap"); return 2; }
#ifdef MADV_NOHUGEPAGE
    if (madvise(mapping, bytes, MADV_NOHUGEPAGE) != 0) {
        perror("madvise(MADV_NOHUGEPAGE)");
    }
#endif
    memset(mapping, 'p', bytes); /* Fault in every 4 KiB page BEFORE fork. */
    unsigned char *buffer = malloc(256 * 1024);
    if (!buffer) { perror("malloc"); munmap(mapping, bytes); return 2; }
    printf("kernel-memory-read benchmark: pid=%ld memory=%lu MiB pages=%zu "
           "page_size=%zu warm_passes=%lu\n",
           (long)getpid(), mb, bytes / page_size, page_size, warm);
    puts("method   blockKB cold_ms cold_MiB/s cold_sys warm_ms warm_MiB/s warm_sys"
         "  PFN_before PFN_after PFN_split child_PrivateDirty_delta_KiB");
    puts("Notes: each case uses a fresh fork; PFN columns count pages still shared."
         " Timing excludes fork, pagemap, smaps, open, and close."
         " proc uses two additional open/close syscalls per case.");
    bool ok = true;
    for (size_t i = 0; i < 3 && ok; ++i) {
        const size_t selected_block = (i == 0 ? 4096 : i == 1 ? 65536 : 262144);
        for (int m = 0; m < 2 && ok; ++m) {
            if (method_filter >= 0 && method_filter != m) continue;
            ok = run_case(m == 0 ? METHOD_VMREAD : METHOD_PROC,
                          selected_block, bytes, (unsigned int)warm,
                          mapping, page_size, buffer);
        }
    }
    free(buffer);
    munmap(mapping, bytes);
    return ok ? 0 : 1;
}

