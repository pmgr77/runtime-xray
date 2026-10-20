/*
 * RuntimeXRay research: mixed-VMA remote-memory benchmark.
 *
 * Compare process_vm_readv() with pread(/proc/<pid>/mem) on a realistic
 * fragmented child address space (anonymous/file-backed, MAP_PRIVATE/SHARED,
 * read-only/executable, PROT_NONE, and unmapped holes).
 *
 * Both methods scan the SAME /proc/<child>/maps readable ranges in 'maps'
 * mode. Optional --probe deliberately attempts reads across gaps to study
 * error and partial-read semantics; those results are not an equivalent
 * workload across readers because /proc/pid/mem can override protections.
 *
 * Every combination uses a fresh fork. All pages are populated before fork;
 * no application writes the measured region afterward. PFN comparisons are
 * restricted to populated private anonymous or pre-dirtied file pages.
 *
 * Linux-only benchmark, NOT production code.
 *
 * cc -std=c11 -O2 -Wall -Wextra -Werror \
 *    benchmark_remote_memory_vma.c -o /tmp/benchmark_remote_memory_vma
 * sudo /tmp/benchmark_remote_memory_vma --mb 32 --warm 5 --probe
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PRESENT_BIT (UINT64_C(1) << 63)
#define PFN_MASK ((UINT64_C(1) << 55) - 1)
#define KINDS 10

enum kind {
    ANON_PRIVATE_RW,
    ANON_PRIVATE_RO,
    ANON_SHARED_RW,
    FILE_PRIVATE_RO,
    FILE_PRIVATE_DIRTY,
    FILE_SHARED_RW,
    ANON_NONE,
    HOLE,
    ANON_PRIVATE_RX,
    FILE_SHARED_RO
};
enum reader { VMREAD, PROC_MEM };
enum policy { MAPS_AWARE, PROBE_ALL };

struct range { uintptr_t lo, hi; };
struct ranges { struct range *items; size_t count, capacity; };
struct arena {
    unsigned char *base;
    size_t len, page_size, pages, segment_pages, segments;
    unsigned char *tracked;
    int file_fd;
    size_t kind_pages[KINDS];
};
struct counters {
    uint64_t calls, errors, short_reads, bytes, checksum;
    uint64_t permission_errors, fault_errors;
};

static void fatal(const char *op) { perror(op); exit(2); }
static double seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) fatal("clock_gettime");
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}
static size_t parse_arg(const char *s, size_t low, size_t high)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || end == s || *end || v < low || v > high) {
        fprintf(stderr, "Invalid numeric argument: %s (range %zu..%zu)\n", s, low, high);
        exit(2);
    }
    return (size_t)v;
}
static void ranges_push(struct ranges *ranges, uintptr_t lo, uintptr_t hi)
{
    if (lo >= hi) return;
    if (ranges->count == ranges->capacity) {
        size_t new_cap = ranges->capacity ? ranges->capacity * 2 : 32;
        struct range *p = realloc(ranges->items, new_cap * sizeof(*p));
        if (!p) fatal("realloc ranges");
        ranges->items = p;
        ranges->capacity = new_cap;
    }
    ranges->items[ranges->count++] = (struct range){ lo, hi };
}
static struct ranges readable_child_ranges(pid_t child, uintptr_t lo, uintptr_t hi)
{
    struct ranges out = {0};
    char path[64], line[4096];
    snprintf(path, sizeof(path), "/proc/%ld/maps", (long)child);
    FILE *f = fopen(path, "r");
    if (!f) fatal("open /proc/pid/maps");
    while (fgets(line, sizeof(line), f)) {
        unsigned long a, b;
        char perm[5];
        if (sscanf(line, "%lx-%lx %4s", &a, &b, perm) != 3) continue;
        if (perm[0] != 'r') continue;
        uintptr_t begin = (uintptr_t)a > lo ? (uintptr_t)a : lo;
        uintptr_t end = (uintptr_t)b < hi ? (uintptr_t)b : hi;
        ranges_push(&out, begin, end);
    }
    fclose(f);
    return out;
}
static void write_all_at(int fd, const void *src, size_t bytes, off_t off)
{
    size_t done = 0;
    while (done < bytes) {
        ssize_t n = pwrite(fd, (const char *)src + done, bytes - done, off + (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fatal("pwrite backing file");
        done += (size_t)n;
    }
}
static void arena_init(struct arena *a, size_t mib, size_t segment_pages)
{
    memset(a, 0, sizeof(*a));
    a->page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (!a->page_size || a->page_size > 65536) {
        fprintf(stderr, "Unsupported page size\n"); exit(2);
    }
    a->len = mib * 1024 * 1024;
    a->pages = a->len / a->page_size;
    a->segment_pages = segment_pages;
    if (a->pages % segment_pages != 0 || a->len % a->page_size != 0) {
        fprintf(stderr, "--mb must yield a whole number of --segment-pages groups\n"); exit(2);
    }
    a->segments = a->pages / segment_pages;
    a->tracked = calloc(a->pages, 1);
    if (!a->tracked) fatal("calloc tracked");
    a->base = mmap(NULL, a->len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a->base == MAP_FAILED) fatal("mmap reserve");

    a->file_fd = memfd_create("rxray-vma-benchmark", MFD_CLOEXEC);
    if (a->file_fd < 0) fatal("memfd_create");
    if (ftruncate(a->file_fd, (off_t)a->len) != 0) fatal("ftruncate");
    const size_t write_buf_len = 1024 * 1024;
    unsigned char *fill = malloc(write_buf_len);
    if (!fill) fatal("malloc fill");
    memset(fill, 'p', write_buf_len);
    for (size_t off = 0; off < a->len; off += write_buf_len) {
        size_t n = a->len - off < write_buf_len ? a->len - off : write_buf_len;
        write_all_at(a->file_fd, fill, n, (off_t)off);
    }
    free(fill);

    const size_t seg_bytes = segment_pages * a->page_size;
    for (size_t s = 0; s < a->segments; ++s) {
        const enum kind kind = (enum kind)(s % KINDS);
        unsigned char *dest = a->base + s * seg_bytes;
        a->kind_pages[kind] += segment_pages;
        if (kind == HOLE) {
            if (munmap(dest, seg_bytes) != 0) fatal("munmap hole");
            continue;
        }
        int flags = MAP_FIXED;
        int fd = -1;
        off_t offset = 0;
        if (kind == ANON_PRIVATE_RW || kind == ANON_PRIVATE_RO ||
            kind == ANON_NONE || kind == ANON_PRIVATE_RX) {
            flags |= MAP_PRIVATE | MAP_ANONYMOUS;
        } else if (kind == ANON_SHARED_RW) {
            flags |= MAP_SHARED | MAP_ANONYMOUS;
        } else {
            flags |= (kind == FILE_SHARED_RW || kind == FILE_SHARED_RO)
                         ? MAP_SHARED : MAP_PRIVATE;
            fd = a->file_fd;
            offset = (off_t)(s * seg_bytes);
        }
        /* Populate anonymous and dirty-file areas while writable, then mprotect. */
        int prot = PROT_READ | PROT_WRITE;
        if (kind == FILE_PRIVATE_RO || kind == FILE_SHARED_RO) prot = PROT_READ;
        void *p = mmap(dest, seg_bytes, prot, flags, fd, offset);
        if (p == MAP_FAILED || p != dest) fatal("mmap segment MAP_FIXED");
        if (kind != FILE_PRIVATE_RO && kind != FILE_SHARED_RO) {
            memset(dest, 'p', seg_bytes);
        } else {
            /* Force file-backed pages into page tables before fork. */
            volatile unsigned char sink = 0;
            for (size_t off = 0; off < seg_bytes; off += a->page_size) sink ^= dest[off];
            (void)sink;
        }
        if (kind == ANON_PRIVATE_RO || kind == ANON_NONE || kind == ANON_PRIVATE_RX) {
            int final_prot = kind == ANON_NONE ? PROT_NONE :
                             kind == ANON_PRIVATE_RX ? PROT_READ | PROT_EXEC : PROT_READ;
            if (mprotect(dest, seg_bytes, final_prot) != 0) fatal("mprotect");
        }
        if (kind == ANON_PRIVATE_RW || kind == ANON_PRIVATE_RO ||
            kind == FILE_PRIVATE_DIRTY || kind == ANON_PRIVATE_RX) {
            memset(a->tracked + s * segment_pages, 1, segment_pages);
        }
    }
}
static size_t tracked_pages_count(const struct arena *a)
{
    size_t n = 0;
    for (size_t i = 0; i < a->pages; ++i) n += a->tracked[i] != 0;
    return n;
}
/* Return -1 if pagemap inaccessible or PFNs hidden, else shared tracked PFNs. */
static long shared_pfns(pid_t child, const struct arena *a)
{
    char pp[64], cp[64];
    snprintf(pp, sizeof(pp), "/proc/%ld/pagemap", (long)getpid());
    snprintf(cp, sizeof(cp), "/proc/%ld/pagemap", (long)child);
    int pf = open(pp, O_RDONLY | O_CLOEXEC);
    int cf = open(cp, O_RDONLY | O_CLOEXEC);
    if (pf < 0 || cf < 0) {
        if (pf >= 0) close(pf);
        if (cf >= 0) close(cf);
        return -1;
    }
    uint64_t *parent = malloc(a->pages * sizeof(uint64_t));
    uint64_t *kid = malloc(a->pages * sizeof(uint64_t));
    if (!parent || !kid) fatal("malloc pagemap buffers");
    off_t offset = (off_t)(((uintptr_t)a->base / a->page_size) * sizeof(uint64_t));
    size_t bytes = a->pages * sizeof(uint64_t);
    bool ok = true;
    for (int which = 0; which < 2; ++which) {
        int fd = which ? cf : pf;
        unsigned char *dst = (unsigned char *)(which ? kid : parent);
        size_t done = 0;
        while (done < bytes) {
            ssize_t n = pread(fd, dst + done, bytes - done, offset + (off_t)done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ok = false; break; }
            done += (size_t)n;
        }
        if (!ok) break;
    }
    long shared = 0;
    if (ok) {
        for (size_t i = 0; i < a->pages; ++i) {
            if (!a->tracked[i]) continue;
            uint64_t p = parent[i], c = kid[i];
            uint64_t pn = p & PFN_MASK, cn = c & PFN_MASK;
            if (!(p & PRESENT_BIT) || !(c & PRESENT_BIT) || !pn || !cn) {
                ok = false; break;
            }
            if (pn == cn) ++shared;
        }
    }
    free(parent);
    free(kid);
    close(pf);
    close(cf);
    return ok ? shared : -1;
}
static int open_child_mem(pid_t child)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/mem", (long)child);
    return open(path, O_RDONLY | O_CLOEXEC);
}
static ssize_t remote_read(enum reader reader, pid_t child, int fd,
                           uintptr_t addr, size_t bytes, unsigned char *dst)
{
    if (reader == VMREAD) {
        struct iovec local = { .iov_base = dst, .iov_len = bytes };
        struct iovec remote = { .iov_base = (void *)addr, .iov_len = bytes };
        return process_vm_readv(child, &local, 1, &remote, 1, 0);
    }
    return pread(fd, dst, bytes, (off_t)addr);
}
static void scan_ranges(enum reader reader, pid_t child, int fd,
                        const struct ranges *ranges, size_t block, size_t pg,
                        unsigned char *buffer, struct counters *c)
{
    for (size_t r = 0; r < ranges->count; ++r) {
        uintptr_t pos = ranges->items[r].lo;
        const uintptr_t hi = ranges->items[r].hi;
        while (pos < hi) {
            size_t nbytes = (size_t)(hi - pos);
            if (nbytes > block) nbytes = block;
            ssize_t n = remote_read(reader, child, fd, pos, nbytes, buffer);
            ++c->calls;
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) {
                ++c->errors;
                if (errno == EPERM || errno == EACCES) ++c->permission_errors;
                if (errno == EFAULT || errno == EIO) ++c->fault_errors;
                size_t advance = pg - (size_t)(pos % pg);
                pos += advance;
                continue;
            }
            if ((size_t)n < nbytes) ++c->short_reads;
            c->bytes += (uint64_t)n;
            /* Verify returned data with low overhead, without scanning each byte. */
            if (buffer[0] != 'p' || buffer[n - 1] != 'p') {
                fprintf(stderr, "Unexpected data at %p: first=%u last=%u\n",
                        (void *)pos, (unsigned)buffer[0], (unsigned)buffer[n - 1]);
                exit(3);
            }
            c->checksum += buffer[0] + buffer[n - 1];
            pos += (uintptr_t)n;
        }
    }
}
static bool run_case(struct arena *a, enum reader reader, enum policy policy,
                     size_t block, size_t warm)
{
    int gate[2];
    if (pipe(gate) != 0) fatal("pipe");
    pid_t child = fork();
    if (child < 0) fatal("fork");
    if (child == 0) {
        close(gate[1]);
        char value;
        while (read(gate[0], &value, 1) < 0 && errno == EINTR) {}
        close(gate[0]);
        _exit(0);
    }
    close(gate[0]);
    struct ranges readable = readable_child_ranges(child,
        (uintptr_t)a->base, (uintptr_t)a->base + a->len);
    struct ranges probe = {0};
    if (policy == PROBE_ALL) {
        ranges_push(&probe, (uintptr_t)a->base, (uintptr_t)a->base + a->len);
    }
    const struct ranges *active = policy == MAPS_AWARE ? &readable : &probe;
    long shared_before = shared_pfns(child, a);
    int fd = -1;
    bool ok = true;
    if (reader == PROC_MEM) {
        fd = open_child_mem(child);
        if (fd < 0) { perror("open /proc/pid/mem"); ok = false; }
    }
    unsigned char *buffer = malloc(block);
    if (!buffer) fatal("malloc read buffer");
    struct counters cold = {0}, repeated = {0};
    double cold_ms = 0, warm_ms = 0;
    long shared_cold = -1;
    if (ok) {
        double t = seconds();
        scan_ranges(reader, child, fd, active, block, a->page_size, buffer, &cold);
        cold_ms = 1000.0 * (seconds() - t);
        shared_cold = shared_pfns(child, a);
        t = seconds();
        for (size_t i = 0; i < warm; ++i)
            scan_ranges(reader, child, fd, active, block, a->page_size, buffer, &repeated);
        warm_ms = 1000.0 * (seconds() - t);
    }
    if (fd >= 0) close(fd);
    free(buffer);
    free(readable.items);
    free(probe.items);
    close(gate[1]);
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) { perror("waitpid"); ok = false; break; }
    }
    if (!ok || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return false;
    double cold_rate = cold_ms > 0 ? ((double)cold.bytes / (1024 * 1024)) / (cold_ms / 1000.0) : 0;
    double warm_rate = warm_ms > 0 ? ((double)repeated.bytes / (1024 * 1024)) / (warm_ms / 1000.0) : 0;
    printf("%-6s %-5s %7zu %5zu %9.2f %10.1f %7" PRIu64 " %5" PRIu64 " %5" PRIu64
           " %10.1f %7" PRIu64 " %5" PRIu64 " %5" PRIu64 " %7.2f %7.2f",
           reader == VMREAD ? "vmread" : "proc", policy == MAPS_AWARE ? "maps" : "probe",
           block / 1024, policy == MAPS_AWARE ? active->count : 1,
           cold_ms, cold_rate, cold.calls, cold.errors, cold.short_reads,
           warm_rate, repeated.calls, repeated.errors, repeated.short_reads,
           (double)cold.bytes / (1024 * 1024), (double)repeated.bytes / (1024 * 1024));
    if (shared_before >= 0 && shared_cold >= 0) {
        printf(" %7ld %7ld %6ld", shared_before, shared_cold, shared_before - shared_cold);
    } else printf(" %7s %7s %6s", "N/A", "N/A", "N/A");
    printf("  # sum=%" PRIu64 "/%" PRIu64 " perm_err=%" PRIu64 " fault_err=%" PRIu64 "\n",
           cold.checksum, repeated.checksum, cold.permission_errors, cold.fault_errors);
    fflush(stdout);
    return true;
}
int main(int argc, char **argv)
{
    size_t mb = 32, warm = 5, segment_pages = 16;
    bool probe = false;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--mb") && i + 1 < argc) mb = parse_arg(argv[++i], 1, 512);
        else if (!strcmp(argv[i], "--warm") && i + 1 < argc) warm = parse_arg(argv[++i], 1, 100);
        else if (!strcmp(argv[i], "--segment-pages") && i + 1 < argc)
            segment_pages = parse_arg(argv[++i], 1, 1024);
        else if (!strcmp(argv[i], "--probe")) probe = true;
        else {
            fprintf(stderr, "Usage: %s [--mb 32] [--warm 5] [--segment-pages 16] [--probe]\n", argv[0]);
            return 2;
        }
    }
    struct arena a;
    arena_init(&a, mb, segment_pages);
    struct ranges readable = readable_child_ranges(getpid(),
        (uintptr_t)a.base, (uintptr_t)a.base + a.len);
    size_t readable_bytes = 0;
    for (size_t i = 0; i < readable.count; ++i)
        readable_bytes += (size_t)(readable.items[i].hi - readable.items[i].lo);
    struct utsname uts;
    if (uname(&uts) != 0) fatal("uname");
    printf("kernel=%s", uts.release);
    printf("; arena=%zu MiB page=%zu seg_pages=%zu segments=%zu readable_VMA=%zu readable=%.2f MiB tracked_COW_pages=%zu\n",
           mb, a.page_size, a.segment_pages, a.segments, readable.count,
           (double)readable_bytes / (1024 * 1024), tracked_pages_count(&a));
    printf("VMA classes (pages): private_anon_rw=%zu private_anon_ro=%zu shared_anon_rw=%zu private_file_ro=%zu private_file_dirty=%zu shared_file_rw=%zu prot_none=%zu holes=%zu private_anon_rx=%zu shared_file_ro=%zu\n",
        a.kind_pages[ANON_PRIVATE_RW], a.kind_pages[ANON_PRIVATE_RO],
        a.kind_pages[ANON_SHARED_RW], a.kind_pages[FILE_PRIVATE_RO],
        a.kind_pages[FILE_PRIVATE_DIRTY], a.kind_pages[FILE_SHARED_RW],
        a.kind_pages[ANON_NONE], a.kind_pages[HOLE],
        a.kind_pages[ANON_PRIVATE_RX], a.kind_pages[FILE_SHARED_RO]);
    printf("METHOD POLICY BLOCKKB VMAs cold_ms cold_MiBs calls errs short warm_MiBs calls errs short cold_MiB warm_MiB PFN_pre PFN_post split\n");
    fflush(stdout);
    free(readable.items);
    size_t blocks[] = {4096, 65536, 262144};
    for (size_t b = 0; b < sizeof(blocks) / sizeof(blocks[0]); ++b) {
        size_t block = blocks[b];
        if (block < a.page_size) block = a.page_size;
        for (int m = 0; m < 2; ++m) {
            if (!run_case(&a, (enum reader)m, MAPS_AWARE, block, warm)) return 1;
        }
    }
    if (probe) {
        puts("PROBE mode deliberately crosses holes/PROT_NONE. Readable bytes differ by API; do not compare rates as equal workloads.");
        for (size_t b = 0; b < sizeof(blocks) / sizeof(blocks[0]); ++b) {
            size_t block = blocks[b];
            if (block < a.page_size) block = a.page_size;
            for (int m = 0; m < 2; ++m) {
                if (!run_case(&a, (enum reader)m, PROBE_ALL, block, warm)) return 1;
            }
        }
    }
    close(a.file_fd);
    free(a.tracked);
    /* The arena deliberately contains unmapped holes; leave cleanup to exit. */
    return 0;
}

