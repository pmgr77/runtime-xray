/**
 * @file test_memory_reader_lifecycle.cpp
 * @brief Stage D.3: verify remote memory reader behavior across VMA changes,
 *        concurrent unmap/remap, execve, and target exit.
 *
 * Copyright 2026 Peter Magram
 * SPDX-License-Identifier: Apache-2.0
 *
 * Compile directly with src/memory_reader.cpp (no CMake changes required).
 * Run as a normal user; a parent reads its own forked child.
 */

#include "memory_reader.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using runtimexray::MemoryReadBackend;
using runtimexray::MemoryReader;

struct Reply {
    std::uintptr_t address;
    int status;
};

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message + ": " + std::strerror(errno));
}

class UnsupportedVmRead : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

void require(bool ok, const std::string& message) {
    if (!ok) fail(message);
}

void write_full(int fd, const void* src, std::size_t count) {
    const auto* bytes = static_cast<const char*>(src);
    while (count > 0) {
        const ssize_t n = ::write(fd, bytes, count);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "pipe write failed");
        const auto consumed = static_cast<std::size_t>(n);
        bytes += consumed;
        count -= consumed;
    }
}

void read_full(int fd, void* dst, std::size_t count) {
    auto* bytes = static_cast<char*>(dst);
    while (count > 0) {
        const ssize_t n = ::read(fd, bytes, count);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "pipe read failed / child exited unexpectedly");
        const auto consumed = static_cast<std::size_t>(n);
        bytes += consumed;
        count -= consumed;
    }
}

std::size_t page_size() {
    const long n = ::sysconf(_SC_PAGESIZE);
    require(n > 0, "sysconf(_SC_PAGESIZE) failed");
    return static_cast<std::size_t>(n);
}

void* map_page(std::uintptr_t requested, std::size_t size) {
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS |
                      (requested ? MAP_FIXED : 0);
    void* p = ::mmap(reinterpret_cast<void*>(requested), size,
                     PROT_READ | PROT_WRITE, flags, -1, 0);
    require(p != MAP_FAILED, "mmap failed");
    return p;
}

[[noreturn]] void child_main(int commands, int responses, bool after_exec) {
    try {
        const std::size_t ps = page_size();
        auto* page = static_cast<char*>(map_page(0, ps));
        std::memset(page, after_exec ? 'Z' : 'A', ps);
        const Reply initial{reinterpret_cast<std::uintptr_t>(page), 0};
        write_full(responses, &initial, sizeof(initial));

        while (true) {
            char command = 0;
            read_full(commands, &command, 1);
            switch (command) {
            case 'U':
                require(::munmap(page, ps) == 0, "munmap failed");
                break;
            case 'M':
                page = static_cast<char*>(map_page(reinterpret_cast<std::uintptr_t>(page), ps));
                std::memset(page, 'B', ps);
                break;
            case 'P':
                require(::mprotect(page, ps, PROT_NONE) == 0, "mprotect NONE failed");
                break;
            case 'R':
                require(::mprotect(page, ps, PROT_READ | PROT_WRITE) == 0,
                        "mprotect RW failed");
                std::memset(page, 'C', ps);
                break;
            case 'T': {
                // Race a reader against real VMA deletion and recreation.
                const auto address = reinterpret_cast<std::uintptr_t>(page);
                for (int i = 0; i < 1500; ++i) {
                    require(::munmap(page, ps) == 0, "stress munmap failed");
                    page = static_cast<char*>(map_page(address, ps));
                    std::memset(page, 'C', ps);
                }
                break;
            }
            case 'E': {
                const std::string in = std::to_string(commands);
                const std::string out = std::to_string(responses);
                ::execl("/proc/self/exe", "rxr-memory-reader-lifecycle",
                        "--after-exec", in.c_str(), out.c_str(),
                        static_cast<char*>(nullptr));
                fail("execve failed");
            }
            case 'Q':
                ::_exit(0);
            default:
                require(false, "unexpected child command");
            }
            const Reply reply{reinterpret_cast<std::uintptr_t>(page), 0};
            write_full(responses, &reply, sizeof(reply));
        }
    } catch (const std::exception& e) {
        std::cerr << "child FAIL: " << e.what() << '\n';
        ::_exit(2);
    }
}

struct Child {
    pid_t pid = -1;
    int commands = -1;
    int replies = -1;

    Child() {
        int to_child[2];
        int from_child[2];
        require(::pipe(to_child) == 0, "pipe to child failed");
        require(::pipe(from_child) == 0, "pipe from child failed");
        pid = ::fork();
        require(pid >= 0, "fork failed");
        if (pid == 0) {
            (void)::close(to_child[1]);
            (void)::close(from_child[0]);
            child_main(to_child[0], from_child[1], false);
        }
        (void)::close(to_child[0]);
        (void)::close(from_child[1]);
        commands = to_child[1];
        replies = from_child[0];
    }

    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;

    ~Child() {
        if (commands >= 0) (void)::close(commands);
        if (replies >= 0) (void)::close(replies);
        if (pid > 0) {
            (void)::kill(pid, SIGKILL);
            int status = 0;
            while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        }
    }

    Reply next_reply() const {
        Reply r{};
        read_full(replies, &r, sizeof(r));
        require(r.status == 0 && r.address != 0, "invalid child reply");
        return r;
    }

    Reply command(char code) const {
        write_full(commands, &code, 1);
        return next_reply();
    }

    void exit_cleanly() {
        const char code = 'Q';
        write_full(commands, &code, 1);
        int status = 0;
        pid_t w;
        do { w = ::waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
        require(w == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "child exit failed");
        pid = -1;
    }
};

std::unique_ptr<MemoryReader> open_reader(pid_t pid, MemoryReadBackend mode) {
    auto reader = runtimexray::open_memory_reader(pid, mode);
    require(reader != nullptr, "open_memory_reader failed");
    return reader;
}

void expect_bytes(MemoryReader& r, std::uintptr_t address, char expected,
                  const std::string& context) {
    char buf[64]{};
    const ssize_t n = r.read(address, buf, sizeof(buf));
    require(n == static_cast<ssize_t>(sizeof(buf)), context + ": short/failed read");
    for (char byte : buf) {
        require(byte == expected, context + ": unexpected memory bytes");
    }
}

void expect_unreadable(MemoryReader& r, std::uintptr_t address,
                       const std::string& context) {
    char bytes[64]{};
    const ssize_t n = r.read(address, bytes, sizeof(bytes));
    require(n <= 0, context + ": unexpectedly read an unmapped/dead address");
}

void run_one(MemoryReadBackend mode, const char* name) {
    Child child;
    const Reply ready = child.next_reply();
    auto reader = open_reader(child.pid, mode);
    if (mode == MemoryReadBackend::ProcessVmReadv) {
        char check = 0;
        errno = 0;
        const ssize_t n = reader->read(ready.address, &check, 1);
        if (n == -1 && (errno == ENOSYS || errno == EPERM || errno == EACCES)) {
            throw UnsupportedVmRead(std::string("process_vm_readv unavailable: ") +
                                    std::strerror(errno));
        }
        require(n == 1 && check == 'A', "vmread initial probe failed");
    }
    expect_bytes(*reader, ready.address, 'A', "initial mapping");

    const Reply unmapped = child.command('U');
    require(unmapped.address == ready.address, "unmap changed virtual address");
    expect_unreadable(*reader, ready.address, "unmapped VMA");

    const Reply remapped = child.command('M');
    require(remapped.address == ready.address, "remap changed virtual address");
    expect_bytes(*reader, ready.address, 'B', "remapped VMA");

    (void)child.command('P');
    char buf[64]{};
    const ssize_t prot_n = reader->read(ready.address, buf, sizeof(buf));
    if (mode == MemoryReadBackend::ProcessVmReadv) {
        require(prot_n <= 0, "vmread unexpectedly read PROT_NONE");
    } else {
        // /proc/pid/mem uses forced access on many Linux kernels.
        // Record behavior, do not mistake permission differences for parity loss.
        require(prot_n <= 0 || prot_n == static_cast<ssize_t>(sizeof(buf)),
                "proc returned an invalid PROT_NONE read length");
    }
    (void)child.command('R');
    expect_bytes(*reader, ready.address, 'C', "mprotect restoration");
    std::cout << "PASS: " << name << " handles munmap/remap and mprotect";
    if (mode == MemoryReadBackend::ProcMem) {
        std::cout << " (PROT_NONE read=" << prot_n << ")";
    }
    std::cout << '\n';

    // Concurrent modification: a syscall may observe either mapping state.
    // Both a full read and a failed/short read are legitimate outcomes.
    const char race = 'T';
    write_full(child.commands, &race, 1);
    std::size_t successes = 0;
    std::size_t non_full = 0;
    while (true) {
        pollfd pfd{};
        pfd.fd = child.replies;
        pfd.events = POLLIN;
        const int polled = ::poll(&pfd, 1, 0);
        require(polled >= 0, "poll failed");
        if (polled != 0) break;
        const ssize_t n = reader->read(ready.address, buf, sizeof(buf));
        require(n <= static_cast<ssize_t>(sizeof(buf)), "read length exceeds request");
        if (n == static_cast<ssize_t>(sizeof(buf))) ++successes;
        else ++non_full;
    }
    (void)child.next_reply();
    expect_bytes(*reader, ready.address, 'C', "post-race mapping");
    std::cout << "PASS: " << name << " survives concurrent VMA changes"
              << " (full=" << successes << " non_full=" << non_full << ")\n";

    const Reply after_exec = child.command('E');
    if (mode == MemoryReadBackend::ProcMem) {
        // An old /proc/<pid>/mem fd must NOT be reused after execve().
        expect_unreadable(*reader, after_exec.address, "stale ProcMem fd after execve");
    }
    auto new_reader = open_reader(child.pid, mode);
    expect_bytes(*new_reader, after_exec.address, 'Z', "new exec image");
    std::cout << "PASS: " << name << " handles execve with a fresh reader";
    if (mode == MemoryReadBackend::ProcMem) {
        std::cout << " (old reader cannot inspect new mm)";
    }
    std::cout << '\n';

    child.exit_cleanly();
    expect_unreadable(*new_reader, after_exec.address, "dead target process");
    std::cout << "PASS: " << name << " handles target exit\n";
}

} // namespace

int main(int argc, char** argv) {
    ::alarm(25);
    try {
        if (argc == 4 && std::strcmp(argv[1], "--after-exec") == 0) {
            const int input = std::stoi(argv[2]);
            const int output = std::stoi(argv[3]);
            child_main(input, output, true);
        }
        require(argc == 1, "unexpected CLI arguments");
        run_one(MemoryReadBackend::ProcMem, "proc");
        run_one(MemoryReadBackend::ProcessVmReadv, "vmread");
        std::cout << "PASS: Stage D.3 memory reader lifecycle regression\n";
        return 0;
    } catch (const UnsupportedVmRead& e) {
        std::cerr << "SKIP: " << e.what() << " (proc checks passed)\n";
        return 125;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
