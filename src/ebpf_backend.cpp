/**
 * @file    ebpf_backend.cpp
 * @brief   eBPF-based tracing backend implementation.
 *
 * @author  Peter Magram
 * @date    2026-08-25
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

#include "itrace_backend.hpp"
#include "trace_bpf_bytecode.h"
#include "logger.hpp"
#include "syscall_names.hpp"
#include <bpf/libbpf.h>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <linux/types.h>  // for __u32, __u64, __u8

namespace runtimexray {

// Must match the layout used in the eBPF program.
struct syscall_event {
    __u32 pid;
    __u32 tid;
    __u32 syscall_id;
    __u64 args[6];
    __u64 ret;
    __u8 is_entry;
};

class EbpfBackend : public ITraceBackend {
public:
    std::string name() const override { return "ebpf"; }
    bool supports_attach() const override { return false; }
    bool supports_function_tracing() const override { return false; }

    std::string read_string(uint64_t address, size_t max_len) const override {
        if (child_pid_ <= 0) {
            return "";
        }
        return read_process_memory_string(child_pid_, address, max_len);
    }

    std::vector<std::byte> read_memory(uint64_t address, size_t size) const override {
        if (child_pid_ <= 0) {
            return std::vector<std::byte>{};
        }
        return read_process_memory_bytes(child_pid_, address, size);
    }

    bool is_timed_out() const override { return timed_out_; }
    std::string child_output_path() const override { return child_output_path_; }

    int trace(const TraceConfig& config) override {
        // 1. Fork + exec the target program
        follow_forks_ = config.follow_forks;
        debug_enabled_ = config.debug;
        child_pid_ = fork();
        if (child_pid_ == -1) {
            throw std::runtime_error("fork failed: " + std::string(strerror(errno)));
        }

         if (child_pid_ == 0) {
            // Child: redirect stdout/stderr to a file
            child_output_path_ = "/tmp/runtimexray_ebpf_child_" + std::to_string(getpid()) + ".log";
            int fd = open(child_output_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            }

            std::vector<char*> argv;
            argv.reserve(config.args.size() + 1);
            for (const auto& a : config.args) {
                argv.push_back(const_cast<char*>(a.c_str()));
            }
            argv.push_back(nullptr);

            raise(SIGSTOP);   // stop until parent process continues
            execv(config.program.c_str(), argv.data());
            _exit(127);
         }

         // 2. Prepare eBPF
        bpf_object_ = bpf_object__open_mem(trace_bpf_bytecode, trace_bpf_bytecode_len, nullptr);
        if (libbpf_get_error(bpf_object_)) {
            kill(child_pid_, SIGKILL);
            waitpid(child_pid_, nullptr, 0);
            throw std::runtime_error("Failed to open eBPF object: " + std::string(strerror(errno)));
        }

        if (bpf_object__load(bpf_object_)) {
            bpf_object__close(bpf_object_);
            kill(child_pid_, SIGKILL);
            waitpid(child_pid_, nullptr, 0);
            throw std::runtime_error("Failed to load eBPF object");
        }

        bpf_program_enter_ = bpf_object__find_program_by_name(bpf_object_, "trace_sys_enter");
        bpf_program_exit_ = bpf_object__find_program_by_name(bpf_object_, "trace_sys_exit");
        bpf_map_pid_filter_ = bpf_object__find_map_by_name(bpf_object_, "pid_filter");
        bpf_map_events_ = bpf_object__find_map_by_name(bpf_object_, "events");
        if (!bpf_program_enter_ || !bpf_program_exit_ || !bpf_map_pid_filter_ || !bpf_map_events_) {
            bpf_object__close(bpf_object_);
            kill(child_pid_, SIGKILL);
            waitpid(child_pid_, nullptr, 0);
            throw std::runtime_error("Required eBPF objects not found");
        }
        bpf_map_enter_counter_ = bpf_object__find_map_by_name(bpf_object_, "enter_counter");
        bpf_map_exit_counter_ = bpf_object__find_map_by_name(bpf_object_, "exit_counter");
        if (!bpf_map_enter_counter_ || !bpf_map_exit_counter_) {
            std::cerr << "Warning: counter maps not found; debug disabled.\n";
        }

        bpf_map_clone_exit_counter_ = bpf_object__find_map_by_name(bpf_object_, "clone_exit_counter");
        if (!bpf_map_clone_exit_counter_) {
            std::cerr << "Warning: clone_exit_counter map not found; debug disabled.\n";
        }
        bpf_map_ringbuf_reserve_fail_ = bpf_object__find_map_by_name(bpf_object_, "ringbuf_reserve_fail");
        if (!bpf_map_ringbuf_reserve_fail_) {
            std::cerr << "Warning: ringbuf_reserve_fail map not found; debug disabled.\n";
        }        

        __u32 key = static_cast<__u32>(child_pid_);
        __u32 value = key;
        if (bpf_map__update_elem(bpf_map_pid_filter_, &key, sizeof(key), &value, sizeof(value), BPF_ANY) != 0) {            bpf_object__close(bpf_object_);
            kill(child_pid_, SIGKILL);
            waitpid(child_pid_, nullptr, 0);
            throw std::runtime_error("Failed to set PID filter");
        }

        link_enter_ = bpf_program__attach_tracepoint(bpf_program_enter_, "raw_syscalls", "sys_enter");
        link_exit_ = bpf_program__attach_tracepoint(bpf_program_exit_, "raw_syscalls", "sys_exit");
        if (libbpf_get_error(link_enter_) || libbpf_get_error(link_exit_)) {
            if (!libbpf_get_error(link_enter_)) bpf_link__destroy(link_enter_);
            if (!libbpf_get_error(link_exit_)) bpf_link__destroy(link_exit_);
            bpf_object__close(bpf_object_);
            kill(child_pid_, SIGKILL);
            waitpid(child_pid_, nullptr, 0);
            throw std::runtime_error("Failed to attach eBPF tracepoints");
        }

        ring_buffer_ = ring_buffer__new(bpf_map__fd(bpf_map_events_), handle_event, this, nullptr);
        if (!ring_buffer_) {
            bpf_link__destroy(link_enter_);
            bpf_link__destroy(link_exit_);
            bpf_object__close(bpf_object_);
            kill(child_pid_, SIGKILL);
            waitpid(child_pid_, nullptr, 0);
            throw std::runtime_error("Failed to create ring buffer");
        }

        // 3. Main loop: poll ring buffer, wait for child or timeout.
        callback_ = config.callback;
        timed_out_ = false;

        // Continue child process after eBPF is ready
        kill(child_pid_, SIGCONT);

        auto start = std::chrono::steady_clock::now();
        int status = 0;
        bool running = true;
        while (running) {
            ring_buffer__poll(ring_buffer_, 100);

            pid_t res = waitpid(child_pid_, &status, WNOHANG);
            if (res == child_pid_) {
                running = false;
            } else if (res == -1 && errno != EINTR) {
                running = false;
            } else if (config.timeout.count() > 0) {
                auto now = std::chrono::steady_clock::now();
                if (now - start >= config.timeout) {
                    kill(child_pid_, SIGKILL);
                    waitpid(child_pid_, &status, 0);
                    timed_out_ = true;
                    running = false;
                }
            }
        }

        // Drain any remaining events from the ring buffer before cleanup
        while (ring_buffer__poll(ring_buffer_, 0) > 0) {
            // busy-wait until all currently available events are consumed
        }

        // ---- Debug: read counters ----
        if (debug_enabled_) {
            if (bpf_map_clone_exit_counter_) {
                __u32 zero = 0;
                __u64 clone_count = 0;
                if (bpf_map__lookup_elem(bpf_map_clone_exit_counter_, &zero, sizeof(zero), &clone_count, sizeof(clone_count), 0) == 0)
                    Logger::log(LogLevel::Debug, "BPF clone_exit_counter = " + std::to_string(clone_count));
            }
            if (bpf_map_ringbuf_reserve_fail_) {
                __u32 zero = 0;
                __u64 fail_count = 0;
                if (bpf_map__lookup_elem(bpf_map_ringbuf_reserve_fail_, &zero, sizeof(zero), &fail_count, sizeof(fail_count), 0) == 0)
                    Logger::log(LogLevel::Debug, "BPF ringbuf_reserve_fail = " + std::to_string(fail_count));
            }
        }
        
        // Cleanup eBPF resources
        ring_buffer__free(ring_buffer_);
        bpf_link__destroy(link_enter_);
        bpf_link__destroy(link_exit_);
        bpf_object__close(bpf_object_);
        ring_buffer_ = nullptr;
        bpf_object_ = nullptr;

        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        if (WIFSIGNALED(status))
            return -1;
        return timed_out_ ? -2 : 0;
    }

private:

    void add_pid_to_filter(pid_t pid) {
        Logger::log(LogLevel::Debug, "Adding PID " + std::to_string(pid) + " to eBPF filter");

        __u32 key = static_cast<__u32>(pid);
        __u32 value = key;
        int err = bpf_map__update_elem(bpf_map_pid_filter_, &key, sizeof(key),
                                       &value, sizeof(value), BPF_ANY);
        if (err < 0 && debug_enabled_) {
            std::cerr << "Warning: failed to add PID " << pid
                      << " to eBPF filter: " << std::strerror(-err) << "\n";
            Logger::log(LogLevel::Error, "Failed to add PID " + std::to_string(pid) +
                        " to eBPF filter: " + std::strerror(-err));
        } else {
            Logger::log(LogLevel::Debug, "Successfully added PID " + std::to_string(pid));
        }
    }

    void handle_fork_event(const struct syscall_event* ev) {
        const char* name = syscall_name(ev->syscall_id);
        Logger::log(LogLevel::Debug, "handle_fork_event: syscall=" + std::to_string(ev->syscall_id) +
                    " name=" + name + " is_entry=" + std::to_string(ev->is_entry) +
                    " ret=" + std::to_string(ev->ret));
        
        if (!follow_forks_) {
            return;
        }
        if (ev->is_entry) {
            return;
        }
        if (ev->ret <= 0) {
            return;
        }
        bool is_fork_like = (strcmp(name, "fork") == 0 ||
                             strcmp(name, "vfork") == 0 ||
                             strcmp(name, "clone") == 0 ||
                             strcmp(name, "clone3") == 0);

        // Fallback: check syscall numbers directly (ARM64: clone=220, clone3=435)
        if (!is_fork_like && (ev->syscall_id == 220 || ev->syscall_id == 435)) {
            is_fork_like = true;
        }

        if (is_fork_like) {
            Logger::log(LogLevel::Debug, "Fork-like syscall detected, adding PID " + std::to_string(ev->ret));
            add_pid_to_filter(static_cast<pid_t>(ev->ret));
        }
    }
    // Support functions for process memory reading (like Tachikoma)

    static std::vector<std::byte> read_process_memory_bytes(pid_t pid, uint64_t addr, size_t size) {
        std::vector<std::byte> buffer(size);

        struct iovec local;
        local.iov_base = buffer.data();
        local.iov_len = size;

        struct iovec remote;
        remote.iov_base = reinterpret_cast<void*>(addr);
        remote.iov_len = size;

        ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (n < 0) { return std::vector<std::byte>{}; }
        buffer.resize(static_cast<size_t>(n));
        return buffer;
    }

    static std::string read_process_memory_string(pid_t pid, uint64_t addr, size_t max_len) {
        std::string result;
        char buffer[256];
        size_t total = 0;

        while (total < max_len) {
            struct iovec local;
            local.iov_base = buffer;
            local.iov_len = sizeof(buffer);

            struct iovec remote;
            remote.iov_base = reinterpret_cast<void*>(addr + total);
            remote.iov_len = sizeof(buffer);

            ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (n <= 0) {
                break;
            }

            for (ssize_t i = 0; i < n; ++i) {
                char c = buffer[i];
                if (c == '\0') {
                    return result;
                }
                result.push_back(c);
                if (result.size() >= max_len) {
                    return result;
                }
            }
            total += static_cast<size_t>(n);
        }
        return result;
    }

    // Callback for ring buffer
    static int handle_event(void *ctx, void *data, size_t /*len*/) {
        auto* backend = static_cast<EbpfBackend*>(ctx);
        if (!backend) {
            return 0;
        }

        struct syscall_event* ev = static_cast<struct syscall_event*>(data);
        // ---- Conditional debug logging ----
        if (getenv("EBPF_DEBUG")) {
            static FILE* log = fopen("/tmp/ebpf_debug.log", "a");
            if (log) {
                fprintf(log, "handle_event: pid=%d, syscall=%d, entry=%d\n",
                        ev->pid, ev->syscall_id, ev->is_entry);
                fflush(log);
            }
        }
        // --- end debug ---        
        runtimexray::SyscallEvent event;
        event.pid = static_cast<pid_t>(ev->pid);
        event.tid = static_cast<pid_t>(ev->tid);
        event.syscall_number = ev->syscall_id;
        event.is_entry = (ev->is_entry != 0);
        event.arg0 = ev->args[0];
        event.arg1 = ev->args[1];
        event.arg2 = ev->args[2];
        event.arg3 = ev->args[3];
        event.arg4 = ev->args[4];
        event.arg5 = ev->args[5];
        event.return_value = static_cast<long long>(ev->ret);
        backend->handle_fork_event(ev);

        if (backend->callback_) {
            backend->callback_(event);
        }

        return 0;
    }

    // members
    pid_t child_pid_ = -1;
    bool timed_out_ = false;
    std::string child_output_path_;
    TraceEventCallback callback_;
    bool follow_forks_ = true;
    bool debug_enabled_ = false;

    struct bpf_object* bpf_object_ = nullptr;
    struct bpf_program* bpf_program_enter_ = nullptr;
    struct bpf_program* bpf_program_exit_ = nullptr;
    struct bpf_map* bpf_map_pid_filter_ = nullptr;
    struct bpf_map* bpf_map_events_ = nullptr;
    struct bpf_map* bpf_map_enter_counter_ = nullptr;
    struct bpf_map* bpf_map_exit_counter_ = nullptr;
    struct bpf_map* bpf_map_clone_exit_counter_ = nullptr;
    struct bpf_map* bpf_map_ringbuf_reserve_fail_ = nullptr;
    struct bpf_link* link_enter_ = nullptr;
    struct bpf_link* link_exit_ = nullptr;
    struct ring_buffer* ring_buffer_ = nullptr;
};

std::unique_ptr<ITraceBackend> create_ebpf_backend() {
    return std::make_unique<EbpfBackend>();
}

} // namespace runtimexray