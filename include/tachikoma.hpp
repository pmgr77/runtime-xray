/**
 * @file    tachikoma.hpp
 * @brief   Tachikoma - a ptrace-based process tracer inspired by Ghost in the Shell.
 *
 * @author  Peter Magram
 * @date    2026-08-17
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

#ifndef RUNTIMEXRAY_TACHIKOMA_HPP
#define RUNTIMEXRAY_TACHIKOMA_HPP

#include <string>
#include <vector>
#include <set>
#include <map>
#include <functional>
#include <cstdint>
#include <chrono>

namespace runtimexray {

/**
 * @brief A single syscall event observed by a tracing backend.
 *
 * Some backends (eBPF) can capture userspace bytes at tracepoint time — the
 * only moment at which they are guaranteed still valid. Those backends
 * populate the `captured_*` fields below with the raw bytes and leave the
 * argN values as-is.
 *
 * Backends that stop the target (ptrace) cannot capture at tracepoint time
 * in this way, so they leave the `captured_*` fields empty. Consumers must
 * prefer the captured value when present and only fall back to
 * ITraceBackend::read_string / read_memory when the captured field is empty.
 */
struct SyscallEvent {
    unsigned long long syscall_number = 0;  ///< System call number (x86_64)
    unsigned long long arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0; ///< Arguments (simplified)
    long long return_value = 0;         ///< Return value (valid on exit)
    pid_t pid = -1;                     ///< Process ID
    pid_t tid = -1;                     ///< Thread ID
    bool is_entry = true;               ///< true = syscall entry, false = exit

    // ---- Bytes captured in-kernel, at tracepoint time --------------------
    //
    // If any of these are non-empty, the corresponding handler in
    // trace_command.cpp must use them instead of reading target memory
    // after the fact. That is what removes the asynchronous-read race.

    // Resolved path for open/openat/execve/execveat.
    std::string captured_path;

    // Resolved "ip:port" endpoint for connect (filled by trace_command after parsing).
    //std::string captured_endpoint;

    // raw sockaddr bytes, connect only
    std::vector<std::byte> captured_sockaddr;

    // Raw userspace buffer content for read/recvfrom/write/writev/sendto.
    // Already truncated by the backend to its capture limit; may be shorter
    // than the syscall's count argument.
    std::vector<std::byte> captured_payload;
};

using SyscallCallback = std::function<void(const SyscallEvent&)>;

/**
 * @brief Tachikoma - RAII ptrace tracer.
 *
 * Starts a child process and traces its system calls.
 * Move-only; not copyable.
 */
class Tachikoma {
public:
    Tachikoma() = default;

    /**
     * @param program Path to executable.
     * @param args Command-line arguments (including argv[0]).
     */
    explicit Tachikoma(const std::string& program, const std::vector<std::string>& args);

    ~Tachikoma();

    // Move semantics
    Tachikoma(Tachikoma&& other) noexcept;
    Tachikoma& operator=(Tachikoma&& other) noexcept;
    Tachikoma(const Tachikoma&) = delete;
    Tachikoma operator=(const Tachikoma&) = delete;

    /**
     * @brief Sets a timeout for tracing.
     * @param timeout Maximum duration to trace. Zero means no timeout.
     */
    void set_timeout(std::chrono::seconds timeout) noexcept {
        timeout_ = timeout;
    }

    const auto& timeout() const noexcept { return timeout_; }

    pid_t get_pid() const noexcept { return child_pid_; }

    // Enable/disable following forks
    void set_follow_forks(bool follow);

    /**
    * @brief Reads a null-terminated string from the traced process memory.
    * @param address Virtual address of the string in the traced process.
    * @param max_len Maximum number of bytes to read.
    * @return String contents (without the null terminator).
    */
    std::string read_string(uint64_t address, size_t max_len = 256) const;

    /**
     * @brief Reads arbitrary bytes from the traced process memory.
     * @param address Virtual address in the traced process.
     * @param size Number of bytes to read.
     * @return Vector of bytes (empty on error).
     */
    std::vector<std::byte> read_memory(uint64_t address, size_t size) const;
     /**
     * @brief Runs the trace loop, invoking callback for each syscall.
     * @param cb Callback receiving SyscallEvent.
     * @return Exit status of traced process, or -1 if killed by signal.
     */
    int run(const SyscallCallback& cb);

    bool is_running() const noexcept { return running_; }

    /**
     * @brief Returns true if the tracing ended because of timeout.
     */
    bool is_timed_out() const noexcept { return timed_out_; }

    /**
     * @brief Returns the path where the child's stdout/stderr is saved.
     */
    const std::string& child_output_path() const noexcept { return child_output_path_; }


private:
    pid_t child_pid_ = -1;
    bool running_ = false;
    bool timed_out_ = false;
    std::chrono::seconds timeout_{0};
    std::string child_output_path_;
    bool follow_forks_ = true;
    std::set<pid_t> traced_pids_;   // all processes currently traced
    std::map<pid_t, bool> in_syscall_state_;

    void handle_syscall_stop(const SyscallCallback& cb, bool& in_syscall);

    // Helper to handle ptrace events (fork, clone, etc.)
    bool handle_ptrace_event(pid_t pid, int status, const SyscallCallback& cb);
    // Process a syscall stop for a specific PID
    void handle_syscall_stop(pid_t pid, const SyscallCallback& cb, bool& in_syscall);
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_TACHIKOMA_HPP
