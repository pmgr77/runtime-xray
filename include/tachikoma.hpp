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
#include <functional>
#include <cstdint>
#include <chrono>

namespace runtimexray {

/**
 * @brief Represents a captured system call event.
 */
struct SyscallEvent {
    unsigned long long syscall_number;    ///< System call number (x86_64)
    unsigned long long arg0, arg1, arg2, arg3, arg4, arg5; ///< Arguments (simplified)
    long long return_value;      ///< Return value (valid on exit)
    pid_t pid;              ///< Process ID
    bool is_entry;          ///< true = syscall entry, false = exit
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

    void handle_syscall_stop(const SyscallCallback& cb, bool& in_syscall);
};
} // namespace runtimexray

#endif // RUNTIMEXRAY_TACHIKOMA_HPP