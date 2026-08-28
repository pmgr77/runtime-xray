/**
 * @file    tachikoma.cpp
 * @brief   Implements Tachikoma – a ptrace-based process tracer.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "tachikoma.hpp"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <chrono>
#include <algorithm>
#include <sys/uio.h>   // for process_vm_readv and struct iovec
#include <set>
#include <map>

#if defined(__aarch64__)
#include <sys/uio.h>      // for struct iovec
#include <elf.h>          // for NT_PRSTATUS
#include <asm/ptrace.h>   // for struct user_pt_regs
#endif

namespace runtimexray {

    // ---------------------------------------------------------------------------
    // Architecture-specific register reading
    // ---------------------------------------------------------------------------

#if defined(__x86_64__)

    struct Registers {
        unsigned long long syscall_number;
        unsigned long long args[6];
        long long return_value;
    };

    Registers read_registers(pid_t pid) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
            throw std::runtime_error(std::string("PTRACE_GETREGS failed: ") + std::strerror(errno));
        }

        Registers out;
        out.syscall_number = regs.orig_rax;
        out.args[0] = regs.rdi;
        out.args[1] = regs.rsi;
        out.args[2] = regs.rdx;
        out.args[3] = regs.r10;
        out.args[4] = regs.r8;
        out.args[5] = regs.r9;
        out.return_value = static_cast<long long>(regs.rax);
        return out;
    }

#elif defined(__aarch64__)

    struct Registers {
        unsigned long long syscall_number;
        unsigned long long args[6];
        long long return_value;
    };

    Registers read_registers(pid_t pid) {
        struct iovec iov;
        struct user_pt_regs regs;   // ARM64 user registers
        iov.iov_base = &regs;
        iov.iov_len = sizeof(regs);

        if (ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &iov) == -1) {
            throw std::runtime_error(std::string("PTRACE_GETREGSET failed: ") + std::strerror(errno));
        }

        Registers out;
        out.syscall_number = regs.regs[8];   // x8 holds syscall number on ARM64
        out.args[0] = regs.regs[0];
        out.args[1] = regs.regs[1];
        out.args[2] = regs.regs[2];
        out.args[3] = regs.regs[3];
        out.args[4] = regs.regs[4];
        out.args[5] = regs.regs[5];
        out.return_value = static_cast<long long>(regs.regs[0]);
        return out;
    }

#else
#error "Unsupported architecture for Tachikoma (only x86_64 and ARM64 are supported)"
#endif

    // ---------------------------------------------------------------------------
    // Tachikoma implementation (constructor, destructor, move, run)
    // ---------------------------------------------------------------------------

    Tachikoma::Tachikoma(const std::string& program, const std::vector<std::string>& args) {
        if (program.empty()) {
            throw std::runtime_error("Tachikoma: program path is empty");
        }

        child_pid_ = fork();
        if (child_pid_ == -1) {
            throw std::runtime_error(std::string("fork failed: ") + std::strerror(errno));
        }

        if (child_pid_ == 0) {
            // Generate a unique output file name based on child's PID
            child_output_path_ = "/tmp/runtimexray_child_" + std::to_string(getpid()) + ".log";

            int fd = open(child_output_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            }

            // Child process
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
                _exit(1);
            }

            std::vector<char*> argv_ptrs;
            argv_ptrs.reserve(args.size() + 1);
            for (const auto& a : args) {
                argv_ptrs.push_back(const_cast<char*>(a.c_str()));
            }
            argv_ptrs.push_back(nullptr);

            execv(program.c_str(), argv_ptrs.data());
            _exit(1); // exec failed
        } else {
            // Parent
            running_ = true;
            child_output_path_ = "/tmp/runtimexray_child_" + std::to_string(child_pid_) + ".log";
            int status;
            if (waitpid(child_pid_, &status, 0) == -1) {
                running_ = false;
                throw std::runtime_error(std::string("waitpid failed: ") + std::strerror(errno));
            }
            
            // Set ptrace options to trace forks, vforks, clones, and exits
            if (ptrace(PTRACE_SETOPTIONS, child_pid_, nullptr,
                        PTRACE_O_TRACEFORK |
                        PTRACE_O_TRACEVFORK |
                        PTRACE_O_TRACECLONE |
                        PTRACE_O_TRACEEXIT) == -1) {
                throw std::runtime_error(std::string("PTRACE_SETOPTIONS failed: ") + std::strerror(errno));
            }
            
            traced_pids_.insert(child_pid_);
            in_syscall_state_[child_pid_] = false;
            
            if (ptrace(PTRACE_SYSCALL, child_pid_, nullptr, nullptr) == -1) {
                running_ = false;
                throw std::runtime_error(std::string("ptrace(PTRACE_SYSCALL) failed: ") + std::strerror(errno));
            }
        }
    }

    Tachikoma::~Tachikoma() {
        // Kill all traced processes
        for (pid_t p : traced_pids_) {
            kill(p, SIGKILL);
        }
        // Reap all children to avoid zombies
        while(!traced_pids_.empty()) {
            pid_t p = waitpid(-1, nullptr, 0);
            if (p > 0) {
                traced_pids_.erase(p);
            }
        }
    }

    Tachikoma::Tachikoma(Tachikoma&& other) noexcept
        : child_pid_(other.child_pid_),
          running_(other.running_),
          timed_out_(other.timed_out_),
          timeout_(other.timeout_),
          child_output_path_(std::move(other.child_output_path_)),
          follow_forks_(other.follow_forks_),
          traced_pids_(std::move(other.traced_pids_)),
          in_syscall_state_(std::move(other.in_syscall_state_)) {
        other.child_pid_ = -1;
        other.running_ = false;
        other.timed_out_ = false;
        other.traced_pids_.clear();
        other.in_syscall_state_.clear();
    }

    Tachikoma& Tachikoma::operator=(Tachikoma&& other) noexcept {
        if (this != &other) {
            // Clean up current resources
            for (pid_t p : traced_pids_) {
                kill(p, SIGKILL);
            }
            while (!traced_pids_.empty()) {
                waitpid(-1, nullptr, -1);
            }

            child_pid_ = other.child_pid_;
            running_ = other.running_;
            timed_out_ = other.timed_out_;
            timeout_ = other.timeout_;
            child_output_path_ = std::move(other.child_output_path_);
            follow_forks_ = other.follow_forks_;
            traced_pids_ = std::move(other.traced_pids_);
            in_syscall_state_ = std::move(other.in_syscall_state_);

            other.child_pid_ = -1;
            other.running_ = false;
            other.timed_out_ = false;
            other.traced_pids_.clear();
            other.in_syscall_state_.clear();
        }
        return *this;
    }

    std::string Tachikoma::read_string(uint64_t address, size_t max_len) const {
        if (address == 0 || max_len == 0 || child_pid_ <= 0) {
            return std::string{};
        }

        std::string result;
        char buffer[256] = { 0 };
        size_t total_read = 0;

        while (total_read < max_len) {
            struct iovec local;
            local.iov_base = buffer;
            local.iov_len = sizeof(buffer);

            struct iovec remote;
            remote.iov_base = reinterpret_cast<void*>(static_cast<uintptr_t>(address + total_read));
            remote.iov_len = sizeof(buffer);

            ssize_t n = process_vm_readv(child_pid_, &local, 1, &remote, 1, 0);
            if (n <= 0) {
                break; // error or no more data
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
            total_read += static_cast<size_t>(n);
        }
        return result;
    }

    std::vector<std::byte> Tachikoma::read_memory(uint64_t address, size_t size) const {
        std::vector<std::byte> buffer(size);
        if (address == 0 || child_pid_ <= 0) {
            return std::vector<std::byte>{};
        }

        struct iovec local;
        local.iov_base = buffer.data();
        local.iov_len = size;

        struct iovec remote;
        remote.iov_base = reinterpret_cast<void*>(static_cast<uintptr_t>(address));
        remote.iov_len = size;

        ssize_t n = process_vm_readv(child_pid_, &local, 1, &remote, 1, 0);
        if (n < 0) {
            return {};
        }
        buffer.resize(static_cast<size_t>(n));
        return buffer;
    }

    // ---------------------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------------------

    // Handle a ptrace event (fork, clone, etc.)
    bool Tachikoma::handle_ptrace_event(pid_t pid, int status, const SyscallCallback& cb) {
        (void)status;
        (void)cb;

        unsigned long new_pid;
        if (ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid) == -1) {
            return false;
        }
        pid_t child = static_cast<pid_t>(new_pid);

        if (follow_forks_) {
            // The child is already attached; just set options to trace its own forks
            // Trace the child: set options and continue with PTRACE_SYSCALL
            if (ptrace(PTRACE_SETOPTIONS, child, nullptr,
                   PTRACE_O_TRACEFORK |
                   PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEEXIT) == -1) {
                throw std::runtime_error(std::string("PTRACE_SETOPTIONS on child failed: pid=") + std::to_string(child) + " " + std::strerror(errno));
            }
            traced_pids_.insert(child);
            in_syscall_state_[child] = false;
            // Continue the child
            if (ptrace(PTRACE_SYSCALL, child, nullptr, nullptr) == -1) {
                throw std::runtime_error(std::string("PTRACE_SYSCALL on child failed: pid=") + std::to_string(child) + " " + std::strerror(errno));
            }
        } else {
            // Do NOT trace the child: continue it normally (untraced)
            if (ptrace(PTRACE_DETACH, child, nullptr, nullptr) == -1) {
                throw std::runtime_error(std::string("PTRACE_DETACH on child failed: pid=") + std::to_string(child) + " " + std::strerror(errno));
            }
            // Do NOT add child to traced_pids_ – it will not be waited for
        }

        // Continue the parent
        if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
            throw std::runtime_error(std::string("PTRACE_SYSCALL on parent failed: pid=") + std::to_string(pid) + " " + std::strerror(errno));
        }
        return true;
    }

    // Process a syscall stop for a specific PID
    void Tachikoma::handle_syscall_stop(pid_t pid, const SyscallCallback& cb, bool& in_syscall) {
        // Read registers to get syscall number and ar
        Registers regs = read_registers(pid);

        SyscallEvent ev;
        ev.pid = pid;
        ev.tid = pid;
        ev.syscall_number = regs.syscall_number;
        ev.arg0 = regs.args[0];
        ev.arg1 = regs.args[1];
        ev.arg2 = regs.args[2];
        ev.arg3 = regs.args[3];
        ev.arg4 = regs.args[4];
        ev.arg5 = regs.args[5];

        if (!in_syscall) {
            // Syscall entry
            ev.is_entry = true;
            ev.return_value = 0;
            cb(ev);
            in_syscall = true;
        } else {
            // Syscall exit
            ev.is_entry = false;
            ev.return_value = regs.return_value;
            cb(ev);
            in_syscall = false;
        }

        // Continue
        if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
            running_ = false;
            throw std::runtime_error(std::string("ptrace(PTRACE_SYSCALL) failed: pid=") + std::to_string(pid) + " " + std::strerror(errno));
        }
    }

    // ---------------------------------------------------------------------------
    // Main tracing loop
    // ---------------------------------------------------------------------------

    int Tachikoma::run(const SyscallCallback& cb) {
        if (!running_) {
            throw std::runtime_error("Tachikoma: not running");
        }

        int status;
        timed_out_ = false;
        auto start_time = std::chrono::steady_clock::now();

        // Loop until all traced processes have exited
        while (!traced_pids_.empty() && running_) {
            // Check timeout (relative to the start of the whole trace)
            if (timeout_.count() > 0) {
                auto now = std::chrono::steady_clock::now();
                if ((now - start_time) >= timeout_) {
                    // Kill all remaining processes
                    for (pid_t p : traced_pids_) {
                        kill(p, SIGKILL);
                    }
                    // Reap them
                    while (!traced_pids_.empty()) {
                        pid_t p = waitpid(-1, nullptr, 0);
                        if (p > 0) {
                            traced_pids_.erase(p);
                        }
                    }
                    timed_out_ = true;
                    return -2; // timeout code
                }
            }

            // Wait for any traced process, non-blocking
            pid_t pid = waitpid(-1, &status, __WALL | WNOHANG);
            if (pid == -1) {
                if (errno == EINTR) {
                    continue;
                }
                running_ = false;
                throw std::runtime_error(std::string("waitpid failed: pid=") + std::to_string(pid) + " " + std::strerror(errno));
            }
            if (pid == 0) {
                // No event yet – sleep a bit to avoid busy-wait
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            // Process event for this pid
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                // Process terminated
                traced_pids_.erase(pid);
                in_syscall_state_.erase(pid);
                if (traced_pids_.empty()) {
                    running_ = false;
                    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                }
                continue;                
            }

            if (WIFSTOPPED(status)) {
                unsigned int event = static_cast<unsigned int>(status >> 16);
                if (event == PTRACE_EVENT_FORK ||
                    event == PTRACE_EVENT_VFORK ||
                    event == PTRACE_EVENT_CLONE) {
                    // New child created
                    handle_ptrace_event(pid, status, cb);
                    continue;
                }

                // Otherwise it's a syscall entry/exit stop
                auto it = in_syscall_state_.find(pid);
                if (it == in_syscall_state_.end()) {
                    // Should not happen – initialize
                    in_syscall_state_[pid] = false;
                    it = in_syscall_state_.find(pid);
                }
                handle_syscall_stop(pid, cb, it->second);
            }
        }

        return 0;
    }

    // ---------------------------------------------------------------------------
    // Public setters
    // ---------------------------------------------------------------------------

    void Tachikoma::set_follow_forks(bool follow) {
        follow_forks_ = follow;
    }

} // namespace runtimexray