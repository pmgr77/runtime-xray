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
#include <sys/uio.h>   // for process_vm_readv and struct iovec
#include <fcntl.h>

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
            if (ptrace(PTRACE_SYSCALL, child_pid_, nullptr, nullptr) == -1) {
                running_ = false;
                throw std::runtime_error(std::string("ptrace(PTRACE_SYSCALL) failed: ") + std::strerror(errno));
            }
        }
    }

    Tachikoma::~Tachikoma() {
        if (child_pid_ > 0 && running_) {
            kill(child_pid_, SIGKILL);
            waitpid(child_pid_, nullptr, 0);
        }
    }

    Tachikoma::Tachikoma(Tachikoma&& other) noexcept
        : child_pid_(other.child_pid_), running_(other.running_) {
        other.child_pid_ = -1;
        other.running_ = false;
    }

    Tachikoma& Tachikoma::operator=(Tachikoma&& other) noexcept {
        if (this != &other) {
            if (child_pid_ > 0 && running_) {
                kill(child_pid_, SIGKILL);
                waitpid(child_pid_, nullptr, 0);
            }
            child_pid_ = other.child_pid_;
            running_ = other.running_;
            other.child_pid_ = -1;
            other.running_ = false;
        }
        return *this;
    }

    std::string Tachikoma::read_string(uint64_t address, size_t max_len) const {
        if (address == 0 || max_len == 0) {
            return {};
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
        if (address == 0) {
            return {};
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

    int Tachikoma::run(const SyscallCallback& cb) {
        if (!running_) {
            throw std::runtime_error("Tachikoma: not running");
        }

        int status;
        bool in_syscall = false; // false = entry, true = exit

        while (running_) {
            if (waitpid(child_pid_, &status, 0) == -1) {
                running_ = false;
                throw std::runtime_error(std::string("waitpid failed: ") + std::strerror(errno));
            }

            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                running_ = false;
                return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            }

            if (WIFSTOPPED(status)) {
                // Read registers to get syscall number and ar
                Registers regs = read_registers(child_pid_);

                SyscallEvent ev;
                ev.pid = child_pid_;
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
                if (ptrace(PTRACE_SYSCALL, child_pid_, nullptr, nullptr) == -1) {
                    running_ = false;
                    throw std::runtime_error(std::string("ptrace(PTRACE_SYSCALL) failed: ") + std::strerror(errno));
                }
            }
        }
        return 0;
    }

} // namespace runtimexray