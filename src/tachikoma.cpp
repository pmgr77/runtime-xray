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

namespace runtimexray {

    Tachikoma::Tachikoma(const std::string& program, const std::vector<std::string>& args)
    {
        if (program.empty()) {
            throw std::runtime_error("Tachikoma: program path is empty");
        }

        child_pid_ = fork();
        if (child_pid_ == -1) {
            throw std::runtime_error(std::string("fork failed: ") + std::strerror(errno));
        }

        if (child_pid_ == 0) {
            // Child
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
                _exit(1);
            }

            std::vector<char *> argv_ptrs;
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
            int status;
            if (waitpid(child_pid_, &status, 0) == -1) {
                running_ = false;
                throw std::runtime_error(std::string("waitpid failed: ") + std::strerror(errno));
            }
            if (ptrace(PTRACE_SYSCALL, child_pid_, nullptr, 0) == -1) {
                running_ = false;
                throw std::runtime_error(std::string("ptrace(PTRACE_SYSCALL) failed: ") + std::strerror(errno));
            }
        }
    }

    Tachikoma::~Tachikoma()
    {
        if (child_pid_ > 0 && running_) {
            kill(child_pid_, SIGKILL);
            waitpid(child_pid_, nullptr, 0);
        }
    }

    Tachikoma::Tachikoma(Tachikoma&& other) noexcept 
        : child_pid_(other.child_pid_), running_(other.running_)
    {
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

    int Tachikoma::run(const SyscallCallback& cb)
    {
        if (!running_) {
            throw std::runtime_error("Tachikoma: not running");
        }

        int status;
        int in_syscall = false; // false = entry, true = exit

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
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, child_pid_, nullptr, &regs) == -1) {
                    running_ = false;
                    throw std::runtime_error(std::string("PTRACE_GETREGS failed: ") + std::strerror(errno));
                }

                SyscallEvent ev;
                ev.pid = child_pid_;
                ev.syscall_number = regs.orig_rax; // x86_64
                ev.arg0 = regs.rdi;
                ev.arg1 = regs.rsi;
                ev.arg2 = regs.rdx;
                ev.arg3 = regs.r10;
                ev.arg4 = regs.r8;
                ev.arg5 = regs.r9;
                
                if (!in_syscall) {
                    // Syscall entry
                    ev.is_entry = true;
                    ev.return_value = 0;
                    cb(ev);
                    in_syscall = true;
                } else {
                    // Syscall exit
                    ev.is_entry = false;
                    ev.return_value = static_cast<long long>(regs.rax);
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