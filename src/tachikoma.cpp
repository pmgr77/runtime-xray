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
#include "logger.hpp"

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

// PTRACE_GET_SYSCALL_INFO and struct ptrace_syscall_info come from
// <linux/ptrace.h>. That header cannot be included alongside glibc's
// <sys/ptrace.h>: it redefines every PTRACE_* constant as a plain integer
// macro, which breaks implicit conversion to the __ptrace_request enum
// used in the ptrace() prototype, and therefore every other ptrace() call
// in this file.
//
// PTRACE_GET_SYSCALL_INFO itself is already declared in glibc's
// <sys/ptrace.h> enum (glibc >= 2.28). We only need to supply the
// PTRACE_SYSCALL_INFO_* operation codes and the struct that the kernel
// fills in.

#ifndef PTRACE_SYSCALL_INFO_NONE
# define PTRACE_SYSCALL_INFO_NONE    0
# define PTRACE_SYSCALL_INFO_ENTRY   1
# define PTRACE_SYSCALL_INFO_EXIT    2
# define PTRACE_SYSCALL_INFO_SECCOMP 3
#endif

struct ptrace_syscall_info {
    unsigned char      op;
    unsigned char      pad[3];
    unsigned int       arch;
    unsigned long long instruction_pointer;
    unsigned long long stack_pointer;
    union {
        struct {
            unsigned long long nr;
            unsigned long long args[6];
        } entry;
        struct {
            long long     rval;
            unsigned char is_error;
        } exit;
        struct {
            unsigned long long nr;
            unsigned long long args[6];
            unsigned int       ret_data;
        } seccomp;
    };
};

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

            int fd = open(child_output_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
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
                        PTRACE_O_TRACEEXIT |
                        PTRACE_O_TRACESYSGOOD) == -1) {
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
            // The child was created by PTRACE_O_TRACECLONE/FORK/VFORK. The
            // kernel does not queue the child's initial SIGSTOP until the
            // parent is resumed from its clone event, so a blocking waitpid
            // here would deadlock. Use WNOHANG: if the stop has not arrived
            // yet, we fall into the `else` branch, resume the parent, and
            // let the main loop adopt the child when its SIGSTOP arrives.
            int child_status;
            pid_t wait_result = waitpid(child, &child_status, __WALL | WNOHANG);
            if (wait_result == -1) {
                // Child may have already exited – log and skip.
                // Continue the parent without tracing this child.
                if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
                    throw std::runtime_error(std::string("PTRACE_SYSCALL on parent failed: pid=") + std::to_string(pid) + " " + std::strerror(errno));
                }
                return true;
            }
            if (wait_result == child && WIFSTOPPED(child_status)) {
                // Child is stopped – set options and add to traced set.
                if (ptrace(PTRACE_SETOPTIONS, child, nullptr,
                        PTRACE_O_TRACEFORK |
                        PTRACE_O_TRACEVFORK |
                        PTRACE_O_TRACECLONE |
                        PTRACE_O_TRACEEXIT |
                        PTRACE_O_TRACESYSGOOD) == -1) {
                    // If setting options fails (e.g., child died), just continue.
                    // Log error but don't crash.
                    // Continue the parent.
                    if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
                        throw std::runtime_error(std::string("PTRACE_SYSCALL on parent failed: pid=") + std::to_string(pid) + " " + std::strerror(errno));
                    }
                    return true;
                }
                traced_pids_.insert(child);
                in_syscall_state_[child] = false;
                // Continue the child
                if (ptrace(PTRACE_SYSCALL, child, nullptr, nullptr) == -1) {
                    throw std::runtime_error(std::string("PTRACE_SYSCALL on child failed: pid=") + std::to_string(child) + " " + std::strerror(errno));
                }
            } else {
                // Child is not stopped (maybe exited) – do not trace it.
                // Detach if necessary (but it might already be detached).
                // Just continue the parent.
                if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
                    throw std::runtime_error(std::string("PTRACE_SYSCALL on parent failed: pid=") + std::to_string(pid) + " " + std::strerror(errno));
                }
                return true;
            }
        } else {
            // Do NOT trace the child: continue it normally (untraced)
            if (ptrace(PTRACE_DETACH, child, nullptr, nullptr) == -1) {
                throw std::runtime_error(std::string("PTRACE_DETACH on child failed: pid=") + std::to_string(child) + " " + std::strerror(errno));
            }
            // Do NOT add child to traced_pids_ – it will not be waited for
        }

        // Continue the parent (only reached if we successfully handled the child)
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
        ev.tid = pid; // ptrace traces individual threads
        ev.syscall_number = regs.syscall_number;
        ev.arg0 = regs.args[0];
        ev.arg1 = regs.args[1];
        ev.arg2 = regs.args[2];
        ev.arg3 = regs.args[3];
        ev.arg4 = regs.args[4];
        ev.arg5 = regs.args[5];

        // Ask the kernel directly whether this stop is a syscall entry or exit.
        // The state machine (`in_syscall`) is unreliable around clone/adopt and
        // signal delivery; it has caused entry stops to be reported as exits,
        // which produced `ret=-100` (= AT_FDCWD, the first argument to openat)
        // in earlier runs. The kernel knows the answer, so we always ask it.
        // The state machine is kept only as a fallback if the query fails.
        //
        // Note: PTRACE_GET_SYSCALL_INFO does NOT use an iovec. The `addr`
        // argument is the size of the buffer, and `data` points directly to
        // the struct ptrace_syscall_info that the kernel fills in.
        bool entry_stop = !in_syscall;

        struct ptrace_syscall_info info;
        errno = 0;
        long ptrace_ret = ptrace(PTRACE_GET_SYSCALL_INFO, pid,
                             reinterpret_cast<void*>(sizeof(info)), &info);
        if (ptrace_ret != -1) {
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY)
                entry_stop = true;
            else if (info.op == PTRACE_SYSCALL_INFO_EXIT)
                entry_stop = false;
        }

        if (entry_stop) {
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
            throw std::runtime_error(std::string("ptrace(PTRACE_SYSCALL) failed: pid=") +
                std::to_string(pid) + " " + std::strerror(errno));
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

        // Loop until every traced process has exited or the timeout fires.
        while (!traced_pids_.empty() && running_) {

            // -------------------------------------------------------------------
            // Timeout check (relative to the start of the whole trace)
            // -------------------------------------------------------------------
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

            // -------------------------------------------------------------------
            // Wait for any traced process (including threads: __WALL)
            // -------------------------------------------------------------------
            pid_t pid = waitpid(-1, &status, __WALL | WNOHANG);
            if (pid == -1) {
                if (errno == EINTR) {
                    continue;
                }
                running_ = false;
                throw std::runtime_error(
                    std::string("waitpid failed: pid=") + std::to_string(pid) +
                    " " + std::strerror(errno));
            }
            if (pid == 0) {
                // No event yet; sleep briefly to avoid busy-waiting.
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            // -------------------------------------------------------------------
            // Process termination
            // -------------------------------------------------------------------
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

            if (!WIFSTOPPED(status)) {
                continue; // not a stop we care about
            }

            // -------------------------------------------------------------------
            // We have a stopped tracee. Classify the stop type.
            // The branches below MUST stay in this order:
            // 1. fork-family events       (PTRACE_EVENT_FORK | VFORK | CLONE)
            // 2. PTRACE_EVENT_EXIT
            // 3. unknown pid              (adopt block - freshly-adopted child)
            // 4. plain SIGTRAP            (exec stop)
            // 5. sig != SIGTRAP|0x80      (real signal delivery)
            // 6. real syscall stop        (handle_syscall_stop)
            // -------------------------------------------------------------------
            unsigned int event = static_cast<unsigned int>(status >> 16);
            int sig = WSTOPSIG(status);

            // (1) Fork-family events: the parent stopped because it just
            //     created a child. handle_ptrace_event registers or defers
            //     the child; do not touch syscall state for the parent here.
            if (event == PTRACE_EVENT_FORK ||
                event == PTRACE_EVENT_VFORK ||
                event == PTRACE_EVENT_CLONE) {
                handle_ptrace_event(pid, status, cb);
                continue;
            }

            // (2) PTRACE_EVENT_EXIT: the tracee is about to die. This is
            //     informational, not a syscall stop, so we must not toggle
            //     in_syscall_state_. Just resume it and let the exit arrive
            //     naturally via waitpid(WIFEXITED).
            if (event == PTRACE_EVENT_EXIT) {
                if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
                    traced_pids_.erase(pid);
                    in_syscall_state_.erase(pid);
                }
                continue;
            }

            // (3) Unknown pid: this is the initial SIGSTOP of a child that
            //     handle_ptrace_event could not wait for synchronously. That
            //     stop only arrives after the parent was resumed from its
            //     clone event, so it reaches us here instead of there.
            //
            //     This branch MUST come before the signal-delivery branch:
            //     otherwise the SIGSTOP gets re-injected and the child stays
            //     stopped forever. We resume with signal 0 to *suppress* the
            //     synthetic SIGSTOP.
            if (in_syscall_state_.find(pid) == in_syscall_state_.end()) {
                if (ptrace(PTRACE_SETOPTIONS, pid, nullptr,
                        PTRACE_O_TRACEFORK |
                        PTRACE_O_TRACEVFORK |
                        PTRACE_O_TRACECLONE |
                        PTRACE_O_TRACEEXIT |
                        PTRACE_O_TRACESYSGOOD) == -1) {
                    // Child died before we could set options; nothing to do.
                    if (ptrace(PTRACE_SYSCALL, pid, nullptr, 0) == -1) {
                        // Already gone; nothing to clean up.
                    }
                    continue;
                }
                traced_pids_.insert(pid);
                // Initial value is a hint only; handle_syscall_stop now asks
                // the kernel via PTRACE_GET_SYSCALL_INFO which stop this is.
                in_syscall_state_[pid] = false;
                if (ptrace(PTRACE_SYSCALL, pid, nullptr, 0) == -1) {
                    traced_pids_.erase(pid);
                    in_syscall_state_.erase(pid);
                }
                continue;
            }

            // (4) Post-exec SIGTRAP from execve(2): the kernel stops the tracee after
            // a successful exec so the tracer can refresh its view of the process.
            // Resume with signal 0 to suppress the trap. Forwarding SIGTRAP would
            // terminate the tracee with the default disposition.
            //
            // Distinguishable from a syscall stop because TRACESYSGOOD is on:
            // syscall stops carry SIGTRAP|0x80 (133), this one carries plain
            // SIGTRAP (5).
            if (sig == SIGTRAP) {
                Logger::log(LogLevel::Debug,
                    "ptrace: exec_sigtrap pid=" + std::to_string(pid));
                if (ptrace(PTRACE_SYSCALL, pid, nullptr, 0) == -1) {
                    traced_pids_.erase(pid);
                    in_syscall_state_.erase(pid);
                }
                continue;
            }

            // (5) Syscall stops with TRACESYSGOOD enabled carry SIGTRAP|0x80.
            //     Anything else — a real signal, a breakpoint, an event we do not
            //     handle — is forwarded as-is and does not touch syscall state.
            if (sig != (SIGTRAP | 0x80)) {
                if (ptrace(PTRACE_SYSCALL, pid, nullptr, sig) == -1) {
                    traced_pids_.erase(pid);
                    in_syscall_state_.erase(pid);
                }
                continue;
            }

            // (6) Real syscall stop for a known pid. handle_syscall_stop is
            //     where the kernel query (PTRACE_GET_SYSCALL_INFO) decides
            //     definitively whether this is an entry or an exit — the
            //     in_syscall_state_ flag is only a fallback.
            auto it = in_syscall_state_.find(pid);
            handle_syscall_stop(pid, cb, it->second);
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