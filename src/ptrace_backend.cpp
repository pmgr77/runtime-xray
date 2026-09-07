/**
 * @file    ptrace_backend.cpp
 * @brief   Implementation of the ptrace-based tracing backend.
 *
 * @author  Peter Magram
 * @date    2026-08-29
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
#include "tachikoma.hpp"
#include <sys/uio.h>

#include <memory>

namespace runtimexray {

class PTraceBackend : public ITraceBackend {
public:
    std::string name() const override { return "ptrace"; }
    bool supports_attach() const override { return false; }
    bool supports_function_tracing() const override { return false; }
    pid_t get_pid() const override { return tracer_ ? tracer_->get_pid() : -1; }

    bool is_timed_out() const { return tracer_ ? tracer_->is_timed_out() : false; }
    
    std::string child_output_path() const { 
        return tracer_ ? tracer_->child_output_path() : ""; 
    }

    std::string read_string(uint64_t address, size_t size) const override {
        if (!tracer_) return {};
        return read_string(tracer_->get_pid(), address, size);
    }

    std::vector<std::byte> read_memory(uint64_t address, size_t size) const override {
        if (!tracer_) return std::vector<std::byte>{};
        return read_memory(tracer_->get_pid(), address, size);
    }

    // PID‑aware methods using process_vm_readv
    std::string read_string(pid_t pid, uint64_t address, size_t max_len) const override {
        if (pid <= 0) return {};
        return read_process_memory_string(pid, address, max_len);
    }

    std::vector<std::byte> read_memory(pid_t pid, uint64_t address, size_t size) const override {
        if (pid <= 0) return {};
        return read_process_memory_bytes(pid, address, size);
    }

    int trace(const TraceConfig& config) override {
        tracer_ = std::make_unique<Tachikoma>(config.program, config.args);
        tracer_->set_timeout(config.timeout);
        tracer_->set_follow_forks(config.follow_forks);
        return tracer_->run(config.callback);
    }

private:

    static std::string read_process_memory_string(pid_t pid, uint64_t addr, size_t max_len) {
        std::string result;
        char buffer[256];
        size_t total = 0;
        while (total < max_len) {
            struct iovec local{ buffer, sizeof(buffer) };
            struct iovec remote{ reinterpret_cast<void*>(addr + total), sizeof(buffer) };
            ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (n <= 0)
                break;
            for (ssize_t i = 0; i < n; ++i) {
                char c = buffer[i];
                if (c == '\0')
                    return result;
                result.push_back(c);
                if (result.size() >= max_len) 
                    return result;
            }
            total += static_cast<size_t>(n);
        }
        return result;
    }

    static std::vector<std::byte> read_process_memory_bytes(pid_t pid, uint64_t addr, size_t size) {
        std::vector<std::byte> buffer(size);
        struct iovec local{ buffer.data(), size };
        struct iovec remote{ reinterpret_cast<void*>(addr), size };
        ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (n < 0) 
            return {};
        buffer.resize(static_cast<size_t>(n));
        return buffer;
    }

    std::unique_ptr<Tachikoma> tracer_; // created in trace(), used by read methods
};

std::unique_ptr<ITraceBackend> create_default_tracer_backend() {
    return std::make_unique<PTraceBackend>();
}

} // namespace runtimexray