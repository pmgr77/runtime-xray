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
#include "memory_reader.hpp"
#include "tachikoma.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <limits>
#include <string>
#include <vector>

namespace runtimexray {

class PTraceBackend : public ITraceBackend {
public:
    std::string name() const override { return "ptrace"; }
    bool supports_attach() const override { return false; }
    bool supports_function_tracing() const override { return false; }
    pid_t get_pid() const override { return tracer_ ? tracer_->get_pid() : -1; }

    bool is_timed_out() const override { return tracer_ ? tracer_->is_timed_out() : false; }

    std::string child_output_path() const override {
        return tracer_ ? tracer_->child_output_path() : "";
    }

    std::string read_string(uint64_t address, size_t max_len) const override {
        if (!tracer_)
            return {};
        return read_string(tracer_->get_pid(), address, max_len);
    }

    std::vector<std::byte> read_memory(uint64_t address, size_t size) const override {
        if (!tracer_)
            return {};
        return read_memory(tracer_->get_pid(), address, size);
    }

    std::string read_string(pid_t pid, uint64_t address, size_t max_len) const override {
        if (pid <= 0 || address == 0 || max_len == 0)
            return {};

        // Opening per request prevents reuse of a /proc/<pid>/mem descriptor
        // belonging to a previous executable image after execve().
        auto reader = open_memory_reader(pid, memory_reader_);
        if (!reader)
            return {};

        std::string result;
        std::array<char, 256> buffer{};
        size_t total = 0;

        while (total < max_len) {
            if (static_cast<std::uintmax_t>(total) >
                static_cast<std::uintmax_t>(std::numeric_limits<uint64_t>::max() - address)) {
                break;
            }
            const size_t requested = std::min(buffer.size(), max_len - total);
            const ssize_t n = reader->read(static_cast<std::uintptr_t>(address + total), buffer.data(), requested);
            if (n <= 0)
                break;

            const size_t count = static_cast<size_t>(n);
            for (size_t i = 0; i < count; ++i) {
                if (buffer[i] == '\0')
                    return result;
                result.push_back(buffer[i]);
            }
            total += count;
        }
        return result;
    }

    std::vector<std::byte> read_memory(pid_t pid, uint64_t address, size_t size) const override {
        if (pid <= 0 || address == 0 || size == 0)
            return {};

        auto reader = open_memory_reader(pid, memory_reader_);
        if (!reader)
            return {};

        std::vector<std::byte> buffer(size);
        const ssize_t n = reader->read(static_cast<std::uintptr_t>(address), buffer.data(), size);
        if (n <= 0)
            return {};

        buffer.resize(static_cast<size_t>(n));
        return buffer;
    }

    int trace(const TraceConfig& config) override {
        // Configure before invoking run(): syscall callbacks call read_*().
        memory_reader_ = config.memory_reader;

        tracer_ = std::make_unique<Tachikoma>(config.program, config.args);
        tracer_->set_timeout(config.timeout);
        tracer_->set_follow_forks(config.follow_forks);
        tracer_->set_memory_reader(config.memory_reader);
        return tracer_->run(config.callback);
    }

private:
    // This is a tracing-session setting, not process-global environment state.
    MemoryReadBackend memory_reader_ = MemoryReadBackend::ProcMem;
    std::unique_ptr<Tachikoma> tracer_;
};

std::unique_ptr<ITraceBackend> create_default_tracer_backend() {
    return std::make_unique<PTraceBackend>();
}

} // namespace runtimexray
