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

#include <memory>

namespace runtimexray {

class PTraceBackend : public ITraceBackend {
public:
    std::string name() const override { return "ptrace"; }
    bool supports_attach() const override { return false; }
    bool supports_function_tracing() const override { return false; }

    bool is_timed_out() const { return tracer_ ? tracer_->is_timed_out() : false; }
    
    std::string child_output_path() const { 
        return tracer_ ? tracer_->child_output_path() : ""; 
    }

    std::string read_string(uint64_t address, size_t size) const override {
        if (!tracer_) return {};
        return tracer_->read_string(address, size);
    }

    std::vector<std::byte> read_memory(uint64_t address, size_t size) const override {
        if (!tracer_) return std::vector<std::byte>{};
        return tracer_->read_memory(address, size);
    }

    int trace(const TraceConfig& config) override {
        tracer_ = std::make_unique<Tachikoma>(config.program, config.args);
        tracer_->set_timeout(config.timeout);
        tracer_->set_follow_forks(config.follow_forks);
        return tracer_->run(config.callback);
    }

private:
    std::unique_ptr<Tachikoma> tracer_; // created in trace(), used by read methods
};

std::unique_ptr<ITraceBackend> create_default_tracer_backend() {
    return std::make_unique<PTraceBackend>();
}

} // namespace runtimexray