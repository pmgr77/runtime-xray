/**
 * @file    trace_command.hpp
 * @brief   Declaration of the TraceCommand class for dynamic syscall tracing.
 *
 * @author  Peter Magram
 * @date    2026-08-22
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

#ifndef RUNTIMEXRAY_TRACE_COMMAND_HPP
#define RUNTIMEXRAY_TRACE_COMMAND_HPP

#include "icommand.hpp"
#include "tachikoma.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace runtimexray
{

    class TraceCommand : public ICommand
    {
    public:
        std::string name() const override
        {
            return "trace";
        }
        std::string description() const override
        {
            return "Trace system calls of a program";
        }

        bool parse_specific_args(const std::vector<std::string> &args) override;
        int execute(const CommonOptions &common) override;
        void print_help() const override;

    private:
        std::chrono::seconds timeout_{0};
        std::string program_;
        std::vector<std::string> program_args_;
    };

} // namespace runtimexray

#endif // RUNTIMEXRAY_TRACE_COMMAND_HPP