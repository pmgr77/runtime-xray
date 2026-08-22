/**
 * @file    analyze_command.hpp
 * @brief   Declaration of the AnalyzeCommand class for static ELF analysis.
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

#ifndef RUNTIMEXRAY_ANALYZE_COMMAND_HPP
#define RUNTIMEXRAY_ANALYZE_COMMAND_HPP

#include "icommand.hpp"
#include "mapped_file.hpp"
#include "elf_parser.hpp"
#include "finding.hpp"
#include <iostream>
#include <string>
#include <optional>

namespace runtimexray
{

    class AnalyzeCommand : public ICommand
    {
    public:
        std::string name() const override
        {
            return "analyze";
        }

        std::string description() const override
        {
            return "Run static analysis on an ELF binary";
        }

        bool parse_specific_args(const std::vector<std::string> &args) override;

        int execute(const CommonOptions &common) override;

        void print_help() const override;

    private:
        std::string binary_path_;
    };

} // namespace runtimexray

#endif // RUNTIMEXRAY_ANALYZE_COMMAND_HPP