/**
 * @file    icommand.hpp
 * @brief   Command interface for the unified RuntimeXRay CLI.
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

#ifndef RUNTIMEXRAY_ICOMMAND_HPP
#define RUNTIMEXRAY_ICOMMAND_HPP

#include "common_cli.hpp"
#include <string>
#include <vector>

namespace runtimexray {
    
/**
 * @brief Abstract base class for all subcommands.
 */
class ICommand {
public:
    virtual ~ICommand() = default;

    /** @return Unique command name (e.g., "analyze"). */
    virtual std::string name() const = 0;

    /** @return Short description shown in main help. */
    virtual std::string description() const = 0;

    /**
     * @brief Parses command‑specific arguments.
     *
     * The args vector contains only the arguments remaining after global
     * options were removed by parse_global_options.
     *
     * @param args Command‑specific arguments.
     * @return true if parsing succeeded, false on error or if help was requested.
     */
    virtual bool parse_specific_args(const std::vector<std::string>& args) = 0;

    /**
     * @brief Executes the command using common and specific options.
     * @param common CommonOptions already filled.
     * @return Exit code.
     */
    virtual int execute(const CommonOptions& common) = 0;

    /** @brief Prints command‑specific help. */
    virtual void print_help() const = 0;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_ICOMMAND_HPP