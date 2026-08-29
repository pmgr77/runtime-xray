/**
 * @file    cli_common.hpp
 * @brief   Common CLI options and global argument parsing.
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

#ifndef RUNTIMEXRAY_COMMON_CLI_HPP
#define RUNTIMEXRAY_COMMON_CLI_HPP

#include "finding.hpp"

#include <string>
#include <vector>

namespace runtimexray {

/**
 * @brief Options shared by all subcommands.
 */
struct CommonOptions {
    std::string report_file;          // human-readable report file (empty = stdout)
    std::string json_file;            // JSON report file (empty = no JSON output)
    std::string log_level = "info";   // error, warn, info, debug, trace
    std::string log_file;             // log file (empty = stderr)
    FindingSeverity min_severity = FindingSeverity::Medium;
};

/**
 * @brief Parses global options from the given arguments.
 *
 * Removes recognised global flags and stores their values in `opts`.
 * All unrecognised arguments are returned in `remaining`.
 *
 * @param args Input arguments (after the subcommand name).
 * @param opts Output common options.
 * @param remaining Arguments not recognised as global options.
 * @return true on success, false on invalid global option.
 */
bool parse_global_options(const std::vector<std::string>& args,
                            CommonOptions& opts,
                            std::vector<std::string>& remaining);

} // namespace runtimexray

#endif // RUNTIMEXRAY_COMMON_CLI_HPP