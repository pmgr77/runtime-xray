/**
 * @file    common_cli.cpp
 * @brief   Implementation of global command‑line option parsing.
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

#include "common_cli.hpp"
#include <iostream>

namespace runtimexray {

namespace {

// Helper to parse a severity string into FindingSeverity.
// Returns true if successful; false on invalid input.
bool parse_severity(const std::string& severity_str, FindingSeverity& out) {
    if (severity_str == "Critical") {
        out = FindingSeverity::Critical;
    } else if (severity_str == "High") {
        out = FindingSeverity::High;
    } else if (severity_str == "Medium") {
        out = FindingSeverity::Medium;
    } else if (severity_str == "Low") {
        out = FindingSeverity::Low;
    } else if (severity_str == "Info") {
        out = FindingSeverity::Info;
    } else {
        return false;
    }
    return true;
}

} // namespace

bool parse_global_options(const std::vector<std::string>& args,
                          CommonOptions& opts,
                          std::vector<std::string>& remaining) {
    remaining.clear();
    remaining.reserve(args.size());

    for (size_t i = 0; i < args.size(); ++i) {
        const std::string arg = args[i];

        if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        } else if (arg == "--min-severity") {
            // Form: --min-severity High
            if ((i + 1) >= args.size()) {
                std::cerr << "Error: Missing value for --min-severity option.\n";
                return false;
            }
            const std::string& severity_str = args[++i];
            if (!parse_severity(severity_str, opts.min_severity)) {
                std::cerr << "Error: Invalid value for --min-severity option: "
                          << severity_str << "\n";
                return false;
            }
        } else if (arg.rfind("--min-severity=", 0) == 0) {
            // Form: --min-severity=High
            const std::string severity_str =
                arg.substr(std::string("--min-severity=").size());
            if (!parse_severity(severity_str, opts.min_severity)) {
                std::cerr << "Error: Invalid value for --min-severity option: "
                          << severity_str << "\n";
                return false;
            }
        } else if (arg == "--output-format") {
            if ((i + 1) >= args.size()) {
                std::cerr << "Error: Missing value for --output-format option.\n";
                return false;
            }
            opts.output_format = args[++i];
        } else {
            remaining.push_back(arg);
        }
    }

    return true;
}

} // namespace runtimexray