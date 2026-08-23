/**
 * @file    analyze_command.cpp
 * @brief   Implementation of AnalyzeCommand for static ELF analysis.
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

#include "commands/analyze_command.hpp"
#include "reporter.hpp"

#include <iostream>
#include <chrono>

namespace runtimexray
{

    bool AnalyzeCommand::parse_specific_args(const std::vector<std::string> &args)
    {
        binary_path_.clear();

        for (const auto &arg : args) {
            if (arg == "-h" || arg == "--help") {
                print_help();
                return false; // signal that help was shown
            } else if (binary_path_.empty()) {
                binary_path_ = arg;
            } else {
                std::cerr << "Error: Unexpected argument '" << arg << "' for analyze command." << std::endl;
                return false;
            }
        }

        if (args.empty() || binary_path_.empty()) {
            std::cerr << "Error: No binary path provided for analyze command." << std::endl;
            return false;
        }

        return true;
    }

    int AnalyzeCommand::execute(const CommonOptions &common)
    {
        auto start_time = std::chrono::steady_clock::now();

        ElfMetadata metadata;
        FindingList findings;
        try {
            findings = runtimexray::analyze_binary(binary_path_,
                                               common.min_severity,
                                               common.verbose,
                                               &metadata);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << '\n';
            return 1;
        }

        auto end_time = std::chrono::steady_clock::now();
        int duration_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count()
        );

        if (common.output_format == "json") {
            ReportContext ctx;
            ctx.command     = "analyze";
            ctx.target      = binary_path_;
            ctx.started_at  = current_iso8601_utc();
            ctx.duration_ms = duration_ms;
            std::cout << Reporter::to_json(findings, ctx);
        } else {
            std::cout << ">  Hardening checks:\n";
            bool has_hardening = false;
            for (const auto& f : findings) {
                if (std::holds_alternative<HardeningFindingDetails>(f.details)) {
                    const auto& details = std::get<HardeningFindingDetails>(f.details);
                    std::cout << "    " << details.feature << ": " << details.status << '\n';
                    has_hardening = true;
                }
            }
            if (!has_hardening) {
                std::cout << "    No findings at this severity level.\n";
            }

            bool has_api = false;
            for (const auto& f : findings) {
                if (std::holds_alternative<DangerousApiFindingDetails>(f.details)) {
                    const auto& details = std::get<DangerousApiFindingDetails>(f.details);
                    if (!has_api) {
                        std::cout << ">  Dangerous API usage:\n";
                        has_api = true;
                    }
                    std::cout << "    Dangerous API: " << details.api
                            << " (reason: " << details.reason
                            << ", recommendation: " << details.recommendation
                            << ", cwe: " << details.cwe_id << ")\n";
                }
            }
        }
        return 0;
    }

    void AnalyzeCommand::print_help() const
    {
        // << "RuntimeXRay - Security posture analyzer for ELF binaries\n\n"
        std::cout << "Usage: runtimexray analyze [--verbose] [--min-severity <level>] <binary>\n";
        std::cout << "Options:\n"
            << "  --min-severity <level>  Show findings at or above severity level.\n"
            << "                          Levels: Critical, High, Medium, Low, Info\n"
            << "                          Default: Medium\n"
            << "  --verbose               Show all findings (equivalent to --min-severity=Info)\n"
            << "  --help                  Show this help message\n";
    }

} // namespace runtimexray