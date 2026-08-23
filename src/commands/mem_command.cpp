/**
 * @file    mem_command.cpp
 * @brief   Implementation of MemCommand for process memory scanning.
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

#include "commands/mem_command.hpp"
#include "reporter.hpp"
#include "finding_filter.hpp"
#include <iostream>
#include <chrono>
namespace runtimexray
{

    bool MemCommand::parse_specific_args(const std::vector<std::string>& args) {
        pid_ = -1;
        max_pages_ = 1000;   // default

        for (size_t i = 0; i < args.size(); ++i) {
            const std::string& arg = args[i];

            if (arg == "-h" || arg == "--help") {
                print_help();
                return false; // signal that help was shown
            } else if (arg == "--max-pages" && (i + 1 < args.size())) {
                try {
                    max_pages_ = std::stoull(args[++i]);
                } catch (...) {
                    std::cerr << "Error: Invalid value for --max-pages option.\n";
                    return false;
                }
            } else if (pid_ == -1) {
                try {
                    pid_ = std::stoi(arg);
                } catch (const std::invalid_argument&) {
                    std::cerr << "Error: Invalid PID value: " << arg << std::endl;
                    return false;
                }
            } else {
                std::cerr << "Error: Unexpected argument '" << arg << "' for mem command." << std::endl;
                return false;
            }
        }

        if (pid_ == -1) {
            std::cerr << "Error: No PID provided for mem command." << std::endl;
            return false;
        }

        return true;
    }

    int MemCommand::execute(const CommonOptions &common) {
        auto start_time = std::chrono::steady_clock::now();

        runtimexray::FindingList findings;
        size_t pages_scanned = 0;

        runtimexray::scan_process_for_secrets(pid_, findings, 50, max_pages_, &pages_scanned);
        runtimexray::filter_findings(findings, common.min_severity, common.verbose);

        auto end_time = std::chrono::steady_clock::now();
        int duration_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count()
        );

        ReportContext ctx;
        ctx.command = "mem";
        ctx.target = std::to_string(pid_);
        ctx.started_at = runtimexray::current_iso8601_utc();
        ctx.duration_ms = duration_ms;

        if (common.output_format == "json") {
            std::cout << Reporter::to_json(findings, ctx);
        } else {
            if (findings.empty()) {
                std::cout << "No sensitive data found in memory of PID " << pid_ << ".\n";
            } else {
                std::cout << "Found " << findings.size() << " potential secrets (scanned " << pages_scanned << " pages):\n";
                for (const auto& f : findings) {
                    std::visit([&](const auto& details) {
                        using T = std::decay_t<decltype(details)>;
                        if constexpr (std::is_same_v<T, runtimexray::SensitiveDataWriteDetails>) {
                            std::cout << " - " << f.description
                                    << " data=\"" << details.data_snippet << "\"\n";
                        } else if constexpr (std::is_same_v<T, runtimexray::MemorySecretFindingDetails>) {
                            std::cout << " - " << f.description
                            << " type=" << details.secret_type
                            << " location=" << details.location
                            << " data=\"" << details.snippet << "\"\n";
                        } else {
                            std::cout << " - " << f.description << "\n";
                        }
                    }, f.details);
                }
            }
            std::cout << "Mem command: PID " << pid_ << "\n";
        }

        return 0;
    }

    void MemCommand::print_help() const {
        std::cout << "Usage: runtimexray mem [--verbose] [--min-severity <level>] [--max-pages <N>] <pid>\n";
        std::cout << "Scans readable memory of the given process for secrets.\n";
        std::cout << "Options:\n";
        std::cout << "  --max-pages <N>       Maximum number of memory pages to scan (default: 1000).\n";
        std::cout << "                        Use 0 to skip memory page scanning and only check\n";
        std::cout << "                        cmdline and environment variables.\n";
    }

} // namespace runtimexray