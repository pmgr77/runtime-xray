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
#include "finding_reporter.hpp"
#include "logger.hpp"

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
                                               false,
                                               &metadata);
        } catch (const std::exception& e) {
            Logger::log(LogLevel::Error, std::string("Analysis failed: ") + e.what());
            return 1;
        }

        auto end_time = std::chrono::steady_clock::now();
        int duration_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count()
        );

        ReportContext ctx;
        ctx.command = "analyze";
        ctx.target = binary_path_;
        ctx.started_at = runtimexray::current_iso8601_utc();
        ctx.duration_ms = duration_ms;
        
        // ---- Create reporter ----
        std::unique_ptr<FindingReporter> reporter;
        std::ofstream file_out;

        if (!common.json_file.empty()) {
            file_out.open(common.json_file);
            if (!file_out) {
                Logger::log(LogLevel::Error, "Could not open JSON file: " + common.json_file);
                return 1;
            }
            reporter = std::make_unique<JsonFindingReporter>(file_out);
            Logger::log(LogLevel::Info, "Writing JSON report to " + common.json_file);
        } else if (!common.report_file.empty()) {
            file_out.open(common.report_file);
            if (!file_out) {
                Logger::log(LogLevel::Error, "Could not open report file: " + common.report_file);
                return 1;
            }
            reporter = std::make_unique<TextFindingReporter>(file_out);
            Logger::log(LogLevel::Info, "Writing text report to " + common.report_file);
        } else {
            reporter = std::make_unique<TextFindingReporter>(std::cout);
        }

        Report r{std::move(ctx), std::move(findings), std::nullopt};
        reporter->report(r, nullptr); // no extra metadata for analyze
        return 0;
    }

    void AnalyzeCommand::print_help() const
    {
        std::cout << "Usage: runtimexray analyze [--report FILE] [--json FILE] "
                  << "[--log-level LEVEL] [--log-file FILE] [--min-severity LEVEL] "
                  << "<binary>\n";
        std::cout << "Options:\n";
        std::cout << "  --report FILE         Write human-readable report to FILE (default: stdout)\n";
        std::cout << "  --json FILE           Write JSON report to FILE\n";
        std::cout << "  --log-level LEVEL     Set log level (error, warn, info, debug, trace)\n";
        std::cout << "  --log-file FILE       Write logs to FILE (default: stderr)\n";
        std::cout << "  --min-severity LEVEL  Minimum severity for findings (Critical, High, Medium, Low, Info)\n";
        std::cout << "  --help                Show this help\n";
    }

} // namespace runtimexray