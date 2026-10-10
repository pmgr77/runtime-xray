/**
 * @file    analyze_command.cpp
 * @brief   Implementation of AnalyzeCommand for static ELF analysis.
 *
 * @author  Peter Magram
 * @date    2026-10-10
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

#include "detection_engine.hpp"
#include "detection_rule_registry.hpp"
#include "finding_filter.hpp"
#include "finding_reporter.hpp"
#include "logger.hpp"
#include "reporter.hpp"

#include <chrono>
#include <iostream>
#include <utility>

namespace runtimexray {

bool AnalyzeCommand::parse_specific_args(
    const std::vector<std::string>& args)
{
    binary_path_.clear();

    for (const auto& arg : args) {
        if (arg == "-h" ||
            arg == "--help") {

            print_help();
            return false;

        } else if (binary_path_.empty()) {

            binary_path_ = arg;

        } else {
            std::cerr
                << "Error: Unexpected argument '"
                << arg
                << "' for analyze command."
                << std::endl;

            return false;
        }
    }

    if (binary_path_.empty()) {
        std::cerr
            << "Error: No binary path provided for analyze command."
            << std::endl;

        return false;
    }

    return true;
}

int AnalyzeCommand::execute(
    const CommonOptions& common)
{
    const auto start_time =
        std::chrono::steady_clock::now();

    try {
        //
        // Static ELF parsing is evidence collection only.
        //
        LineageGraph graph =
            collect_elf_observations(
                binary_path_);

        //
        // All security conclusions, static or dynamic, go through the
        // same DetectionEngine.
        //
        DetectionEngine detection_engine(
            DetectionRuleRegistry::instance());

        FindingList findings =
            detection_engine.detect(graph);

        filter_findings(
            findings,
            common.min_severity,
            false);

        const auto end_time =
            std::chrono::steady_clock::now();

        const int duration_ms =
            static_cast<int>(
                std::chrono::duration_cast<
                    std::chrono::milliseconds>(
                        end_time -
                        start_time)
                    .count());

        ReportContext context;

        context.command =
            "analyze";

        context.target =
            binary_path_;

        context.started_at =
            current_iso8601_utc();

        context.duration_ms =
            duration_ms;

        return report_findings(
            common,
            std::move(context),
            std::move(findings),
            std::move(graph),
            nullptr)
            ? 0
            : 1;

    } catch (const std::exception& e) {
        Logger::log(
            LogLevel::Error,
            std::string("Analysis failed: ") +
                e.what());

        return 1;
    }
}

void AnalyzeCommand::print_help() const
{
    std::cout
        << "Usage: runtimexray analyze [--report FILE] [--json FILE] "
        << "[--log-level LEVEL] [--log-file FILE] [--min-severity LEVEL] "
        << "<binary>\n";

    std::cout << "Options:\n";
    std::cout << "  --report FILE         Write human-readable report to FILE (default: stdout)\n";
    std::cout << "  --json FILE           Write JSON report to FILE\n";
    std::cout << "  --log-level LEVEL     Set log level (error, warn, info, debug, trace)\n";
    std::cout << "  --log-file FILE       Write logs to FILE (default: stderr)\n";
    std::cout << "  --min-severity LEVEL  Minimum severity for findings (Critical, High, Medium, Low, Info)\n";
    std::cout << "  --show-secrets        Show raw secret values in reports (default: hidden)\n";
    std::cout << "  --help                Show this help\n";
}

} // namespace runtimexray