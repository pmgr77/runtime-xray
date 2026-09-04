/**
 * @file    finding_reporter.cpp
 * @brief   Implementation of centralized finding reporter.
 *
 * @author  Peter Magram
 * @date    2026-09-04
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

#include "finding_reporter.hpp"
#include "logger.hpp"
#include "common_cli.hpp"

namespace runtimexray {

    bool report_findings(
        const CommonOptions &common,
        ReportContext ctx,
        FindingList findings,
        std::optional<LineageGraph> lineage_graph,
        const nlohmann::json* extra)
    {
        // ---- Create reporter ----
        std::unique_ptr<FindingReporter> json_reporter;
        std::unique_ptr<FindingReporter> txt_reporter;
        std::ofstream json_file_out;
        std::ofstream txt_file_out;

        // ---- JSON reporter ----
        if (!common.json_file.empty()) {
            json_file_out.open(common.json_file);
            if (!json_file_out) {
                Logger::log(LogLevel::Error, "Could not open JSON file: " + common.json_file);
                return false;
            }
            json_reporter = std::make_unique<JsonFindingReporter>(json_file_out);
            Logger::log(LogLevel::Info, "Writing JSON report to " + common.json_file);
        }

        // ---- Text reporter ----
        if (!common.report_file.empty()) {
            txt_file_out.open(common.report_file);
            if (!txt_file_out) {
                Logger::log(LogLevel::Error, "Could not open report file: " + common.report_file);
                return false;
            }
            txt_reporter = std::make_unique<TextFindingReporter>(txt_file_out);
            Logger::log(LogLevel::Info, "Writing text report to " + common.report_file);
        } else {
            // Default to stdout if no report file specified
            txt_reporter = std::make_unique<TextFindingReporter>(std::cout);
            Logger::log(LogLevel::Info, "Writing text report to stdout");
        }

        Report r{std::move(ctx), std::move(findings), std::move(lineage_graph)};
        if (json_reporter) {
            json_reporter->report(r, extra);
        }
        if (txt_reporter) {
            txt_reporter->report(r, extra);
        }
        return true;
    }

} // namespace runtimexray