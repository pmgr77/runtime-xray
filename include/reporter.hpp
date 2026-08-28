/**
 * @file    reporter.hpp
 * @brief   Declaration of reporting utilities for findings.
 *
 * @author  Peter Magram
 * @date    2026-08-23
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

#ifndef RUNTIMEXRAY_REPORTER_HPP
#define RUNTIMEXRAY_REPORTER_HPP

#include "finding.hpp"
#include <nlohmann/json.hpp>
#include <string>

namespace runtimexray {
    
struct ReportContext {
    std::string tool_name = "runtimexray";
    std::string tool_version = "0.1.0";
    std::string command;      // "analyze", "trace", "mem"
    std::string target;       // binary path, program, or pid
    std::string started_at;   // ISO 8601
    int duration_ms = 0;
};

std::string current_iso8601_utc();

class Reporter {
public:
    // Generates a human-readable text report
    static std::string to_text(const FindingList& findings, bool verbose);

    // Generates a JSON report
    static std::string to_json(const FindingList& findings, const ReportContext& context, const nlohmann::json* extra = nullptr);

private:
    static std::string severity_to_string(FindingSeverity severity);

    static void serialize_findings(const FindingList& findings, nlohmann::json& findings_arr);
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_REPORTER_HPP