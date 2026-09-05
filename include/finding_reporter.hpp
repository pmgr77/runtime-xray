/**
 * @file    finding_reporter.hpp
 * @brief   Abstract and concrete reporters for findings.
 *
 * @author  Peter Magram
 * @date    2026-08-29
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
#ifndef RUNTIMEXRAY_FINDING_REPORTER_HPP
#define RUNTIMEXRAY_FINDING_REPORTER_HPP

#include "finding.hpp"
#include "reporter.hpp"
#include "common_cli.hpp"
#include <ostream>

namespace runtimexray {

/**
 * @brief Abstract base class for finding reporters.
 */
class FindingReporter {
public:
    virtual ~FindingReporter() = default;

    /**
     * @brief Generate a report from findings and context.
     * @param findings List of findings.
     * @param ctx Report context (command, target, timings, etc.).
     * @param extra Optional extra JSON metadata (e.g., trace backend, timeout).
     */
    virtual void report(const Report& r, const nlohmann::json* extra) = 0;
};

/**
 * @brief Human-readable text reporter.
 */
class TextFindingReporter : public FindingReporter {
public:
    explicit TextFindingReporter(std::ostream& out) : out_(out) {}
    void report(const Report& r, const nlohmann::json* extra) override {
        out_ << Reporter::to_text(r, extra);
    }
private:
    std::ostream& out_;
};

/**
 * @brief JSON reporter.
 */
class JsonFindingReporter : public FindingReporter {
public:
    explicit JsonFindingReporter(std::ostream& out) : out_(out) {}
    void report(const Report& r, const nlohmann::json* extra) override {
        out_ << Reporter::to_json(r, extra);
    }
private:
    std::ostream& out_;    
};

/**
 * @brief Centralised report generation function.
 *
 * Creates and writes both JSON and text reports based on CommonOptions
 * and ReportingOptions.
 *
 * @param common Global CLI options.
 * @param ctx Report context.
 * @param findings List of findings.
 * @param lineage_graph Optional lineage graph.
 * @param extra Optional extra JSON metadata.
 * @param report_opts Reporting policy (show_secrets).
 * @return true on success, false on error.
 */
bool report_findings(const CommonOptions &common,
        ReportContext ctx,
        FindingList findings,
        std::optional<LineageGraph> lineage_graph,
        const nlohmann::json* extra);

} // namespace runtimexray

#endif // RUNTIMEXRAY_FINDING_REPORTER_HPP