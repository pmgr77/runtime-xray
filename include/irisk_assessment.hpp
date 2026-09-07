/**
 * @file    irisk_assessment.hpp
 * @brief   Interface for risk assessments.
 *
 * @author  Peter Magram
 * @date    2026-09-06
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

#ifndef RUNTIMEXRAY_IRISK_ASSESSMENT_HPP
#define RUNTIMEXRAY_IRISK_ASSESSMENT_HPP

#include "finding.hpp"
#include "reporter.hpp"
#include "lineage.hpp"

#include <string>

namespace runtimexray {

/**
 * @brief Interface for risk assessments.
 *
 * Risk Assessments analyse existing findings and the lineage graph to
 * produce higher‑level composite findings (e.g., credential exfiltration,
 * privilege escalation chains).
 */
class IRiskAssessment {
public:
    virtual ~IRiskAssessment() = default;
    
    /** @return Unique assessment name. */
    virtual std::string name() const = 0;

    /** @return Human‑readable description. */
    virtual std::string description() const = 0;

    /**
     * @brief Process all findings and produce additional findings.
     * @param findings Input list (will be extended with new findings).
     * @param ctx Report context (command, target, etc.).
     * @param graph Lineage graph for context (may be null if not available).
     */
    virtual void assess_findings(FindingList& findings, const ReportContext& ctx, const LineageGraph* graph) = 0;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_IRISK_ASSESSMENT_HPP