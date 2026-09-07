/**
 * @file    risk_assessment_registry.hpp
 * @brief   Registry for risk assessments.
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

#ifndef RUNTIMEXRAY_RISK_ASSESSMENT_REGISTRY_HPP
#define RUNTIMEXRAY_RISK_ASSESSMENT_REGISTRY_HPP

#include "irisk_assessment.hpp"
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace runtimexray {

/**
 * @brief Singleton registry for risk assessments.
 *
 * Allows dynamic registration, enabling, and disabling of assessment modules.
 * Assessments are run after findings are collected and (optionally) the lineage
 * graph is built, before the final report is generated.
 */
class RiskAssessmentRegistry {
public:
    static RiskAssessmentRegistry& instance();
    
    /**
     * @brief Register a new assessment (takes ownership).
     */
    void register_risk_assessment(std::unique_ptr<IRiskAssessment> assessment);

    /**
     * @brief Unregister an assessment by name.
     */
    void unregister_risk_assessment(const std::string& name);

    /**
     * @brief Disable an assessment (keep registered but skip execution).
     */
    void disable_risk_assessment(const std::string& name);

    /**
     * @brief Re‑enable a previously disabled assessment.
     */
    void enable_risk_assessment(const std::string& name);

    /**
     * @brief Return all active (non‑disabled) assessments.
     */
    std::vector<IRiskAssessment*> active_risk_assessments() const;

    /**
     * @brief Run all active assessments on the findings.
     * @param findings Input findings (will be extended).
     * @param ctx Report context.
     * @param graph Lineage graph (may be null).
     */
    void assess_findings(FindingList& findings, const ReportContext& ctx, const LineageGraph* graph) const;

private:
    RiskAssessmentRegistry() = default;

    std::vector<std::unique_ptr<IRiskAssessment>> assessments_;
    std::unordered_set<std::string> disabled_;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_RISK_ASSESSMENT_REGISTRY_HPP