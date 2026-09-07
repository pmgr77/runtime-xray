/**
 * @file    risk_accumulator_registry.cpp
 * @brief   Implementation of RiskAccumulatorRegistry.
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

#include "risk_assessment_registry.hpp"
#include "logger.hpp"

namespace runtimexray {


RiskAssessmentRegistry& RiskAssessmentRegistry::instance() {
    static RiskAssessmentRegistry registry;
    return registry;
}

void RiskAssessmentRegistry::register_risk_assessment(
        std::unique_ptr<IRiskAssessment> risk_assessment) {
    if (!risk_assessment) {
        Logger::log(LogLevel::Error, "Attempted to register a null risk assessment");
        return;
    }
    const std::string& name = risk_assessment->name();
    unregister_risk_assessment(name); // remove existing with same name
    assessments_.push_back(std::move(risk_assessment));
    disabled_.erase(name);
}

void RiskAssessmentRegistry::unregister_risk_assessment(const std::string& name) {
    assessments_.erase(std::remove_if(assessments_.begin(), assessments_.end(),
        [&name](const std::unique_ptr<IRiskAssessment>& existing) {
            return existing->name() == name;
        }), assessments_.end());
    disabled_.erase(name);
}

void RiskAssessmentRegistry::disable_risk_assessment(const std::string& name) {
    disabled_.insert(name);
}

void RiskAssessmentRegistry::enable_risk_assessment(const std::string& name) {
    disabled_.erase(name);
}

std::vector<IRiskAssessment*> RiskAssessmentRegistry::active_risk_assessments() const {
    std::vector<IRiskAssessment*> active;
    for (const auto& assessment : assessments_) {
        if (disabled_.find(assessment->name()) == disabled_.end()) {
            active.push_back(assessment.get());
        }
    }
    return active;
}

void RiskAssessmentRegistry::assess_findings(FindingList& findings, const ReportContext& ctx, const LineageGraph* graph) const {
    for (auto* assessment : active_risk_assessments()) {
        assessment->assess_findings(findings, ctx, graph);
    }
}

} // namespace runtimexray