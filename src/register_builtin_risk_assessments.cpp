/**
 * @file    register_builtin_risk_assessments.cpp
 * @brief   Registers all built‑in risk assessments.
 *
 * @author  Peter Magram
 * @date    2026-09-07
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
#include "cross_boundary_risk_assessment.hpp"
#include <memory>

namespace runtimexray {

// Forward declaration
class CrossBoundaryRiskAssessment;

void register_builtin_risk_assessments() {
    auto& registry = RiskAssessmentRegistry::instance();
    registry.register_risk_assessment(std::make_unique<CrossBoundaryRiskAssessment>());
}

} // namespace runtimexray