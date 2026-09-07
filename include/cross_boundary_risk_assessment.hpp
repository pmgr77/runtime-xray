/**
 * @file    cross_boundary_risk_assessment.hpp
 * @brief   Risk assessment for secrets crossing process and network boundaries.
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

#ifndef RUNTIMEXRAY_CROSS_BOUNDARY_RISK_ASSESSMENT_HPP
#define RUNTIMEXRAY_CROSS_BOUNDARY_RISK_ASSESSMENT_HPP

#include "irisk_assessment.hpp"
#include "lineage.hpp"
#include "finding.hpp"
#include "reporter.hpp"

namespace runtimexray {

/**
 * @brief Detects when the same secret appears in environment, memory, child processes, and network output.
 *
 * This assessment walks the lineage graph to correlate secrets by fingerprint.
 * If a secret is found in an environment variable, appears in memory of a child process,
 * and is sent over a network connection, it produces a Critical composite finding.
 */
class CrossBoundaryRiskAssessment : public IRiskAssessment {
public:
    
    std::string name() const override;
    
    std::string description() const override;

    void assess_findings(FindingList& findings,
                         const ReportContext& /*ctx*/,
                         const LineageGraph* graph) override;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_CROSS_BOUNDARY_RISK_ASSESSMENT_HPP