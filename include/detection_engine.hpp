/**
 * @file    detection_engine.hpp
 * @brief   Executes RuntimeXRay graph-based security detection stages.
 *
 * DetectionEngine executes registered detection rules in deterministic stages.
 *
 * Primary rules analyze the LineageGraph and produce first-level Findings.
 * Their complete output is then frozen.
 *
 * Composite rules receive the same LineageGraph together with that frozen
 * Primary Finding set and may derive higher-level security conclusions.
 *
 * Rules inside one stage never observe Findings produced by other rules in
 * that same stage.
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

#ifndef RUNTIMEXRAY_DETECTION_ENGINE_HPP
#define RUNTIMEXRAY_DETECTION_ENGINE_HPP

#include "detection_rule_registry.hpp"
#include "finding.hpp"
#include "lineage.hpp"

#include <cstdint>

namespace runtimexray {

/**
 * @brief Executes graph-based detection and returns canonical Findings.
 *
 * DetectionEngine is responsible for orchestration only:
 *
 *   1. execute all Primary rules;
 *   2. assign Finding identities;
 *   3. freeze the Primary result;
 *   4. execute all Composite rules using that frozen result;
 *   5. assign identities to Composite Findings;
 *   6. return the combined FindingList.
 *
 * Security reasoning remains entirely inside IDetectionRule implementations.
 */
class DetectionEngine {
public:
    /**
     * @brief Construct an engine using a particular rule registry.
     *
     * Explicit registry injection keeps orchestration testable even though the
     * normal application uses DetectionRuleRegistry::instance().
     */
    explicit DetectionEngine(
        const DetectionRuleRegistry& registry);

    /**
     * @brief Run all enabled detection stages against a completed graph.
     *
     * Finding::rule_id is assigned by the engine from the producing rule's
     * stable ID. Rules therefore cannot accidentally omit or falsify their
     * producer identity.
     *
     * Finding::finding_id is assigned monotonically within this analysis.
     *
     * @param graph Completed evidence graph.
     * @return Combined Primary and Composite Findings.
     */
    FindingList detect(
        const LineageGraph& graph) const;

private:
    const DetectionRuleRegistry& registry_;

    /**
     * @brief Execute one detection stage against a frozen context.
     *
     * @param stage Stage to execute.
     * @param graph Completed lineage graph.
     * @param previous_stage_findings Frozen Findings available to this stage.
     * @param next_finding_id Next analysis-local Finding identity.
     * @return Findings produced by all rules in this stage.
     */
    FindingList run_stage(
        DetectionStage stage,
        const LineageGraph& graph,
        const FindingList& previous_stage_findings,
        uint64_t& next_finding_id) const;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_DETECTION_ENGINE_HPP