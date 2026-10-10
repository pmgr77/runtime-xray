/**
 * @file    detection_engine.cpp
 * @brief   Implementation of RuntimeXRay graph-based detection engine.
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

#include "detection_engine.hpp"

#include "detection_context.hpp"

#include <iterator>
#include <utility>

namespace runtimexray {

DetectionEngine::DetectionEngine(
    const DetectionRuleRegistry& registry)
    : registry_(registry)
{
}

FindingList DetectionEngine::run_stage(
    DetectionStage stage,
    const LineageGraph& graph,
    const FindingList& previous_stage_findings,
    uint64_t& next_finding_id) const
{
    FindingList stage_findings;

    //
    // Every rule in this stage receives the exact same frozen context.
    //
    // Findings produced below are accumulated separately and therefore cannot
    // affect any other rule executing in this stage.
    //
    const DetectionContext context{
        graph,
        previous_stage_findings
    };

    for (const auto* rule : registry_.active_rules(stage)) {
        FindingList rule_findings =
            rule->detect(context);

        for (auto& finding : rule_findings) {
            //
            // Producer identity belongs to orchestration, not rule-authored
            // data. This guarantees that every Finding is traceable to the
            // rule that actually produced it.
            //
            finding.rule_id = rule->id();

            //
            // Finding IDs are RuntimeXRay-local identities valid only inside
            // this analysis result.
            //
            finding.finding_id = next_finding_id++;
        }

        stage_findings.insert(
            stage_findings.end(),
            std::make_move_iterator(rule_findings.begin()),
            std::make_move_iterator(rule_findings.end()));
    }

    return stage_findings;
}

FindingList DetectionEngine::detect(
    const LineageGraph& graph) const
{
    uint64_t next_finding_id = 1;

    //
    // Primary rules reason directly from graph evidence.
    //
    static const FindingList no_previous_findings;

    FindingList primary_findings =
        run_stage(
            DetectionStage::Primary,
            graph,
            no_previous_findings,
            next_finding_id);

    //
    // primary_findings is now the frozen semantic result available to every
    // Composite rule. Composite rules cannot see each other's output.
    //
    FindingList composite_findings =
        run_stage(
            DetectionStage::Composite,
            graph,
            primary_findings,
            next_finding_id);

    //
    // Final result preserves stage ordering:
    //
    //     Primary Findings
    //     Composite Findings
    //
    primary_findings.insert(
        primary_findings.end(),
        std::make_move_iterator(composite_findings.begin()),
        std::make_move_iterator(composite_findings.end()));

    return primary_findings;
}

} // namespace runtimexray