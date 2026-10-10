/**
 * @file    hardening_rule.cpp
 * @brief   Detection rule for ELF hardening observations.
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

#include "hardening_rule.hpp"

namespace runtimexray {

std::string HardeningRule::id() const
{
    return "builtin.hardening";
}

std::string HardeningRule::description() const
{
    return "Evaluates ELF hardening properties";
}

DetectionStage HardeningRule::stage() const
{
    return DetectionStage::Primary;
}

FindingList HardeningRule::detect(
    const DetectionContext& context) const
{
    FindingList findings;

    for (const auto& observation :
        context.graph.observations) {

        if (observation.type !=
            ObservationType::Static) {
            continue;
        }

        if (observation.static_category !=
            "hardening") {
            continue;
        }

        if (observation.static_field.empty() ||
            observation.static_value.empty()) {
            continue;
        }

        FindingSeverity severity =
            FindingSeverity::Info;

        if (observation.static_value ==
            "Disabled") {

            severity =
                FindingSeverity::High;

        } else if (
            observation.static_value ==
            "Partial") {

            severity =
                FindingSeverity::Low;
        }

        Finding finding;

        finding.kind =
            "binary_hardening";

        finding.severity =
            severity;

        //
        // Preserve the established CLI contract:
        //
        //     NX: Disabled
        //     RELRO: Full
        //
        finding.title =
            observation.static_field +
            ": " +
            observation.static_value;

        finding.summary =
            "Hardening property observed in binary.";

        finding.attributes["feature"] =
            observation.static_field;

        finding.attributes["status"] =
            observation.static_value;

        if (observation.seq != 0) {
            finding.evidence_observation_seqs.push_back(
                observation.seq);
        }

        findings.push_back(
            std::move(finding));
    }

    return findings;
}

} // namespace runtimexray