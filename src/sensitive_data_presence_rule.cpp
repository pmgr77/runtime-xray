/**
 * @file    sensitive_data_presence_rule.cpp
 * @brief   Detects sensitive data represented by Data observations.
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

#include "sensitive_data_presence_rule.hpp"

#include <cstdint>
#include <string>
#include <utility>

namespace runtimexray {

std::string SensitiveDataPresenceRule::id() const
{
    return "builtin.sensitive_data_presence";
}

std::string SensitiveDataPresenceRule::description() const
{
    return "Detects sensitive values observed in runtime data";
}

DetectionStage SensitiveDataPresenceRule::stage() const
{
    return DetectionStage::Primary;
}

FindingList SensitiveDataPresenceRule::detect(
    const DetectionContext& context) const
{
    FindingList findings;

    for (const auto& observation :
         context.graph.observations) {

        if (observation.type != ObservationType::Data) {
            continue;
        }

        if (observation.secret_type.empty() ||
            observation.fingerprint.empty()) {
            continue;
        }

        Finding finding;

        finding.kind =
            "sensitive_data_presence";

        finding.severity =
            FindingSeverity::High;

        finding.title =
            "Sensitive data observed";

        finding.summary =
            "RuntimeXRay observed a sensitive value in " +
            observation.data_type + ".";

        finding.attributes["secret_type"] =
            observation.secret_type;

        finding.attributes["location"] =
            observation.data_type;

        finding.attributes["fingerprint"] =
            observation.fingerprint;

        finding.attributes["length"] =
            static_cast<uint64_t>(
                observation.size);

        if (observation.address != 0) {
            finding.attributes["address"] =
                static_cast<uint64_t>(
                    observation.address);
        }

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