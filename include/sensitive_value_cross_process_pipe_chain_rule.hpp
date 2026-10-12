/**
 * @file    sensitive_value_cross_process_pipe_chain_rule.hpp
 * @brief   Detects sensitive values observed across multi-process pipe chains.
 *
 * @author  Peter Magram
 * @date    2026-10-12
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

#ifndef RUNTIMEXRAY_SENSITIVE_VALUE_CROSS_PROCESS_PIPE_CHAIN_RULE_HPP
#define RUNTIMEXRAY_SENSITIVE_VALUE_CROSS_PROCESS_PIPE_CHAIN_RULE_HPP

#include "idetection_rule.hpp"

namespace runtimexray {

/**
 * @brief Detects the same sensitive value across a temporally connected
 *        sequence of explicit cross-process pipe DataFlow edges.
 *
 * The rule does not infer DataFlow from fingerprint equality. Every
 * inter-process boundary must already exist in LineageGraph as an explicit
 * RelationType::DataFlow edge.
 *
 * Two DataFlow boundaries are connected into one chain only when:
 *
 *   incoming.to_session == outgoing.from_session
 *
 * and the incoming read completed no later than the outgoing write started.
 *
 * A finding requires at least two cross-process pipe boundaries. A single
 * pipe DataFlow edge is already represented by the lineage graph and does
 * not justify an additional composite finding.
 */
class SensitiveValueCrossProcessPipeChainRule final : public IDetectionRule {
public:
    std::string id() const override;
    std::string description() const override;
    DetectionStage stage() const override;

    FindingList detect(const DetectionContext& context) const override;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_SENSITIVE_VALUE_CROSS_PROCESS_PIPE_CHAIN_RULE_HPP