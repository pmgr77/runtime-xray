/**
 * @file    idetection_rule.hpp
 * @brief   Interface for RuntimeXRay graph-based security detection rules.
 *
 * DetectionRule is the only layer responsible for deriving new security
 * conclusions from RuntimeXRay evidence.
 *
 * Rules inspect the LineageGraph and, for later detection stages, Findings
 * produced by an earlier stage. When a security-relevant condition is
 * detected, the rule returns a complete Finding.
 *
 * A Finding is therefore the direct canonical result of a DetectionRule;
 * there is no intermediate DetectionMatch layer.
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

#ifndef RUNTIMEXRAY_IDETECTION_RULE_HPP
#define RUNTIMEXRAY_IDETECTION_RULE_HPP

#include "detection_context.hpp"
#include "finding.hpp"

#include <string>

namespace runtimexray {

/**
 * @brief Detection stage in which a rule executes.
 *
 * Primary rules derive Findings directly from LineageGraph evidence.
 *
 * Composite rules may additionally reason about the frozen set of Findings
 * produced by the Primary stage. They can use those semantic results to build
 * higher-level conclusions without repeating lower-level classification logic.
 *
 * Rules within the same stage never observe each other's output.
 */
enum class DetectionStage {
    Primary,
    Composite
};

/**
 * @brief Base interface for all RuntimeXRay security detection rules.
 *
 * A rule owns the complete security logic for the condition it detects.
 *
 * Examples:
 *
 * Primary:
 *
 *     LineageGraph
 *          ->
 *     sensitive_resource_access Finding
 *
 * Composite:
 *
 *     LineageGraph
 *       +
 *     several sensitive_resource_access Findings
 *          ->
 *     credential_reconnaissance Finding
 *
 * Rules return complete Findings ready for later narrative generation and
 * reporting. No additional per-rule Finding adapter is required.
 */
class IDetectionRule {
public:
    virtual ~IDetectionRule() = default;

    /**
     * @brief Return the stable machine-readable identity of this rule.
     *
     * Findings produced by this rule should use this value as Finding::rule_id.
     *
     * Rule identity describes the implementation that produced the Finding.
     * Semantic consumers should normally use Finding::kind instead.
     *
     * Example:
     *
     *     "builtin.sensitive_file_access"
     */
    virtual std::string id() const = 0;

    /**
     * @brief Return a short human-readable description of the rule.
     */
    virtual std::string description() const = 0;

    /**
     * @brief Return the stage in which this rule must execute.
     */
    virtual DetectionStage stage() const = 0;

    /**
     * @brief Analyze the supplied evidence and return security Findings.
     *
     * The rule may inspect DetectionContext::graph for evidence.
     *
     * Composite rules may additionally inspect
     * DetectionContext::previous_stage_findings.
     *
     * The context is read-only. A rule must never mutate existing Findings or
     * the LineageGraph.
     *
     * Every returned Finding must contain enough information to represent the
     * rule's security conclusion, including:
     *
     *     rule_id
     *     kind
     *     severity
     *     title
     *     summary
     *     appropriate evidence references
     *
     * finding_id is intentionally not assigned by the rule. The DetectionEngine
     * assigns stable Finding IDs after collecting the complete stage output.
     *
     * @param context Read-only evidence available to the rule.
     * @return Zero or more complete Findings.
     */
    virtual FindingList detect(
        const DetectionContext& context) const = 0;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_IDETECTION_RULE_HPP