/**
 * @file    detection_rule_registry.hpp
 * @brief   Registry for RuntimeXRay graph-based detection rules.
 *
 * DetectionRuleRegistry owns registered IDetectionRule implementations and
 * manages their enabled or disabled state.
 *
 * The registry does not execute detection stages and does not create Findings.
 * Execution order, stage isolation, and Finding identity assignment belong to
 * DetectionEngine.
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

#ifndef RUNTIMEXRAY_DETECTION_RULE_REGISTRY_HPP
#define RUNTIMEXRAY_DETECTION_RULE_REGISTRY_HPP

#include "idetection_rule.hpp"

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace runtimexray {

/**
 * @brief Owns RuntimeXRay detection rules.
 *
 * Rule IDs are unique identities. Registering another rule with the same ID
 * replaces the previous implementation.
 *
 * Rules are enabled by default.
 */
class DetectionRuleRegistry {
public:
    /**
     * @brief Return the process-wide rule registry.
     */
    static DetectionRuleRegistry& instance();

    /**
     * @brief Register a detection rule and take ownership of it.
     *
     * An existing rule with the same ID is replaced.
     *
     * @param rule Rule to register.
     */
    void register_rule(std::unique_ptr<IDetectionRule> rule);

    /**
     * @brief Remove a rule by stable rule ID.
     *
     * @param rule_id Rule identity returned by IDetectionRule::id().
     */
    void unregister_rule(const std::string& rule_id);

    /**
     * @brief Disable a rule without removing it.
     */
    void disable_rule(const std::string& rule_id);

    /**
     * @brief Re-enable a disabled rule.
     */
    void enable_rule(const std::string& rule_id);

    /**
     * @brief Return enabled rules belonging to one detection stage.
     *
     * Returned pointers remain owned by the registry.
     *
     * Rules are returned sorted by stable rule ID. Detection semantics must not
     * depend on rule order, but deterministic ordering makes Finding identity
     * assignment and tests reproducible.
     */
    std::vector<const IDetectionRule*> active_rules(
        DetectionStage stage) const;

    /**
     * @brief Return IDs of all registered rules.
     */
    std::vector<std::string> list_rule_ids() const;

private:
    DetectionRuleRegistry() = default;

    std::vector<std::unique_ptr<IDetectionRule>> rules_;
    std::unordered_set<std::string> disabled_rules_;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_DETECTION_RULE_REGISTRY_HPP