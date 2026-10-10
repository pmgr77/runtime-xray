/**
 * @file    detection_rule_registry.cpp
 * @brief   Implementation of RuntimeXRay detection rule registry.
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

#include "detection_rule_registry.hpp"
#include "register_builtin_detection_rules.hpp"

#include <algorithm>
#include <utility>

namespace runtimexray {

DetectionRuleRegistry& DetectionRuleRegistry::instance()
{
    static DetectionRuleRegistry registry;
    return registry;
}

void DetectionRuleRegistry::register_rule(
    std::unique_ptr<IDetectionRule> rule)
{
    if (!rule) {
        return;
    }

    const std::string rule_id = rule->id();

    //
    // Rule ID is the stable implementation identity. Re-registration replaces
    // the previous implementation rather than causing duplicate execution.
    //
    rules_.erase(
        std::remove_if(
            rules_.begin(),
            rules_.end(),
            [&rule_id](const std::unique_ptr<IDetectionRule>& existing) {
                return existing->id() == rule_id;
            }),
        rules_.end());

    rules_.push_back(std::move(rule));

    //
    // A newly registered implementation is enabled by default.
    //
    disabled_rules_.erase(rule_id);
}

void DetectionRuleRegistry::unregister_rule(
    const std::string& rule_id)
{
    rules_.erase(
        std::remove_if(
            rules_.begin(),
            rules_.end(),
            [&rule_id](const std::unique_ptr<IDetectionRule>& rule) {
                return rule->id() == rule_id;
            }),
        rules_.end());

    disabled_rules_.erase(rule_id);
}

void DetectionRuleRegistry::disable_rule(
    const std::string& rule_id)
{
    disabled_rules_.insert(rule_id);
}

void DetectionRuleRegistry::enable_rule(
    const std::string& rule_id)
{
    disabled_rules_.erase(rule_id);
}

std::vector<const IDetectionRule*>
DetectionRuleRegistry::active_rules(
    DetectionStage stage) const
{
    std::vector<const IDetectionRule*> result;

    for (const auto& rule : rules_) {
        if (disabled_rules_.count(rule->id()) != 0) {
            continue;
        }

        if (rule->stage() != stage) {
            continue;
        }

        result.push_back(rule.get());
    }

    //
    // Registration order must not influence Finding IDs or report ordering.
    //
    std::sort(
        result.begin(),
        result.end(),
        [](const IDetectionRule* lhs,
           const IDetectionRule* rhs) {
            return lhs->id() < rhs->id();
        });

    return result;
}

std::vector<std::string>
DetectionRuleRegistry::list_rule_ids() const
{
    std::vector<std::string> result;
    result.reserve(rules_.size());

    for (const auto& rule : rules_) {
        result.push_back(rule->id());
    }

    std::sort(result.begin(), result.end());

    return result;
}

} // namespace runtimexray