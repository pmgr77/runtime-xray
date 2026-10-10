/**
 * @file    register_builtin_detection_rules.cpp
 * @brief   Registers RuntimeXRay built-in detection rules.
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

#include "register_builtin_detection_rules.hpp"

#include "dangerous_api_rule.hpp"
#include "detection_rule_registry.hpp"
#include "hardening_rule.hpp"
#include "sensitive_data_presence_rule.hpp"
#include "sensitive_file_access_rule.hpp"
#include "network_rule.hpp"
#include "sensitive_data_flow_rule.hpp"

#include <memory>

namespace runtimexray {

void register_builtin_detection_rules(
    DetectionRuleRegistry& registry)
{
    registry.register_rule(
        std::make_unique<HardeningRule>());

    registry.register_rule(
        std::make_unique<DangerousApiRule>());

    registry.register_rule(
        std::make_unique<SensitiveFileAccessRule>());

    registry.register_rule(
        std::make_unique<NetworkRule>());

    registry.register_rule(
        std::make_unique<SensitiveDataPresenceRule>());

    registry.register_rule(
        std::make_unique<SensitiveDataFlowRule>());
}

} // namespace runtimexray