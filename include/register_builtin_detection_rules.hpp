/**
 * @file    register_builtin_detection_rules.hpp
 * @brief   Declares registration of built-in RuntimeXRay detection rules.
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

#ifndef RUNTIMEXRAY_REGISTER_BUILTIN_DETECTION_RULES_HPP
#define RUNTIMEXRAY_REGISTER_BUILTIN_DETECTION_RULES_HPP

namespace runtimexray {

class DetectionRuleRegistry;

/**
 * @brief Register all built-in RuntimeXRay detection rules.
 *
 * The supplied registry owns all registered rule instances.
 */
void register_builtin_detection_rules(
    DetectionRuleRegistry& registry);

} // namespace runtimexray

#endif // RUNTIMEXRAY_REGISTER_BUILTIN_DETECTION_RULES_HPP