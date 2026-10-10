/**
 * @file    sensitive_file_access_rule.hpp
 * @brief   Detects attempts to access known sensitive filesystem paths.
 *
 * This Primary detection rule analyzes completed LineageGraph observations.
 * It detects open()/openat() attempts targeting known sensitive paths and
 * returns canonical Findings.
 *
 * Detection does not require the open to succeed. A denied or failed attempt
 * is still security-relevant evidence of what the process tried to access.
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

#ifndef RUNTIMEXRAY_SENSITIVE_FILE_ACCESS_RULE_HPP
#define RUNTIMEXRAY_SENSITIVE_FILE_ACCESS_RULE_HPP

#include "idetection_rule.hpp"

#include <string>

namespace runtimexray {

/**
 * @brief Detects attempts to access sensitive filesystem resources.
 *
 * This is a Primary rule. Each matching open()/openat() Observation produces
 * one sensitive_resource_access Finding.
 */
class SensitiveFileAccessRule : public IDetectionRule {
public:
    std::string id() const override;

    std::string description() const override;

    DetectionStage stage() const override;

    FindingList detect(
        const DetectionContext& context) const override;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_SENSITIVE_FILE_ACCESS_RULE_HPP