/**
 * @file    dangerous_api_rule.hpp
 * @brief   Detection rule for dangerous imported APIs.
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

#ifndef RUNTIMEXRAY_DANGEROUS_API_RULE_HPP
#define RUNTIMEXRAY_DANGEROUS_API_RULE_HPP

#include "idetection_rule.hpp"

namespace runtimexray {

class DangerousApiRule final : public IDetectionRule {
public:
    std::string id() const override;
    std::string description() const override;
    DetectionStage stage() const override;

    FindingList detect(
        const DetectionContext& context) const override;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_DANGEROUS_API_RULE_HPP