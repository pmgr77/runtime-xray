/**
 * @file    credit_card_analyzer.hpp
 * @brief   Credit card number memory analyzer example.
 *
 * @author  Peter Magram
 * @date    2026-08-24
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

#ifndef RUNTIMEXRAY_EXAMPLE_CREDIT_CARD_ANALYZER_HPP
#define RUNTIMEXRAY_EXAMPLE_CREDIT_CARD_ANALYZER_HPP

#include <ianalyzer.hpp>
#include <evidence.hpp>
#include <finding.hpp>

class CreditCardAnalyzer : public runtimexray::IAnalyzer {
public:
    std::string name() const override;
    std::string description() const override;
    runtimexray::AnalyzerCategory category() const override;
    runtimexray::FindingList analyze(const runtimexray::Evidence& evidence) const override;
};

#endif