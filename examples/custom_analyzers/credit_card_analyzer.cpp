/**
 * @file    credit_card_analyzer.cpp
 * @brief   Implementation of credit card memory analyzer.
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

#include "credit_card_analyzer.hpp"

#include <cctype>
#include <string>

std::string CreditCardAnalyzer::name() const {
    return "credit_card";
}

std::string CreditCardAnalyzer::description() const {
    return "Detects potential credit card numbers in memory";
}

runtimexray::AnalyzerCategory CreditCardAnalyzer::category() const {
    return runtimexray::AnalyzerCategory::Memory;
}

runtimexray::FindingList CreditCardAnalyzer::analyze(const runtimexray::Evidence& evidence) const {
    runtimexray::FindingList findings;
    if (auto* mem = std::get_if<runtimexray::MemoryChunkEvidence>(&evidence)) {
        const std::string& chunk = mem->chunk;
        size_t pos = 0;
        while ((pos = chunk.find_first_of("0123456789", pos)) != std::string::npos) {
            size_t end = pos;
            int digits = 0;
            while (end < chunk.size() && digits < 19 && std::isdigit(static_cast<unsigned char>(chunk[end]))) {
                ++digits;
                ++end;
            }
            if (digits >= 13 && digits <= 19) {
                std::string card = chunk.substr(pos, static_cast<std::size_t>(digits));
                findings.emplace_back(
                    runtimexray::FindingSeverity::High,
                    "Credit card number found in memory",
                    "Potential PAN data detected.",
                    runtimexray::MemorySecretFindingDetails{card, "credit_card", mem->location}
                );
                pos = end;
            } else {
                pos = end;
            }
        }
    }
    return findings;
}
