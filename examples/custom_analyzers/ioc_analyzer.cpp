/**
 * @file    ioc_analyzer.cpp
 * @brief   Implementation of IoC memory analyzer.
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

#include "ioc_analyzer.hpp"

#include <string>

std::string IocAnalyzer::name() const {
    return "ioc_scanner";
}

std::string IocAnalyzer::description() const {
    return "Scans for specific indicators of compromise";
}

runtimexray::AnalyzerCategory IocAnalyzer::category() const {
    return runtimexray::AnalyzerCategory::Memory;
}

runtimexray::FindingList IocAnalyzer::analyze(const runtimexray::Evidence& evidence) const {
    runtimexray::FindingList findings;
    if (auto* mem = std::get_if<runtimexray::MemoryChunkEvidence>(&evidence)) {
        if (mem->chunk.find("malicious.command") != std::string::npos ||
            mem->chunk.find("cnc.example.com") != std::string::npos) {
            findings.emplace_back(
                runtimexray::FindingSeverity::Critical,
                "IoC detected in process memory",
                "Known malicious indicator found.",
                runtimexray::MemorySecretFindingDetails{
                    mem->chunk, "ioc", mem->location
                }
            );
        }
    }
    return findings;
}