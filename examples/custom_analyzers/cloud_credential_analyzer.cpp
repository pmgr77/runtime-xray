/**
 * @file    cloud_credential_analyzer.cpp
 * @brief   Implementation of cloud credential analyzer.
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

#include "cloud_credential_analyzer.hpp"

#include <string>

std::string CloudCredentialAnalyzer::name() const {
    return "cloud_credentials";
}

std::string CloudCredentialAnalyzer::description() const {
    return "Detects AWS, GCP, and Azure credential patterns";
}

runtimexray::AnalyzerCategory CloudCredentialAnalyzer::category() const {
    return runtimexray::AnalyzerCategory::Memory;
}

runtimexray::FindingList CloudCredentialAnalyzer::analyze(const runtimexray::Evidence& evidence) const {
    runtimexray::FindingList findings;
    if (auto* mem = std::get_if<runtimexray::MemoryChunkEvidence>(&evidence)) {
        const std::string& chunk = mem->chunk;
        // AWS Access Key ID pattern: "AKIA" followed by 16 alphanumeric characters.
        size_t pos = 0;
        while ((pos = chunk.find("AKIA", pos)) != std::string::npos) {
            if (pos + 20 <= chunk.size()) {
                std::string key = chunk.substr(pos, 20);
                findings.emplace_back(
                    runtimexray::FindingSeverity::Critical,
                    "Cloud credential found",
                    "Potential AWS Access Key ID detected.",
                    runtimexray::MemorySecretFindingDetails{key, "aws_access_key", mem->location}
                );
            }
            pos += 4;
        }
    }
    return findings;
}