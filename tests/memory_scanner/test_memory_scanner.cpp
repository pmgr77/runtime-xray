/**
 * @file    test_memory_scanner.cpp
 * @brief   Tests for the analyzer registry using memory evidence.
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

#include "analyzer_registry.hpp"
#include "evidence.hpp"
#include "finding.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

// Helper: check if the findings contain a memory secret of a given type.
bool contains_memory_secret(const runtimexray::FindingList& findings,
                            const std::string& secret_type) {
    for (const auto& f : findings) {
        if (auto* details = std::get_if<runtimexray::MemorySecretFindingDetails>(&f.details)) {
            if (details->secret_type == secret_type) {
                return true;
            }
        }
    }
    return false;
}

int main() {
    auto& registry = runtimexray::AnalyzerRegistry::instance();

    // Built-in analyzers should be registered.
    auto analyzer_names = registry.list_analyzers();
    if (analyzer_names.empty()) {
        std::cerr << "No analyzers registered.\n";
        return 1;
    }

    // 1. Password evidence should produce a finding with secret_type == "password".
    runtimexray::MemoryChunkEvidence password_ev{
        "some text password=supersecret123 more text",
        "memory",
        getpid()
    };
    auto password_findings = registry.analyze_evidence(password_ev);
    if (!contains_memory_secret(password_findings, "password")) {
        std::cerr << "Password analyzer failed to detect password evidence.\n";
        return 1;
    }

    // 2. Private key evidence should produce a finding with secret_type == "private_key".
    runtimexray::MemoryChunkEvidence key_ev{
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----",
        "memory",
        getpid()
    };
    auto key_findings = registry.analyze_evidence(key_ev);
    if (!contains_memory_secret(key_findings, "private_key")) {
        std::cerr << "Private key analyzer failed to detect private key evidence.\n";
        return 1;
    }

    std::cout << "Memory scanner analyzer tests passed.\n";
    return 0;
}