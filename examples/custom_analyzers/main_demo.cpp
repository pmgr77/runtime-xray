/**
 * @file    main_demo.cpp
 * @brief   Demo of custom analyzers for RuntimeXRay.
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

#include <analyzer_registry.hpp>
#include <evidence.hpp>
#include <finding.hpp>

#include "credit_card_analyzer.hpp"
#include "cloud_credential_analyzer.hpp"
#include "ioc_analyzer.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>

// Helper to print a finding with its details.
void print_finding(const runtimexray::Finding& f) {
    std::cout << "[" << (int)f.severity << "] " << f.description << "\n";
    if (auto* d = std::get_if<runtimexray::MemorySecretFindingDetails>(&f.details)) {
        std::cout << "    type: " << d->secret_type
                  << " location: " << d->location
                  << " snippet: " << d->snippet << "\n";
    }
}

int main() {
    // Register custom analyzers.
    auto& registry = runtimexray::AnalyzerRegistry::instance();
    registry.register_analyzer(std::make_unique<CreditCardAnalyzer>());
    registry.register_analyzer(std::make_unique<CloudCredentialAnalyzer>());
    registry.register_analyzer(std::make_unique<IocAnalyzer>());

    // Create test evidence.
    std::vector<runtimexray::MemoryChunkEvidence> test_chunks = {
        {"some text 4111-1111-1111-1111 more text", "memory", getpid()},
        {"config aws_access_key_id=AKIAIOSFODNN7EXAMPLE", "memory", getpid()},
        {"connection to cnc.example.com established", "memory", getpid()}
    };

    // Run each evidence chunk through the registry.
    for (const auto& chunk : test_chunks) {
        auto findings = registry.analyze_evidence(chunk);
        for (const auto& f : findings) {
            print_finding(f);
        }
    }

    std::cout << "Done.\n";
    return 0;
}