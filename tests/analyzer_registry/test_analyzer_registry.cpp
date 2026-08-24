/**
 * @file    test_analyzer_registry.cpp
 * @brief   Unit tests for the analyzer registry.
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
#include <variant>

int main() {
    using namespace runtimexray;
    auto& registry = AnalyzerRegistry::instance();

    // 1. HardeningAnalyzer
    {
        HardeningEvidence ev{"NX", "Disabled"};
        auto findings = registry.analyze_evidence(ev);
        bool found = false;
        for (const auto& f : findings) {
            if (auto* d = std::get_if<HardeningFindingDetails>(&f.details)) {
                if (d->feature == "NX" && d->status == "Disabled") {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            std::cerr << "HardeningAnalyzer failed\n";
            return 1;
        }
    }

    // 2. DangerousApiAnalyzer
    {
        SymbolEvidence ev{"strcpy", "import"};
        auto findings = registry.analyze_evidence(ev);
        bool found = false;
        for (const auto& f : findings) {
            if (auto* d = std::get_if<DangerousApiFindingDetails>(&f.details)) {
                if (d->api == "strcpy") {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            std::cerr << "DangerousApiAnalyzer failed\n";
            return 1;
        }
    }

    // 3. SensitiveFileAnalyzer
    {
        FileAccessEvidence ev{"/etc/shadow", 0, 123};
        auto findings = registry.analyze_evidence(ev);
        bool found = false;
        for (const auto& f : findings) {
            if (auto* d = std::get_if<SensitiveFileAccessDetails>(&f.details)) {
                if (d->path == "/etc/shadow") {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            std::cerr << "SensitiveFileAnalyzer failed\n";
            return 1;
        }
    }

    // 4. NetworkAnalyzer
    {
        NetworkEvidence ev{"1.2.3.4", 22, 123, "outbound"};
        auto findings = registry.analyze_evidence(ev);
        bool found = false;
        for (const auto& f : findings) {
            if (auto* d = std::get_if<NetworkConnectionDetails>(&f.details)) {
                if (d->port == 22) {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            std::cerr << "NetworkAnalyzer failed\n";
            return 1;
        }
    }

    std::cout << "Analyzer registry tests passed.\n";
    return 0;
}