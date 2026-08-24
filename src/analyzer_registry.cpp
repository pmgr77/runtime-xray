/**
 * @file    analyzer_registry.cpp
 * @brief   Implementation of the analyzer registry.
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

#include <algorithm>

namespace runtimexray {

    AnalyzerRegistry& AnalyzerRegistry::instance() {
        static AnalyzerRegistry registry;
        return registry;
    }

    AnalyzerRegistry::AnalyzerRegistry() {
        // Built-in analyzers will be registered later; initially empty.
    }


    void AnalyzerRegistry::register_analyzer(std::unique_ptr<IAnalyzer> analyzer) {
        if (!analyzer) {
            return;
        }
        for (const auto& a : analyzers_) {
            if (a->name() == analyzer->name()) {
                return;
            }
        }
        analyzers_.push_back(std::move(analyzer));
    }

    void AnalyzerRegistry::unregister_analyzer(const std::string& name) {
        analyzers_.erase(
            std::remove_if(analyzers_.begin(), analyzers_.end(),
            [&](const std::unique_ptr<IAnalyzer>& a) {
                return a->name() == name;
            }),
            analyzers_.end());
        disabled_analyzers_.erase(name);
    }

    void AnalyzerRegistry::disable_analyzer(const std::string& name) {
        disabled_analyzers_.insert(name);
    }

    void AnalyzerRegistry::enable_analyzer(const std::string& name) {
        disabled_analyzers_.erase(name);
    }

    std::vector<IAnalyzer*> AnalyzerRegistry::active_analyzers() const {
        std::vector<IAnalyzer*> active;
        for (const auto& a : analyzers_) {
            if (disabled_analyzers_.count(a->name()) == 0) {
                active.push_back(a.get());
            }
        }
        return active;
     }

     std::vector<std::string> AnalyzerRegistry::list_analyzers() const {
        std::vector<std::string> names;
        for (const auto& a : analyzers_) {
            names.push_back(a->name());
        }
        return names;
     }

    FindingList AnalyzerRegistry::analyze_evidence(const Evidence& evidence) const {
        FindingList results;
        for (const auto& analyzer : active_analyzers()) {
            // We could filter by category, but for simplicity call all active analyzers.
            // Each analyzer is responsible for deciding whether it handles the evidence type.
            FindingList found = analyzer->analyze(evidence);
            results.insert(results.end(), found.begin(), found.end());
        }
        return results;
    }

} // namespace runtimexray