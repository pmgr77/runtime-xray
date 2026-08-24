/**
 * @file    analyzer_registry.hpp
 * @brief   Registry for managing and running analyzers.
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

#ifndef RUNTIMEXRAY_ANALYZER_REGISTRY_HPP
#define RUNTIMEXRAY_ANALYZER_REGISTRY_HPP

#include "ianalyzer.hpp"
#include "finding.hpp"
#include "evidence.hpp"

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace runtimexray {

/**
 * @brief Singleton registry for all analyzers.
 *
 * Low-level collectors feed Evidence into this registry. All registered
 * analyzers that match the evidence category are executed and their findings
 * are aggregated.
 */
class AnalyzerRegistry {
public:
    static AnalyzerRegistry& instance();

    /** @brief Registers a new analyzer. Takes ownership. */
    void register_analyzer(std::unique_ptr<IAnalyzer> analyzer);

    /** @brief Unregisters and deletes an analyzer by name. */
    void unregister_analyzer(const std::string& name);

    /** @brief Disables an analyzer by name (keeps it but skips execution). */
    void disable_analyzer(const std::string& name);

    /** @brief Re-enables a previously disabled analyzer. */
    void enable_analyzer(const std::string& name);

    /** @brief Returns all active analyzers. */
    std::vector<IAnalyzer*> active_analyzers() const;

    /** @brief Returns names of all registered analyzers. */
    std::vector<std::string> list_analyzers() const;

    /**
     * @brief Feeds an Evidence object through all active analyzers.
     * @param evidence The evidence to analyze.
     * @return Aggregated findings from all analyzers that processed this evidence.
     */
    FindingList analyze_evidence(const Evidence& evidence) const;

private:
    AnalyzerRegistry(); // private constructor for singleton

    std::vector<std::unique_ptr<IAnalyzer>> analyzers_;
    std::unordered_set<std::string> disabled_analyzers_;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_ANALYZER_REGISTRY_HPP