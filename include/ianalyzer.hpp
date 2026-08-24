/**
 * @file    ianalyzer.hpp
 * @brief   Interface for custom security analyzers.
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

#ifndef RUNTIMEXRAY_IANALYZER_HPP
#define RUNTIMEXRAY_IANALYZER_HPP

#include "finding.hpp"
#include "evidence.hpp"

#include <string>
#include <vector>

namespace runtimexray {

/**
 * @brief Categories of analyzers. Helps users understand when an analyzer is called.
 */
enum class AnalyzerCategory {
    Static,         // receives SymbolEvidence, HardeningEvidence
    Dynamic,        // receives SyscallEventEvidence, FileAccessEvidence, NetworkEvidence
    Memory,         // receives MemoryChunkEvidence
    PostProcess     // receives the final FindingList (special, not via Evidence)
};

/**
 * @brief Base interface for all custom analyzers.
 *
 * Users implement this interface to add custom security checks.
 * Each analyzer receives an Evidence object and returns a list of Findings.
 */
class IAnalyzer {
public:
    virtual ~IAnalyzer() = default;

    /** @return Unique analyzer name, e.g. "my_custom_aws_key_detector". */
    virtual std::string name() const = 0;

    /** @return Short human-readable description. */
    virtual std::string description() const = 0;

    /** @return The category this analyzer belongs to. */
    virtual AnalyzerCategory category() const = 0;

    /**
     * @brief Analyzes a single evidence item and returns findings.
     * @param evidence The observed evidence.
     * @return List of findings produced by this analyzer.
     */
    virtual FindingList analyze(const Evidence& evidence) const = 0;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_IANALYZER_HPP