/**
 * @file    finding_filter.cpp
 * @brief   Implementation of severity/verbosity filtering for findings.
 *
 * @author  Peter Magram
 * @date    2026-08-22
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

#include "finding_filter.hpp"

#include <algorithm>

namespace runtimexray {

bool should_show_finding(const Finding& f, FindingSeverity min_severity, bool verbose) {
    if (verbose) {
        return true; // Show everything
    }
    // Lower numeric value = more severe (Critical=0, High=1, Medium=2, Low=3, Info=4)
    return static_cast<int>(f.severity) <= static_cast<int>(min_severity);
}

void filter_findings(FindingList& findings, FindingSeverity min_severity, bool verbose) {
    findings.erase(
        std::remove_if(findings.begin(), findings.end(),
                       [min_severity, verbose](const Finding& f) {
                           return !should_show_finding(f, min_severity, verbose);
                       }),
        findings.end());
}

} // namespace runtimexray