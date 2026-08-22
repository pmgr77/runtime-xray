/**
 * @file    finding_filter.hpp
 * @brief   Declaration of central severity/verbosity filtering for findings.
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

#ifndef RUNTIMEXRAY_FINDING_FILTER_HPP
#define RUNTIMEXRAY_FINDING_FILTER_HPP

#include "finding.hpp"

namespace runtimexray {

/**
 * @brief Checks whether a finding should be shown based on severity and verbosity.
 * @param f Finding to check.
 * @param min_severity Minimum severity threshold.
 * @param verbose If true, show all findings regardless of severity.
 * @return true if the finding should be shown, false otherwise.
 */
bool should_show_finding(const Finding& f, FindingSeverity min_severity, bool verbose = false);

/**
 * @brief Filters a list of findings in-place according to severity and verbosity.
 * @param findings The list to filter.
 * @param min_severity Minimum severity threshold.
 * @param verbose If true, keep all findings.
 */
void filter_findings(FindingList& findings, FindingSeverity min_severity, bool verbose = false);

} // namespace runtimexray

#endif // RUNTIMEXRAY_FINDING_FILTER_HPP