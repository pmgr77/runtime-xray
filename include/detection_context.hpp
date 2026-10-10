/**
 * @file    detection_context.hpp
 * @brief   Defines the read-only input available to detection rules.
 *
 * Detection rules analyze a completed LineageGraph and may also inspect
 * Findings produced by an earlier detection stage.
 *
 * The context is intentionally read-only. Rules return new Findings rather
 * than mutating the graph or previously produced Findings.
 *
 * @author  Peter Magram
 * @date    2026-10-10
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

#ifndef RUNTIMEXRAY_DETECTION_CONTEXT_HPP
#define RUNTIMEXRAY_DETECTION_CONTEXT_HPP

#include "finding.hpp"
#include "lineage.hpp"

namespace runtimexray {

/**
 * @brief Read-only analysis input supplied to a DetectionRule.
 *
 * graph contains the complete evidence collected for the current analysis.
 *
 * previous_stage_findings contains a frozen snapshot of Findings produced by
 * the previous detection stage.
 *
 * For Primary rules this list is empty.
 *
 * For Composite rules it contains the completed Primary-stage Findings.
 *
 * Rules must not depend on Findings produced by other rules in the same stage.
 * This guarantees that detection results do not depend on rule registration
 * or execution order.
 */
struct DetectionContext {
    const LineageGraph& graph;
    const FindingList& previous_stage_findings;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_DETECTION_CONTEXT_HPP