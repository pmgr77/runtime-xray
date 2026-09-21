/**
 * @file    narrative_builder.hpp
 * @brief   Builds evidence-backed security narratives from RuntimeXRay findings.
 *
 * NarrativeBuilder converts structured findings and lineage observations into
 * human-readable statements. Every statement retains the stable observation
 * sequence numbers that support it.
 *
 * The builder must not infer causality merely from matching fingerprints.
 *
 * @author  Peter Magram
 * @date    2026-09-20
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

#ifndef RUNTIMEXRAY_NARRATIVE_BUILDER_HPP
#define RUNTIMEXRAY_NARRATIVE_BUILDER_HPP

#include "finding.hpp"
#include "lineage.hpp"
#include "narrative.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace runtimexray {

/**
 * @brief One human-readable claim backed by lineage observations.
 */
struct NarrativeStatement {
    std::string text;

    // Stable Observation::seq values supporting this exact statement.
    std::vector<uint64_t> evidence_observation_seqs;
};

struct NarrativeSessionContext {
    SessionId id;
    std::string program_name;
};

/**
 * @brief Narrative explanation derived from one Finding.
 *
 * A story may span several executable sessions when its supporting
 * observations cross an exec or process boundary.
 */
struct NarrativeStory {
    // Index into the FindingList used to build this narrative.
    // Internal analysis identity only; not a persistent finding ID.
    size_t finding_index = 0;

    std::string title;

    // Fingerprint of the value around which this story was correlated.
    std::string fingerprint;

    // Executable-image lifetimes involved in this story.
    std::vector<NarrativeSessionContext> sessions;
    std::vector<NarrativeStatement> statements;
};

class NarrativeBuilder {
public:
    std::vector<NarrativeStory> build(const LineageGraph& graph, const FindingList& findings) const;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_NARRATIVE_BUILDER_HPP