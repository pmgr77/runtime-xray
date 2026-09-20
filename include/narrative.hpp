/**
 * @file    narrative.hpp
 * @brief   Derived narrative model built from RuntimeXRay lineage observations.
 *
 * A narrative session represents one executable-image lifetime inside a
 * RuntimeXRay process instance. Sessions are identified by the pair:
 *
 *     (process_instance_id, exec_generation)
 *
 * The lineage graph remains the source of truth. Narrative structures are
 * derived views intended to organize observations and findings into a form
 * suitable for higher-level security explanations and reporting.
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

#ifndef RUNTIMEXRAY_NARRATIVE_HPP
#define RUNTIMEXRAY_NARRATIVE_HPP

#include "lineage.hpp"
#include "finding.hpp"

#include <cstdint>
#include <string>
#include <tuple>
#include <vector>
#include <sys/types.h>
#include <cstddef>

namespace runtimexray {

/**
 * @brief Stable identity of one executable-image lifetime.
 *
 * A process instance may execute multiple program images over its lifetime.
 * Each successful exec advances exec_generation while preserving the same
 * process_instance_id.
 *
 * Example:
 *
 *     process_instance_id = 7, exec_generation = 0  -> ./launcher
 *     process_instance_id = 7, exec_generation = 1  -> /bin/worker
 *
 * The important comments there explain the three non-obvious concepts:
 *
 * (1) Session != process
 *     Session = one executable-image lifetime
 *
 * (2) SessionId ordering != runtime ordering
 *
 * (3) seq ordering != causality
 */
struct SessionId {
    uint64_t process_instance_id = 0;
    uint64_t exec_generation = 0;

    /**
     * @brief Ordering required for use as a std::map key.
     *
     * This ordering is an identity ordering only. It does not imply runtime
     * chronology; sessions are ordered by first_seq when returned to callers.
     */
    bool operator<(const SessionId& other) const noexcept {
        return
            std::tie(process_instance_id, exec_generation) <
            std::tie(other.process_instance_id, other.exec_generation);
    }
};

/**
 * @brief Association between a Finding and the evidence belonging to one
 *        narrative session.
 *
 * finding_index is local to the FindingList used to build the narrative
 * model. It is not a persistent or externally visible finding identifier.
 *
 * Evidence remains identified by stable Observation::seq values.
 */
struct NarrativeFindingRef {
    size_t finding_index = 0;

    // Only the evidence observations from this finding that belong to
    // this particular session.
    std::vector<uint64_t> evidence_observation_seqs;
};

/**
 * @brief Derived view of all observations belonging to one executable image.
 *
 * Observation sequence numbers are stored instead of vector indices so the
 * session refers to the same stable observation identifiers used by Findings.
 *
 * first_seq and last_seq describe collector-observed order. They do not imply
 * causal relationships between observations.
 */
struct NarrativeSession {
    SessionId id;
    // Linux thread-group identity of the process that owns this session.
    pid_t tgid = -1;
    // Executable associated with this generation, when it can be resolved.
    std::string program_name;
    // Inclusive observed sequence range covered by this session.
    uint64_t first_seq = 0;
    uint64_t last_seq = 0;
    // Stable Observation::seq values belonging to this executable generation.
    std::vector<uint64_t> observation_seqs;
    // Findings supported by observations in this executable session.
    // A composite finding may appear in more than one session.
    std::vector<NarrativeFindingRef> finding_refs;
};

/**
 * @brief Derive executable sessions from a lineage graph.
 *
 * Process observations are intentionally excluded because a process node
 * represents the complete process lifetime and may span multiple exec
 * generations.
 *
 * Generation 0 obtains its executable name from the process observation.
 * Later generations obtain their executable name from the successful exec
 * observation belonging to the previous generation.
 *
 * @param graph Source lineage graph.
 * @return Sessions ordered by the first observation seen in each session.
 */
std::vector<NarrativeSession> build_narrative_sessions(const LineageGraph& graph);

/**
 * @brief Associate findings with their supporting narrative sessions.
 *
 * Finding evidence is resolved through stable Observation::seq values.
 * A finding may be associated with multiple sessions when its supporting
 * observations cross process or exec-generation boundaries.
 *
 * Evidence references that do not belong to any known session are ignored;
 * no session identity is guessed.
 */
void associate_findings_with_sessions(const FindingList& findings, std::vector<NarrativeSession>& sessions);

} // namespace runtimexray

#endif // RUNTIMEXRAY_NARRATIVE_HPP