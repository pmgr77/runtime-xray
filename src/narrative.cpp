/**
 * @file    narrative.cpp
 * @brief   Builds executable narrative sessions from lineage observations.
 *
 * The narrative layer is derived from the lineage graph and does not replace
 * it as RuntimeXRay's source of evidence. Its purpose is to organize low-level
 * observations into executable-image lifetimes that can later be associated
 * with Findings and rendered as higher-level security narratives.
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

#include "narrative.hpp"

#include <algorithm>
#include <map>

namespace runtimexray {

std::vector<NarrativeSession> build_narrative_sessions(const LineageGraph& graph)
{
    //
    // Build sessions by executable-image identity.
    //
    // std::map is used here for simple deterministic grouping. Its ordering is
    // not used as narrative chronology; sessions are sorted by first_seq before
    // being returned.
    //
    std::map<SessionId, NarrativeSession> sessions;

    for (const auto& obs : graph.observations) {
        //
        // Observations without a RuntimeXRay process-instance identity cannot
        // be assigned reliably to an executable session.
        //
        if (obs.process_instance_id == 0) {
            continue;
        }

        //
        // A process node describes the entire process lifetime. The same
        // process instance may span several exec generations, so assigning
        // the process node to one session would be misleading.
        //
        if (obs.type == ObservationType::Event &&
            obs.syscall_name == "process") {
            continue;
        }

        const SessionId id {
            obs.process_instance_id,
            obs.exec_generation
        };

        auto [it, inserted] = sessions.try_emplace(id);
        auto& session = it->second;

        if (inserted) {
            session.id = id;
            session.tgid = obs.tgid > 0 ? obs.tgid : obs.pid;
            session.first_seq = obs.seq;
        }

        //
        // seq=0 means the observation has not received a stable lineage
        // sequence number and therefore should not be exposed as narrative
        // evidence.
        //
        if (obs.seq != 0) {
            session.observation_seqs.push_back(obs.seq);
            session.last_seq = obs.seq;
        }
    }

    //
    // Resolve generation-zero executable names.
    //
    // The process observation represents the initial image known when the
    // process instance entered the lineage graph.
    //
    std::map<uint64_t, std::string> initial_programs;
    for (const auto& obs : graph.observations) {
        if (obs.type != ObservationType::Event ||
            obs.syscall_name != "process" ||
            obs.process_instance_id == 0 ||
            obs.program_name.empty())
        {
            continue;
        }

        initial_programs[obs.process_instance_id] = obs.program_name;
    }

    //
    // Resolve executable names introduced by exec.
    //
    // RuntimeXRay deliberately associates the exec syscall with the OLD
    // generation:
    //
    //     generation 0: execve("/bin/echo")
    //     generation 1: /bin/echo executes
    //
    // Therefore the program named by a successful exec observation belongs
    // to exec_generation + 1.
    //
    std::map<SessionId, std::string> exec_programs;
    for (const auto& obs : graph.observations) {
        if (obs.type != ObservationType::Event) {
            continue;
        }

        if (obs.syscall_name != "execve" &&
            obs.syscall_name != "execveat") {
            continue;
        }

        if (obs.process_instance_id == 0 || obs.program_name.empty()) {
            continue;
        }

        // Only a successful exec creates a new executable generation.
        if (obs.return_value != 0) {
            continue;
        }

        // exec itself belongs to the OLD generation.
        // Its program_name names the NEXT executable image.
        const SessionId next_session {
            obs.process_instance_id,
            obs.exec_generation + 1
        };

        exec_programs[next_session] = obs.program_name;
    }

    //
    // Attach the best executable identity available to each derived session.
    //
    // Missing names are intentionally left empty instead of being guessed.
    //
    for (auto& [id, session] : sessions) {
        if (id.exec_generation == 0) {
            auto it = initial_programs.find(id.process_instance_id);
            if (it != initial_programs.end()) {
                session.program_name = it->second;
            }
        } else {
            auto it = exec_programs.find(id);
            if (it != exec_programs.end()) {
                session.program_name = it->second;
            }
        }
    }

    //
    // Convert the grouping map into the public representation.
    //
    std::vector<NarrativeSession> result;
    result.reserve(sessions.size());
    for (auto& [id, session] : sessions) {
        (void)id;
        result.push_back(std::move(session));
    }

    //
    // Narrative order follows the collector-observed sequence rather than
    // process-instance or exec-generation numeric ordering.
    //
    std::sort(
        result.begin(),
        result.end(),
        [](const NarrativeSession& a, const NarrativeSession& b) {
            return a.first_seq < b.first_seq;
        });

    return result;
}

} // namespace runtimexray