/**
 * @file    narrative_builder.cpp
 * @brief   Builds evidence-backed security narratives from RuntimeXRay findings.
 *
 * NarrativeBuilder converts structured findings and lineage observations into
 * human-readable statements while preserving the exact Observation::seq values
 * that support each statement.
 *
 * The builder operates on derived evidence rather than replacing the lineage
 * graph as the source of truth. In particular, matching fingerprints establish
 * that the same value was observed in multiple places, but do not by themselves
 * establish causality, propagation direction, or malicious intent.
 *
 * @author  Peter Magram
 * @date    2026-09-21
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

#include "narrative_builder.hpp"

#include <map>

namespace runtimexray {

std::vector<NarrativeStory> NarrativeBuilder::build(
    const LineageGraph& graph,
    const FindingList& findings) const {

    std::vector<NarrativeStory> stories;

    //
    // Build the executable-session model first.
    //
    // A session represents one executable-image lifetime identified by
    // (process_instance_id, exec_generation). Finding associations are then
    // derived from the stable observation sequence numbers attached to each
    // finding.
    //
    auto sessions = build_narrative_sessions(graph);

    associate_findings_with_sessions(findings, sessions);

    //
    // Build a stable Observation::seq -> Observation lookup.
    //
    // Narrative evidence must be resolved through stable sequence numbers,
    // never through graph vector positions.
    //
    std::map<uint64_t, const Observation*> observations_by_seq;

    for (const auto& obs : graph.observations) {
        if (obs.seq != 0) {
            observations_by_seq.emplace(obs.seq, &obs);
        }
    }

    for (size_t finding_index = 0; finding_index < findings.size(); ++finding_index) {
        const Finding& finding = findings[finding_index];

        const auto* details = std::get_if<MemorySecretFindingDetails>(&finding.details);

        //
        // Initial NarrativeBuilder support is intentionally narrow.
        //
        // Only the existing correlated sensitive-object finding is converted
        // into a story here. Other finding types will be added explicitly as
        // their narrative semantics become defined.
        //
        if (!details ||
            details->location != "correlated" ||
            details->fingerprint.empty()) {
            continue;
        }

        NarrativeStory story;

        story.finding_index = finding_index;
        story.title = finding.description;
        story.fingerprint = details->fingerprint;

        //
        // Record every executable session containing evidence for this
        // finding. Composite findings may legitimately span more than one
        // process instance or exec generation.
        //
        for (const auto& session : sessions) {
            for (const auto& ref : session.finding_refs) {
                if (ref.finding_index != finding_index) {
                    continue;
                }
                story.session_ids.push_back(session.id);
                break;
            }
        }

        //
        // Preserve the semantic evidence ordering stored by the Finding.
        //
        // For example, the sensitive-object finding currently records:
        //
        //     read -> memory -> send
        //
        // The numeric Observation::seq values are collector-observed order and
        // may therefore not be monotonically increasing in this vector.
        //
        for (uint64_t seq : finding.evidence_observation_seqs) {
            const auto it = observations_by_seq.find(seq);
            if (it == observations_by_seq.end()) {
                continue;
            }

            const Observation& obs = *it->second;

            //
            // The correlated finding is built around one fingerprinted value.
            // Do not attach an observation merely because its sequence number
            // was referenced if it does not carry the same fingerprint.
            //
            if (obs.fingerprint != details->fingerprint) {
                continue;
            }

            NarrativeStatement statement;
            statement.evidence_observation_seqs.push_back(seq);

            //
            // Input-side observation.
            //
            // This states only that the fingerprinted value was present in
            // data returned by the syscall. Source attribution such as the
            // backing file will be added separately from FD lineage evidence.
            //
            if (obs.type == ObservationType::Event &&
                (obs.syscall_name == "read" ||
                 obs.syscall_name == "recvfrom")) {
                statement.text =
                    "A " +
                    details->secret_type +
                    " value was observed in data returned by " +
                    obs.syscall_name +
                    "().";
            }

            //
            // Independent scanner observation.
            //
            // data_type == "memory" specifically identifies an observation
            // produced by the process-memory scanner rather than a derived
            // read/write Data node.
            //
            else if (obs.type == ObservationType::Data &&
                obs.data_type == "memory") {
                statement.text =
                    "The same fingerprinted value was also found "
                    "in process memory.";
            }

            //
            // Output-side observation.
            //
            // Matching fingerprints establish that the same value was present
            // in the syscall data. They do not by themselves prove malicious
            // exfiltration or a causal path from the earlier observation.
            //
            else if (obs.type == ObservationType::Event &&
                (obs.syscall_name == "sendto" ||
                 obs.syscall_name == "write" ||
                 obs.syscall_name == "writev")) {
                statement.text =
                    "The same fingerprinted value was observed in "
                    "data supplied to " +
                    obs.syscall_name +
                    "().";
            }

            //
            // Unknown evidence types are deliberately skipped rather than
            // converted into speculative narrative statements.
            //
            else {
                continue;
            }

            story.statements.push_back(std::move(statement));
        }

        //
        // Do not emit empty stories. A finding may be structurally valid but
        // contain evidence types that NarrativeBuilder does not yet know how
        // to explain.
        //
        if (!story.statements.empty()) {
            stories.push_back(std::move(story));
        }
    }

    return stories;
}

} // namespace runtimexray