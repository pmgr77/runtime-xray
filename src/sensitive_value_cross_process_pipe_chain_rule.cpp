/**
 * @file    sensitive_value_cross_process_pipe_chain_rule.cpp
 * @brief   Detects sensitive values observed across multi-process pipe chains.
 *
 * @author  Peter Magram
 * @date    2026-10-12
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

#include "sensitive_value_cross_process_pipe_chain_rule.hpp"

#include <algorithm>
#include <chrono>
#include <functional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace runtimexray {
namespace {

struct SessionKey {
    uint64_t process_instance_id = 0;
    uint64_t exec_generation = 0;

    bool operator==(const SessionKey& other) const
    {
        return process_instance_id == other.process_instance_id &&
               exec_generation == other.exec_generation;
    }
};

struct PipeBoundary {
    const Observation* from = nullptr;
    const Observation* to = nullptr;

    uint64_t resource_id = 0;
    std::string fingerprint;
};

SessionKey session_of(const Observation& observation)
{
    return {
        observation.process_instance_id,
        observation.exec_generation
    };
}

bool has_timestamp(
    const std::chrono::steady_clock::time_point& value)
{
    return value != std::chrono::steady_clock::time_point{};
}

bool is_cross_process_pipe_dataflow(
    const LineageGraph& graph,
    const LineageEdge& edge,
    PipeBoundary& boundary)
{
    if (edge.relation != RelationType::DataFlow) {
        return false;
    }

    if (edge.from_index >= graph.observations.size() ||
        edge.to_index >= graph.observations.size()) {
        return false;
    }

    const Observation& from = graph.observations[edge.from_index];
    const Observation& to = graph.observations[edge.to_index];

    if (from.type != ObservationType::Event ||
        to.type != ObservationType::Event) {
        return false;
    }

    if (from.fingerprint.empty() ||
        to.fingerprint.empty() ||
        from.fingerprint != to.fingerprint) {
        return false;
    }

    if (from.resource_id == 0 ||
        to.resource_id == 0 ||
        from.resource_id != to.resource_id) {
        return false;
    }

    if (from.resource_type != "pipe" ||
        to.resource_type != "pipe") {
        return false;
    }

    if (from.resource_role != "write" ||
        to.resource_role != "read") {
        return false;
    }

    if (from.process_instance_id == 0 ||
        to.process_instance_id == 0) {
        return false;
    }

    /*
     * This rule specifically models cross-process pipe boundaries.
     *
     * Different exec generations of the same process instance are not
     * considered a cross-process transfer.
     */
    if (from.process_instance_id == to.process_instance_id) {
        return false;
    }

    boundary.from = &from;
    boundary.to = &to;
    boundary.resource_id = from.resource_id;
    boundary.fingerprint = from.fingerprint;

    return true;
}

bool boundaries_connect(
    const PipeBoundary& incoming,
    const PipeBoundary& outgoing)
{
    if (!incoming.to || !outgoing.from) {
        return false;
    }

    /*
     * Both explicit DataFlow edges must meet in exactly the same execution
     * session. process_instance_id alone is insufficient because exec changes
     * the executable image and therefore the execution context.
     */
    if (!(session_of(*incoming.to) == session_of(*outgoing.from))) {
        return false;
    }

    /*
     * Fingerprint equality proves exact value identity.
     * It does not, by itself, prove causality.
     */
    if (incoming.fingerprint != outgoing.fingerprint) {
        return false;
    }

    /*
     * For a blocking read(), start_time may be earlier than the producer's
     * write(). The value becomes available to the reader when read completes.
     *
     * Therefore the relevant ordering for connecting two boundaries is:
     *
     *   incoming read completion <= outgoing write start
     *
     * and not the generic LineageEdge::time_delta.
     */
    if (!has_timestamp(incoming.to->end_time) ||
        !has_timestamp(outgoing.from->start_time)) {
        return false;
    }

    return incoming.to->end_time <= outgoing.from->start_time;
}

std::string session_to_string(const SessionKey& session)
{
    return std::to_string(session.process_instance_id) +
           ":" +
           std::to_string(session.exec_generation);
}

const std::string* find_string_attribute(
    const Finding& finding,
    const std::string& name)
{
    const auto it = finding.attributes.find(name);
    if (it == finding.attributes.end()) {
        return nullptr;
    }

    return std::get_if<std::string>(&it->second);
}

const Observation* find_observation_by_seq(
    const LineageGraph& graph,
    uint64_t seq)
{
    const auto it = std::find_if(
        graph.observations.begin(),
        graph.observations.end(),
        [seq](const Observation& observation) {
            return observation.seq == seq;
        });

    if (it == graph.observations.end()) {
        return nullptr;
    }

    return &(*it);
}

bool session_in_chain(
    const SessionKey& session,
    const std::vector<SessionKey>& sessions)
{
    return std::find(
               sessions.begin(),
               sessions.end(),
               session) != sessions.end();
}

void append_unique_seq(
    std::vector<uint64_t>& seqs,
    uint64_t seq)
{
    if (seq == 0) {
        return;
    }

    if (std::find(seqs.begin(), seqs.end(), seq) == seqs.end()) {
        seqs.push_back(seq);
    }
}

Finding build_finding(
    const DetectionContext& context,
    const std::vector<PipeBoundary>& boundaries,
    const std::vector<std::size_t>& path)
{
    Finding finding;

    finding.kind =
        "sensitive_value_cross_process_pipe_chain";

    finding.severity = FindingSeverity::High;

    finding.title =
        "Sensitive value observed across a cross-process pipe chain";

    /*
     * Build the ordered execution-session path:
     *
     *   edge0.from -> edge0.to == edge1.from -> edge1.to ...
     */
    std::vector<SessionKey> sessions;

    const PipeBoundary& first = boundaries[path.front()];
    sessions.push_back(session_of(*first.from));

    for (const std::size_t boundary_index : path) {
        sessions.push_back(
            session_of(*boundaries[boundary_index].to));
    }

    std::ostringstream summary;
    summary
        << "The same sensitive value was observed across "
        << path.size()
        << " temporally connected cross-process pipe transfers spanning "
        << sessions.size()
        << " execution sessions.";

    finding.summary = summary.str();

    const std::string& fingerprint =
        boundaries[path.front()].fingerprint;

    std::vector<uint64_t> resource_ids;
    std::vector<uint64_t> process_instance_ids;
    std::vector<std::string> session_strings;

    process_instance_ids.reserve(sessions.size());
    session_strings.reserve(sessions.size());
    resource_ids.reserve(path.size());

    for (const SessionKey& session : sessions) {
        process_instance_ids.push_back(
            session.process_instance_id);

        session_strings.push_back(
            session_to_string(session));
    }

    for (const std::size_t boundary_index : path) {
        const PipeBoundary& boundary = boundaries[boundary_index];

        resource_ids.push_back(boundary.resource_id);

        append_unique_seq(finding.evidence_observation_seqs, boundary.from->seq);

        append_unique_seq(finding.evidence_observation_seqs, boundary.to->seq);

        FindingEdgeEvidence edge_evidence;
        edge_evidence.from_seq = boundary.from->seq;
        edge_evidence.to_seq = boundary.to->seq;
        edge_evidence.relation = RelationType::DataFlow;

        finding.evidence_edges.push_back(std::move(edge_evidence));
    }

    finding.attributes["fingerprint"] = fingerprint;

    finding.attributes["boundary_count"] = static_cast<uint64_t>(path.size());

    finding.attributes["session_count"] = static_cast<uint64_t>(sessions.size());

    finding.attributes["resource_ids"] = std::move(resource_ids);

    finding.attributes["process_instance_ids"] = std::move(process_instance_ids);

    finding.attributes["sessions"] = std::move(session_strings);

    finding.attributes["confidence"] = std::string("explicit-pipe-dataflow-chain");

    /*
     * Primary sensitive-data findings are supporting context, not the proof
     * of the pipe chain. The proof is stored above as explicit DataFlow edge
     * evidence.
     *
     * Scope supporting findings to both:
     *   - the same exact fingerprint
     *   - a session participating in this specific chain
     *
     * This prevents a disconnected occurrence of the same value from being
     * attached merely because its HMAC fingerprint is equal.
     */
    std::set<std::string> secret_types;

    for (const Finding& previous : context.previous_stage_findings) {

        if (previous.kind != "sensitive_data_presence") {
            continue;
        }

        const std::string* previous_fingerprint = find_string_attribute(previous, "fingerprint");

        if (!previous_fingerprint || *previous_fingerprint != fingerprint) {
            continue;
        }

        bool belongs_to_chain = false;

        for (const uint64_t seq : previous.evidence_observation_seqs) {

            const Observation* observation = find_observation_by_seq(context.graph, seq);

            if (!observation) {
                continue;
            }

            if (session_in_chain(session_of(*observation), sessions)) {
                belongs_to_chain = true;
                break;
            }
        }

        if (!belongs_to_chain) {
            continue;
        }

        if (previous.finding_id != 0) {
            finding.supporting_finding_ids.push_back(previous.finding_id);
        }

        const std::string* secret_type =
            find_string_attribute(previous, "secret_type");

        if (secret_type && !secret_type->empty()) {
            secret_types.insert(*secret_type);
        }
    }

    if (!secret_types.empty()) {
        finding.attributes["secret_types"] = std::vector<std::string>(secret_types.begin(), secret_types.end());
    }

    return finding;
}

} // namespace

std::string
SensitiveValueCrossProcessPipeChainRule::id() const
{
    return "builtin.sensitive_value_cross_process_pipe_chain";
}

std::string
SensitiveValueCrossProcessPipeChainRule::description() const
{
    return
        "Detects the same sensitive value across two or more "
        "temporally connected explicit cross-process pipe "
        "DataFlow boundaries";
}

DetectionStage
SensitiveValueCrossProcessPipeChainRule::stage() const
{
    return DetectionStage::Composite;
}

FindingList
SensitiveValueCrossProcessPipeChainRule::detect(
    const DetectionContext& context) const
{
    FindingList findings;

    /*
     * First retain only explicit cross-process pipe DataFlow edges.
     */
    std::vector<PipeBoundary> boundaries;

    for (const LineageEdge& edge : context.graph.edges) {
        PipeBoundary boundary;
        if (is_cross_process_pipe_dataflow(context.graph, edge, boundary)) {
            boundaries.push_back(std::move(boundary));
        }
    }

    if (boundaries.size() < 2) {
        return findings;
    }

    /*
     * A chain may only connect boundaries carrying the same exact value.
     * Grouping by fingerprint keeps unrelated values completely separate.
     */
    std::unordered_map<std::string, std::vector<std::size_t>> by_fingerprint;

    for (std::size_t i = 0; i < boundaries.size(); ++i) {
        by_fingerprint[boundaries[i].fingerprint].push_back(i);
    }

    for (const auto& group_entry : by_fingerprint) {
        const std::vector<std::size_t>& group =
            group_entry.second;

        if (group.size() < 2) {
            continue;
        }

        /*
         * Build a directed graph whose nodes are explicit DataFlow
         * boundaries.
         *
         * E1 -> E2 means:
         *
         *   E1 ends in session S
         *   E2 begins in session S
         *
         * and E1's read completed before E2's write started.
         */
        std::vector<std::vector<std::size_t>> next(group.size());

        std::vector<std::size_t> indegree(group.size(), 0);

        for (std::size_t i = 0; i < group.size(); ++i) {

            for (std::size_t j = 0; j < group.size(); ++j) {

                if (i == j) {
                    continue;
                }

                if (!boundaries_connect(boundaries[group[i]], boundaries[group[j]])) {
                    continue;
                }

                next[i].push_back(j);
                ++indegree[j];
            }
        }

        /*
         * Emit one Finding for each maximal directed path containing at
         * least two explicit cross-process pipe boundaries.
         *
         * Isolated single-boundary transfers intentionally remain only in
         * LineageGraph.
         */
        for (std::size_t start = 0; start < group.size(); ++start) {

            if (indegree[start] != 0) {
                continue;
            }

            std::vector<std::size_t> path;
            std::vector<bool> on_path(group.size(), false);

            std::function<void(std::size_t)> walk;

            walk = [&](std::size_t node) {
                if (on_path[node]) {
                    return;
                }

                on_path[node] = true;
                path.push_back(group[node]);

                if (next[node].empty()) {
                    if (path.size() >= 2) {
                        findings.push_back(build_finding(context, boundaries, path));
                    }
                } else {
                    for (const std::size_t child : next[node]) {
                        walk(child);
                    }
                }

                path.pop_back();
                on_path[node] = false;
            };

            walk(start);
        }
    }

    return findings;
}

} // namespace runtimexray