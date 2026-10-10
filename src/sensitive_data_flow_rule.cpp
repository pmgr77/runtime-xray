/**
 * @file    sensitive_data_flow_rule.cpp
 * @brief   Composite detection rule for observed sensitive-data flow.
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

#include "sensitive_data_flow_rule.hpp"

#include <algorithm>
#include <cstddef>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace runtimexray {

namespace {

struct FdResource {
    std::string path;
    std::string endpoint;
};

bool same_session(const Observation& a, const Observation& b)
{
    return
        a.process_instance_id != 0 &&
        a.process_instance_id == b.process_instance_id &&
        a.exec_generation == b.exec_generation;
}

FdResource resolve_fd_at(
    const LineageGraph& graph,
    const Observation& event,
    int fd,
    size_t at_index)
{
    FdResource result;

    for (size_t i = 0; i < at_index && i < graph.observations.size(); ++i) {

        const auto& observation = graph.observations[i];

        if (observation.type != ObservationType::Event) {
            continue;
        }

        if (!same_session(observation, event)) {
            continue;
        }

        if (observation.syscall_name == "open" ||
            observation.syscall_name == "openat") {

            if (observation.return_value == fd && !observation.source.empty()) {
                result.path = observation.source;
                result.endpoint.clear();
            }

            continue;
        }

        if (observation.syscall_name == "connect") {

            if (observation.return_value == 0 &&
                static_cast<int>(observation.arg0) == fd &&
                !observation.source.empty()) {

                result.endpoint = observation.source;
                result.path.clear();
            }

            continue;
        }

        if (observation.syscall_name == "close") {

            if (observation.return_value == 0 &&
                static_cast<int>(observation.arg0) == fd) {

                result.path.clear();
                result.endpoint.clear();
            }
        }
    }

    return result;
}

bool is_read_event(const Observation& observation)
{
    return
        observation.type == ObservationType::Event &&
        (
            observation.syscall_name == "read" ||
            observation.syscall_name == "recvfrom"
        );
}

bool is_output_event(const Observation& observation)
{
    return
        observation.type == ObservationType::Event &&
        (
            observation.syscall_name == "write" ||
            observation.syscall_name == "writev" ||
            observation.syscall_name == "sendto"
        );
}

bool is_memory_observation(const Observation& observation)
{
    return
        observation.type == ObservationType::Data &&
        observation.data_type == "memory";
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

void append_supporting_findings(
    const FindingList& primary_findings,
    const std::string& fingerprint,
    Finding& result)
{
    for (const auto& finding : primary_findings) {

        if (finding.kind != "sensitive_data_presence") {
            continue;
        }

        const std::string* candidate = find_string_attribute(finding, "fingerprint");

        if (!candidate || *candidate != fingerprint) {
            continue;
        }

        if (finding.finding_id == 0) {
            continue;
        }

        result.supporting_finding_ids.push_back(finding.finding_id);
    }
}

} // anonymous namespace

std::string SensitiveDataFlowRule::id() const
{
    return "builtin.sensitive_data_flow";
}

std::string SensitiveDataFlowRule::description() const
{
    return
        "Detects an exact sensitive value observed in a file read, "
        "process memory, and socket-bound output";
}

DetectionStage SensitiveDataFlowRule::stage() const
{
    return DetectionStage::Composite;
}

FindingList SensitiveDataFlowRule::detect(
    const DetectionContext& context) const
{
    FindingList findings;

    //
    // Fingerprint equality proves value identity.
    //
    // It does NOT by itself prove causality, so this rule additionally
    // requires:
    //
    //   - a read/recvfrom event carrying the value,
    //   - a scanner-derived memory observation carrying the value,
    //   - a write/writev/sendto event carrying the value,
    //   - all three in one executable session,
    //   - the input FD to resolve to a file,
    //   - the output FD to resolve to a connected socket.
    //
    std::map<std::string, std::vector<size_t>> observations_by_fingerprint;

    for (size_t i = 0; i < context.graph.observations.size(); ++i) {

        const auto& observation = context.graph.observations[i];

        if (observation.fingerprint.empty()) {
            continue;
        }

        observations_by_fingerprint[observation.fingerprint].push_back(i);
    }

    for (const auto& entry : observations_by_fingerprint) {

        const std::string& fingerprint = entry.first;

        const auto& indices = entry.second;

        bool emitted = false;

        for (size_t read_index : indices) {

            const auto& read_observation = context.graph.observations[read_index];

            if (!is_read_event(read_observation)) {
                continue;
            }

            const int read_fd = static_cast<int>(read_observation.arg0);

            const FdResource read_resource =
                resolve_fd_at(
                    context.graph,
                    read_observation,
                    read_fd,
                    read_index);

            if (read_resource.path.empty()) {
                continue;
            }

            for (size_t memory_index : indices) {

                const auto& memory_observation = context.graph.observations[memory_index];

                if (!is_memory_observation(memory_observation)) {
                    continue;
                }

                if (!same_session(read_observation, memory_observation)) {
                    continue;
                }

                for (size_t output_index : indices) {

                    const auto& output_observation = context.graph.observations[output_index];

                    if (!is_output_event(output_observation)) {
                        continue;
                    }

                    if (!same_session(read_observation, output_observation)) {
                        continue;
                    }

                    //
                    // The output event must happen after the input event.
                    //
                    // Memory observations may be appended to the graph after
                    // tracing, so their seq is intentionally not used as a
                    // temporal constraint here.
                    //
                    if (output_observation.seq <= read_observation.seq) {
                        continue;
                    }

                    const int output_fd = static_cast<int>(output_observation.arg0);

                    const FdResource output_resource =
                        resolve_fd_at(
                            context.graph,
                            output_observation,
                            output_fd,
                            output_index);

                    if (output_resource.endpoint.empty()) {
                        continue;
                    }

                    Finding finding;

                    finding.kind = "sensitive_data_flow";

                    finding.severity = FindingSeverity::High;

                    finding.title = "Sensitive object observed from file to socket";

                    finding.summary =
                        "RuntimeXRay observed the same sensitive value "
                        "in a file read, process memory, and socket-bound "
                        "output within one executable session.";

                    finding.attributes["fingerprint"] = fingerprint;

                    finding.attributes["secret_type"] =
                        memory_observation.secret_type.empty()
                            ? std::string("unknown")
                            : memory_observation.secret_type;

                    finding.attributes["source_file"] = read_resource.path;

                    finding.attributes["socket_destination"] = output_resource.endpoint;

                    finding.attributes["confidence"] = std::string("exact-fingerprint-match");

                    finding.attributes["read_syscall"] = read_observation.syscall_name;

                    finding.attributes["send_syscall"] = output_observation.syscall_name;

                    finding.evidence_observation_seqs = {
                        read_observation.seq,
                        memory_observation.seq,
                        output_observation.seq
                    };

                    //
                    // Do not invent DataFlow edges here.
                    //
                    // The graph currently proves exact-value participation
                    // in these observations plus endpoint/resource context;
                    // evidence_edges is reserved for actual graph edges.
                    //
                    append_supporting_findings(
                        context.previous_stage_findings,
                        fingerprint,
                        finding);

                    findings.push_back(std::move(finding));

                    emitted = true;
                    break;
                }

                if (emitted) {
                    break;
                }
            }

            if (emitted) {
                break;
            }
        }
    }

    return findings;
}

} // namespace runtimexray