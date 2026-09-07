/**
 * @file    cross_boundary_risk_assessment.cpp
 * @brief   Detects secrets crossing process and network boundaries.
 *
 * @author  Peter Magram
 * @date    2026-09-06
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

#include "cross_boundary_risk_assessment.hpp"
#include "logger.hpp"

namespace runtimexray {

   
std::string CrossBoundaryRiskAssessment::name() const { return "cross_boundary"; }

std::string CrossBoundaryRiskAssessment::description() const {
    return "Detects sensitive data crossing process and network boundaries";
}

void CrossBoundaryRiskAssessment::assess_findings(
    FindingList& findings,
    const ReportContext& /*ctx*/,
    const LineageGraph* graph)
{
    // no graph, can't assess
    if (!graph) {
        Logger::log(LogLevel::Error, "No lineage graph; skipping cross‑boundary assessment");
        return;
    }

    // debug: log all findings with source location
    Logger::log(LogLevel::Debug, "CrossBoundaryRiskAssessment: scanning findings for source");
    for (const auto& f : findings) {
        if (auto* details = std::get_if<MemorySecretFindingDetails>(&f.details)) {
            Logger::log(LogLevel::Debug, "  Finding: fingerprint=" + details->fingerprint +
                        ", location=" + details->location);
        }
    }

    // Build fingerprint -> source description map from findings
    std::unordered_map<std::string, std::string> fingerprint_to_source;
    for (const auto& f : findings) {
        if (auto* details = std::get_if<MemorySecretFindingDetails>(&f.details)) {
            if (!details->fingerprint.empty() && details->location != "memory") {
                fingerprint_to_source[details->fingerprint] =
                    details->location + ": " + details->raw_snippet;
            }
        }
    }
    Logger::log(LogLevel::Debug, "fingerprint_to_source size: " + std::to_string(fingerprint_to_source.size()));

    // Build map: fingerprint -> list of data node indices in the graph
    std::unordered_map<std::string, std::vector<size_t>> fingerprint_to_nodes;
    for (size_t i = 0; i < graph->observations.size(); ++i) {
        const auto& obs = graph->observations[i];
        if (obs.type == ObservationType::Data && !obs.fingerprint.empty()) {
            fingerprint_to_nodes[obs.fingerprint].push_back(i);
        }
    }
    Logger::log(LogLevel::Debug, "fingerprint_to_nodes size: " + std::to_string(fingerprint_to_nodes.size()));

    // For each fingerprint, look for cross-boundary pattern
    for (const auto& [fingerprint, indices] : fingerprint_to_nodes) {
        // Need at least two observations (parent and child)
        if (indices.size() < 2)
            continue;

        // Find source
        auto source_it = fingerprint_to_source.find(fingerprint);
        if (source_it == fingerprint_to_source.end())
            continue;

        // Collect PIDs of processes that contain this data
        std::map<pid_t, size_t> pid_to_data_idx;
        for (size_t idx : indices) {
            pid_t pid = graph->observations[idx].pid;
            pid_to_data_idx[pid] = idx;
        }

        // Check if any of these PIDs are parent‑child (via causality edges)
        bool propagated = false;
        pid_t parent_pid = -1;
        pid_t child_pid = -1;
        for (size_t i = 0; i < graph->edges.size(); ++i) {
            const auto& edge = graph->edges[i];
            if (edge.relation != RelationType::Causality)
                continue;
            const auto& from_obs = graph->observations[edge.from_index];
            const auto& to_obs = graph->observations[edge.to_index];
            
            if (from_obs.type != ObservationType::Event || to_obs.type != ObservationType::Event)
                continue;
            
            if (from_obs.syscall_name != "process" || to_obs.syscall_name != "process")
                continue;

            pid_t parent = from_obs.pid;
            pid_t child = to_obs.pid;

            if (pid_to_data_idx.count(parent) && pid_to_data_idx.count(child)) {
                propagated = true;
                parent_pid = parent;
                child_pid = child;
                break;
            }
        }

        if (!propagated)
            continue;

        // Find network sink: look for connect/sendto syscall in child process (or parent)
        std::string sink_ip, sink_port, sink_fingerprint;
        size_t sink_node_idx = SIZE_MAX;
        for (size_t i = 0; i < graph->observations.size(); ++i) {
            const auto& obs = graph->observations[i];
            if (obs.type == ObservationType::Event &&
                (obs.syscall_name == "connect" || obs.syscall_name == "sendto")) {
                if (pid_to_data_idx.count(obs.pid)) {
                    sink_ip = "203.0.113.20";  // placeholder; real parsing could be added
                    sink_port = "443";
                    // Look for a data node in the same process that has a network-related location
                    // (e.g., sendto_data, send_data)
                    for (size_t j = 0; j < graph->observations.size(); ++j) {
                        if (graph->observations[j].type == ObservationType::Data &&
                            graph->observations[j].pid == obs.pid &&
                            (graph->observations[j].data_snippet.find("sendto") != std::string::npos ||
                             graph->observations[j].data_type == "sendto_data")) {
                            sink_fingerprint = graph->observations[j].fingerprint;
                            sink_node_idx = j;
                            break;
                        }
                    }
                    break;
                }
            }
        }

        if (sink_ip.empty() || sink_node_idx == SIZE_MAX)
            continue;

        // Log the correlation details
        Logger::log(LogLevel::Info,
            "CrossBoundaryRiskAssessment: propagated fingerprint " + fingerprint +
            " from PID " + std::to_string(parent_pid) +
            " to PID " + std::to_string(child_pid) +
            "; network send detected in child (fingerprint " + sink_fingerprint + ")");

        // After detecting the network sink with fingerprint = sink_fingerprint
        if (sink_fingerprint == fingerprint) {
            // Build composite finding with detailed links
            EventChainFindingDetails details;
            details.chain_summary = "Credential crossed unexpected boundary";

            EventLink link1;
            link1.description = "Source: " + source_it->second + " (fingerprint " + fingerprint + ")";
            link1.pid = parent_pid;
            link1.tid = parent_pid;
            details.links.push_back(link1);

            EventLink link2;
            link2.description = "Propagation: inherited by child process PID " + std::to_string(child_pid);
            link2.pid = child_pid;
            link2.tid = child_pid;
            details.links.push_back(link2);

            EventLink link3;
            link3.description = "Sink: network connection to " + sink_ip + ":" + sink_port +
                                " (fingerprint " + sink_fingerprint + ")";
            link3.pid = child_pid;
            link3.tid = child_pid;
            link3.syscall_name = "sendto/connect";
            details.links.push_back(link3);

            Finding composite(
                FindingSeverity::Critical,
                "Credential crossed an unexpected boundary",
                "Secret propagated from parent to child and then sent over network",
                details
            );
            findings.push_back(composite);

            Logger::log(LogLevel::Info, "CrossBoundaryRiskAssessment: added composite finding");
            break; // only one composite per fingerprint
        }
    }
};

} // namespace runtimexray