/**
 * @file    reporter.cpp
 * @brief   Implementation of reporting utilities.
 *
 * @author  Peter Magram
 * @date    2026-08-23
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

#include "reporter.hpp"
#include "finding_reporter.hpp"
#include <nlohmann/json.hpp>

#include <iostream>
#include <sstream>
#include <map>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <type_traits>

namespace runtimexray {

    static const char* relation_to_string(RelationType rel) {
        switch (rel) {
            case RelationType::Chronological:       return "chronological";
            case RelationType::Causality:           return "causality";
            case RelationType::DataFlow:            return "dataflow";
            case RelationType::Calls:               return "calls";
            case RelationType::ObservedIn:          return "observed_in";
            case RelationType::StaticAssociated:    return "static_associated";
            case RelationType::ObservedAt:          return "observed_at";
            default: return "unknown";
        }
    }

    std::string current_iso8601_utc() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_utc{};
#ifdef _WIN32
        gmtime_s(&tm_utc, &t);
#else
        gmtime_r(&t, &tm_utc);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    std::string Reporter::severity_to_string(FindingSeverity severity) {
        switch (severity) {
            case FindingSeverity::Critical: return "Critical";
            case FindingSeverity::High: return "High";
            case FindingSeverity::Medium: return "Medium";
            case FindingSeverity::Low: return "Low";
            case FindingSeverity::Info: return "Info";
            default: return "Unknown";
        }
        return "Unknown";
    }

    static std::string finding_attribute_to_text(const FindingAttributeValue& value)
    {
        return std::visit(
            [](const auto& v) -> std::string {
                using T =
                    std::decay_t<decltype(v)>;

                if constexpr (
                    std::is_same_v<T, std::string>) {
                    return v;

                } else if constexpr (
                    std::is_same_v<T, bool>) {
                    return v ? "true" : "false";

                } else if constexpr (
                    std::is_arithmetic_v<T>) {
                    std::ostringstream out;
                    out << v;
                    return out.str();

                } else {
                    std::ostringstream out;
                    out << "[";

                    for (size_t i = 0;
                        i < v.size();
                        ++i) {

                        if (i != 0) {
                            out << ", ";
                        }

                        out << v[i];
                    }

                    out << "]";
                    return out.str();
                }
            },
            value);
    }

    static nlohmann::json finding_attribute_to_json(const FindingAttributeValue& value)
    {
        return std::visit(
            [](const auto& v) -> nlohmann::json {
                return v;
            },
            value);
    }

    static nlohmann::json serialize_narratives(
        const std::vector<NarrativeStory>& narratives)
    {
        nlohmann::json narratives_arr = nlohmann::json::array();

        for (const auto& story : narratives) {
            nlohmann::json story_json;
            story_json["finding_index"] = story.finding_index;
            story_json["title"] = story.title;
            story_json["fingerprint"] = story.fingerprint;
            story_json["sessions"] = nlohmann::json::array();

            for (const auto& session : story.sessions) {
                nlohmann::json session_json;
                session_json["process_instance_id"] = session.id.process_instance_id;
                session_json["exec_generation"] = session.id.exec_generation;
                session_json["program"] = session.program_name;
                story_json["sessions"].push_back(std::move(session_json));
            }

            story_json["statements"] = nlohmann::json::array();
            for (const auto& statement : story.statements) {
                nlohmann::json statement_json;
                statement_json["text"] = statement.text;
                statement_json["evidence_observation_seqs"] = statement.evidence_observation_seqs;
                story_json["statements"].push_back(std::move(statement_json));
            }

            narratives_arr.push_back(std::move(story_json));
        }

        return narratives_arr;
    }

    static const char* observation_type_to_string(ObservationType type) {
        switch (type) {
            case ObservationType::Event: return "event";
            case ObservationType::Data: return "data";
            case ObservationType::Static: return "static";
            default: return "unknown";
        }
    }

    static const char* transformation_type_to_string(TransformationType transformation) {
        switch (transformation) {
            case TransformationType::None:
                return "none";

            case TransformationType::Base64Decoded:
                return "base64_decoded";
        }

        return "unknown";
    }

    static nlohmann::json serialize_observation(const Observation& obs, const ReportingOptions& opts) {
        nlohmann::json j;

        //
        // Stable identity and process/executable context.
        //
        j["seq"] = obs.seq;
        j["type"] = observation_type_to_string(obs.type);

        j["pid"] = obs.pid;
        j["tid"] = obs.tid;
        j["tgid"] = obs.tgid;

        j["process_instance_id"] = obs.process_instance_id;
        j["exec_generation"] = obs.exec_generation;

        if (!obs.program_name.empty()) { j["program"] = obs.program_name; }

        if (obs.duration.count() != 0) { j["duration_us"] = obs.duration.count(); }

        //
        // Event observation.
        //
        if (obs.type == ObservationType::Event) {
            j["syscall"] = obs.syscall_name;
            j["return_value"] = obs.return_value;
            j["is_entry"] = obs.is_entry;
            j["args"] = { obs.arg0, obs.arg1, obs.arg2, obs.arg3, obs.arg4, obs.arg5 };

            if (!obs.source.empty()) { j["source"] = obs.source; }

            if (!obs.fingerprint.empty()) { j["fingerprint"] = obs.fingerprint; }

            if (!obs.secret_type.empty()) { j["secret_type"] = obs.secret_type; }

            if (obs.resource_id != 0) { j["resource_id"] = obs.resource_id; }

            if (!obs.resource_type.empty()) { j["resource_type"] = obs.resource_type; }

            if (!obs.resource_role.empty()) { j["resource_role"] = obs.resource_role; }
        }

        //
        // Data observation.
        //
        else if (obs.type == ObservationType::Data) {
            j["data_type"] = obs.data_type;

            if (!obs.fingerprint.empty()) { j["fingerprint"] = obs.fingerprint; }

            if (!obs.secret_type.empty()) { j["secret_type"] = obs.secret_type; }

            if (obs.source_event_seq != 0) {
                j["source_event_seq"] = obs.source_event_seq;
            }

            if (obs.resource_id != 0) {
                j["resource_id"] = obs.resource_id;
            }

            if (!obs.resource_type.empty()) {
                j["resource_type"] = obs.resource_type;
            }

            if (!obs.resource_role.empty()) {
                j["resource_role"] = obs.resource_role;
            }

            if (obs.transformation != TransformationType::None) {
                j["transformation"] = transformation_type_to_string(obs.transformation);
            }

            if (obs.address != 0) { j["address"] = obs.address; }

            if (obs.size != 0) { j["size"] = obs.size; }

            if (!obs.source.empty()) { j["source"] = obs.source; }

            //
            // Data snippets may contain the sensitive value itself.
            // Never expose them unless --show-secrets is enabled.
            //
            if (!obs.data_snippet.empty()) {
                if (opts.show_secrets) { j["data_snippet"] = obs.data_snippet; } 
                else { j["data_snippet"] = nullptr; }
            }
        }

        //
        // Static-analysis observation.
        //
        else if (obs.type == ObservationType::Static) {
            if (!obs.static_field.empty()) { j["field"] = obs.static_field; }

            if (!obs.static_value.empty()) { j["value"] = obs.static_value; }

            if (!obs.static_category.empty()) { j["category"] = obs.static_category; }

            if (!obs.static_description.empty()) { j["description"] = obs.static_description; }

            if (!obs.static_recommendation.empty()) { j["recommendation"] = obs.static_recommendation; }

            if (!obs.cwe_id.empty()) { j["cwe"] = obs.cwe_id; }
        }

        return j;
    }

    static nlohmann::json serialize_lineage(const LineageGraph& graph, const ReportingOptions& opts) {
        nlohmann::json lineage_json;

        lineage_json["summary"] = graph.summary;

        lineage_json["observations"] = nlohmann::json::array();

        for (const auto& obs : graph.observations) {
            lineage_json["observations"].push_back(serialize_observation(obs, opts));
        }

        lineage_json["edges"] = nlohmann::json::array();

        for (const auto& edge : graph.edges)
        {
            nlohmann::json edge_json;

            //
            // External JSON references use stable Observation::seq,
            // not internal vector positions.
            //
            if (edge.from_index < graph.observations.size()) {
                edge_json["from_seq"] = graph.observations[edge.from_index].seq;
            } else {
                edge_json["from_seq"] = nullptr;
            }

            if (edge.to_index < graph.observations.size()) {
                edge_json["to_seq"] = graph.observations[edge.to_index].seq;
            } else {
                edge_json["to_seq"] = nullptr;
            }

            edge_json["relation"] = relation_to_string(edge.relation);

            edge_json["time_delta_us"] = edge.time_delta.count();

            if (!edge.details.empty()) { edge_json["details"] = edge.details; }

            lineage_json["edges"].push_back(std::move(edge_json));
        }

        return lineage_json;
    }

    std::string Reporter::to_text(const Report& r, const nlohmann::json* extra) {
        std::ostringstream out;

        // ---- Header ----
        out << "RuntimeXRay Analysis\n";
        out << "=====================\n";
        out << "Tool:    " << r.context.tool_name << " v" << r.context.tool_version << "\n";
        out << "Command: " << r.context.command << "\n";
        out << "Target:  " << r.context.target << "\n";
        out << "Started: " << r.context.started_at << "\n";
        out << "Duration: " << r.context.duration_ms << " ms\n";

        // ---- Extra trace metadata (if present) ----
        if (extra) {
            if (extra->contains("backend"))
                out << "Backend: " << (*extra)["backend"].get<std::string>() << "\n";
            if (extra->contains("timeout_seconds"))
                out << "Timeout: " << (*extra)["timeout_seconds"].get<int>() << "s\n";
            if (extra->contains("timed_out"))
                out << "Timed out: " << ((*extra)["timed_out"].get<bool>() ? "yes" : "no") << "\n";
            if (extra->contains("child_output"))
                out << "Child output: " << (*extra)["child_output"].get<std::string>() << "\n";
            if (extra->contains("follow_forks"))
                out << "Follow forks: " << ((*extra)["follow_forks"].get<bool>() ? "yes" : "no") << "\n";
        }

        out << "\n";

        // ---- Findings ----
        if (r.findings.empty()) {
            out << "No findings.\n";
        } else {
            out << "Findings ("
                << r.findings.size()
                << "):\n";

            for (const auto& finding :
                r.findings) {

                out << "  ["
                    << severity_to_string(
                        finding.severity)
                    << "] "
                    << finding.title
                    << "\n";

                if (!finding.summary.empty()) {
                    out << "      "
                        << finding.summary
                        << "\n";
                }

                if (!finding.kind.empty()) {
                    out << "      Kind: "
                        << finding.kind
                        << "\n";
                }

                if (!finding.rule_id.empty()) {
                    out << "      Rule: "
                        << finding.rule_id
                        << "\n";
                }

                for (const auto& [name, value] :
                    finding.attributes) {

                    out << "      "
                        << name
                        << ": "
                        << finding_attribute_to_text(value)
                        << "\n";
                }

                if (!finding.cwe_ids.empty()) {
                    out << "      CWE:";

                    for (const auto& cwe :
                        finding.cwe_ids) {
                        out << " " << cwe;
                    }

                    out << "\n";
                }

                if (!finding.evidence_observation_seqs.empty()) {
                    out << "      Evidence observations:";

                    for (uint64_t seq :
                        finding.evidence_observation_seqs) {
                        out << " seq=" << seq;
                    }

                    out << "\n";
                }

                if (!finding.supporting_finding_ids.empty()) {
                    out << "      Supporting findings:";

                    for (uint64_t id :
                        finding.supporting_finding_ids) {
                        out << " id=" << id;
                    }

                    out << "\n";
                }

                for (const auto& edge :
                    finding.evidence_edges) {

                    out << "      Evidence edge: seq="
                        << edge.from_seq
                        << " -> seq="
                        << edge.to_seq
                        << " ["
                        << relation_to_string(
                            edge.relation)
                        << "]\n";
                }
            }
        }

        // ---- Evidence-backed narratives ----
        if (!r.narratives.empty()) {
            out << "\nNarratives:\n";
            for (const auto& story : r.narratives) {
                out << "  " << story.title << "\n";
                //
                // A narrative may span more than one executable image.
                //
                for (const auto& session : story.sessions) {
                    out << "    Program: ";

                    if (!session.program_name.empty()) {
                        out << session.program_name;
                    } else {
                        out << "<unknown>";
                    }

                    out << " [instance="
                        << session.id.process_instance_id
                        << ", exec="
                        << session.id.exec_generation
                        << "]\n";
                }
            
                for (const auto& statement : story.statements) {
                    out << "    - "
                        << statement.text
                        << "\n";

                    if (!statement.evidence_observation_seqs.empty()) {
                        out << "      Evidence: ";

                        for (size_t i = 0; i < statement.evidence_observation_seqs.size(); ++i) {
                            if (i != 0) {
                                out << ", ";
                            }

                            out << "seq="
                                << statement.evidence_observation_seqs[i];
                        }

                        out << "\n";
                    }
                }
            }
        }

        // ---- Lineage Graph ----
        if (r.lineage_graph.has_value()) {
            const auto& graph = r.lineage_graph.value();
            out << "\nLineage Graph:\n";
            out << "  Summary: " << graph.summary << "\n";
            out << "  Observations (" << graph.observations.size() << "):\n";
            for (size_t i = 0; i < graph.observations.size(); ++i) {
                const auto& obs = graph.observations[i];
                out << "    [" << i << "] "
                    << "seq=" << obs.seq << " ";
                if (obs.type == ObservationType::Event) {
                    out << "Event: " << obs.syscall_name;
                    if (obs.syscall_name == "process") {
                        out << " (PID " << obs.pid
                            << ", instance " << obs.process_instance_id
                            << ")";
                        if (!obs.program_name.empty()) {
                            out << ", Program: " << obs.program_name;
                        }
                    } else {
                        out << " (PID " << obs.pid 
                            << ", TID " << obs.tid 
                            << ", TGID " << obs.tgid
                            << ", instance " << obs.process_instance_id
                            << ", exec " << obs.exec_generation
                            << ")";
                        // Also print program_name if present (e.g., after execve)
                        if (!obs.program_name.empty()) {
                            out << " program: " << obs.program_name;
                        }
                    }
                } else if (obs.type == ObservationType::Data) {
                    out << "Data: "
                        << obs.data_type;

                    if (!obs.secret_type.empty()) {
                        out << " secret_type="
                            << obs.secret_type;
                    }

                    if (obs.transformation != TransformationType::None) {
                        out << " transformation="
                            << transformation_type_to_string(obs.transformation);
                    }

                    if (!obs.fingerprint.empty()) {
                        out << " fingerprint="
                            << obs.fingerprint;
                    }

                    if (!obs.data_snippet.empty()) {
                        out << " data=";

                        if (r.report_opts.show_secrets) {
                            out << obs.data_snippet;
                        } else {
                            out << "<redacted>";
                        }
                    }
                } else if (obs.type == ObservationType::Static) {
                    out << "Static: ";

                    if (!obs.static_category.empty()) {
                        out << obs.static_category;
                    }

                    if (!obs.static_field.empty()) {
                        out << " field="
                            << obs.static_field;
                    }

                    if (!obs.static_value.empty()) {
                        out << " value="
                            << obs.static_value;
                    }
                }
                out << "\n";
            }
            out << "  Edges (" << graph.edges.size() << "):\n";
            for (const auto& edge : graph.edges) {
                out << "    " << edge.from_index << " -> " << edge.to_index
                    << " [" << relation_to_string(edge.relation) << "]";
                if (!edge.details.empty()) out << " (" << edge.details << ")";
                out << "\n";
            }
        }

        return out.str();
    }

    void Reporter::serialize_findings(
        const FindingList& findings,
        nlohmann::json& findings_arr,
        const ReportingOptions&)
    {
        for (const auto& finding :
            findings) {

            nlohmann::json fj;

            fj["finding_id"] =
                finding.finding_id;

            fj["rule_id"] =
                finding.rule_id;

            fj["kind"] =
                finding.kind;

            fj["severity"] =
                severity_to_string(
                    finding.severity);

            fj["title"] =
                finding.title;

            fj["summary"] =
                finding.summary;

            fj["evidence_observation_seqs"] =
                finding.evidence_observation_seqs;

            fj["supporting_finding_ids"] =
                finding.supporting_finding_ids;

            fj["cwe_ids"] =
                finding.cwe_ids;

            fj["attributes"] =
                nlohmann::json::object();

            for (const auto& [name, value] :
                finding.attributes) {

                fj["attributes"][name] =
                    finding_attribute_to_json(value);
            }

            fj["evidence_edges"] =
                nlohmann::json::array();

            for (const auto& edge :
                finding.evidence_edges) {

                nlohmann::json ej;

                ej["from_seq"] =
                    edge.from_seq;

                ej["to_seq"] =
                    edge.to_seq;

                ej["relation"] =
                    relation_to_string(
                        edge.relation);

                fj["evidence_edges"].push_back(
                    std::move(ej));
            }

            findings_arr.push_back(
                std::move(fj));
        }
    }

    std::string Reporter::to_json(const Report& r, const nlohmann::json* extra) {
        nlohmann::json j;

        j["schema_version"] = "2.0";
        j["tool"] = r.context.tool_name;
        j["tool_version"] = r.context.tool_version;
        j["command"] = r.context.command;
        j["target"] = r.context.target;
        j["started_at"] = r.context.started_at;
        j["duration_ms"] = r.context.duration_ms;

        nlohmann::json findings_arr = nlohmann::json::array();
        serialize_findings(r.findings, findings_arr, r.report_opts);
        j["findings"] = std::move(findings_arr);
        j["narratives"] = serialize_narratives(r.narratives);

        // Summary
        std::map<std::string, int> by_severity;
        std::map<std::string, int> by_kind;

        for (const auto& finding : r.findings) {
            ++by_severity[
                severity_to_string(finding.severity)];

            ++by_kind[
                finding.kind.empty()
                    ? "unknown"
                    : finding.kind];
        }

        j["summary"]["total"] =
            r.findings.size();

        for (const auto& [name, count] : by_severity) {
            j["summary"]["by_severity"][name] =
                count;
        }

        for (const auto& [name, count] : by_kind) {
            j["summary"]["by_kind"][name] =
                count;
        }

        if (extra) {
           for (auto& [key, value] : extra->items()) {
                j[key] = value;
            }
        }

        if (r.lineage_graph.has_value()) {
            j["lineage"] = serialize_lineage(r.lineage_graph.value(), r.report_opts);
        }

        return j.dump(4);
    }

} // namespace runtimexray