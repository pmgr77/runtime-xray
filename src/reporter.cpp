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

namespace runtimexray {

    static const char* relation_to_string(RelationType rel) {
        switch (rel) {
            case RelationType::Chronological:       return "chronological";
            case RelationType::Causality:           return "causality";
            case RelationType::DataFlow:            return "dataflow";
            case RelationType::Calls:               return "calls";
            case RelationType::StaticAssociated:    return "static_associated";
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

    // Redact all occurrences of a secret in a snippet
    static std::string redact_secret(const std::string& snippet, const std::string& secret) {
        if (secret.empty()) {
            return snippet;
        }
        std::string result = snippet;
        size_t pos = 0;
        while ((pos = result.find(secret, pos)) != std::string::npos) {
            result.replace(pos, secret.size(), "<redacted>");
            pos+=9; // lenght of "<redacted>"
        }
        return result;
    }

    static void append_secret_fields(
        std::ostream& out,
        const MemorySecretFindingDetails& details,
        const ReportingOptions& opts)
    {
        if (details.raw_secret.empty()) {
            return;
        }

        out << " value: "
            << (opts.show_secrets
                    ? details.raw_secret
                    : "<redacted>");

        if (details.raw_snippet.empty()) {
            return;
        }

        out << " context: "
            << (opts.show_secrets
                    ? details.raw_snippet
                    : redact_secret(details.raw_snippet, details.raw_secret));
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

        // ---- Command-specific formatting ----
        if (!r.findings.empty()) {
            if (r.context.command == "analyze") {
                // --- Hardening checks ---
                out << ">  Hardening checks:\n";
                bool has_hardening = false;
                for (const auto& f : r.findings) {
                    if (std::holds_alternative<HardeningFindingDetails>(f.details)) {
                        const auto& details = std::get<HardeningFindingDetails>(f.details);
                        out << "    " << details.feature << ": " << details.status << "\n";
                        has_hardening = true;
                    }
                }
                if (!has_hardening) {
                    out << "    No findings at this severity level.\n";
                }

                // --- Dangerous API usage ---
                bool has_api = false;
                for (const auto& f : r.findings) {
                    if (std::holds_alternative<DangerousApiFindingDetails>(f.details)) {
                        const auto& details = std::get<DangerousApiFindingDetails>(f.details);
                        if (!has_api) {
                            out << ">  Dangerous API usage:\n";
                            has_api = true;
                        }
                        out << "    Dangerous API: " << details.api
                            << " (reason: " << details.reason
                            << ", recommendation: " << details.recommendation
                            << ", cwe: " << details.cwe_id << ")\n";
                    }
                }
                if (!has_api) {
                    out << "    No dangerous API usage found.\n";
                }
            } else if (r.context.command == "mem") {
                // ---- Memory scanning specific output ----
                if (r.findings.empty()) {
                    out << "No sensitive data found in memory of PID " << r.context.target << ".\n";
                } else {
                    size_t pages_scanned = 0;
                    if (extra && extra->contains("pages_scanned")) {
                        pages_scanned = (*extra)["pages_scanned"].get<size_t>();
                    }
                    out << "Found " << r.findings.size() << " potential secrets (scanned " << pages_scanned << " pages):\n";
                    for (const auto& f : r.findings) {
                        std::visit([&](const auto& details) {
                            using T = std::decay_t<decltype(details)>;
                            if constexpr (std::is_same_v<T, SensitiveDataWriteDetails>) {
                                out << " - " << f.description
                                    << " data=\"" << details.data_snippet << "\"\n";
                            } else if constexpr (std::is_same_v<T, MemorySecretFindingDetails>) {
                                out << " - " << f.description;
                                out << " type=" << details.secret_type;
                                out << " location=" << details.location;
                                if (details.address != 0) {
                                    out << " address: 0x" << std::hex << details.address << std::dec;
                                }
                                out << " length: " << details.secret_length;
                                out << " fingerprint: " << details.fingerprint;

                                append_secret_fields(out, details, r.report_opts);
                            } else {
                                out << " - " << f.description << "\n";
                            }
                        }, f.details);
                    }
                }
            } else { // Generic (trace)
                out << "Findings (" << r.findings.size() << "):\n";
                for (const auto& f : r.findings) {
                    out << "  [" << severity_to_string(f.severity) << "] " << f.description << "\n";
                    std::visit([&](const auto& details) {
                        using T = std::decay_t<decltype(details)>;
                        if constexpr (std::is_same_v<T, HardeningFindingDetails>) {
                            out << "      Feature: " << details.feature << ", Status: " << details.status << "\n";
                        } else if constexpr (std::is_same_v<T, DangerousApiFindingDetails>) {
                            out << "      API: " << details.api
                                << ", CWE: " << details.cwe_id
                                << ", Recommendation: " << details.recommendation << "\n";
                        } else if constexpr (std::is_same_v<T, SensitiveFileAccessDetails>) {
                            out << "      Path: " << details.path
                                << ", Reason: " << details.reason
                                << ", Outcome: " << details.outcome
                                << ", Error: " << details.err << "\n";
                        } else if constexpr (std::is_same_v<T, NetworkConnectionDetails>) {
                            out << "      Remote: " << details.remote_addr << ":" << details.port
                                << ", Reason: " << details.reason << "\n";
                        } else if constexpr (std::is_same_v<T, SensitiveDataWriteDetails>) {
                            out << "      Data: " << details.data_snippet
                                << ", Reason: " << details.reason << "\n";
                        } else if constexpr (std::is_same_v<T, MemorySecretFindingDetails>) {
                            out << "      Type: " << details.secret_type
                                << ", Location: " << details.location
                                << ", Length: " << details.secret_length
                                << ", Fingerprint: " << details.fingerprint;

                            append_secret_fields(out, details, r.report_opts);
                            out << "\n";
                        }
                    }, f.details);
                    if (!f.evidence_observation_seqs.empty()) {
                        out << "      Evidence observations:";
                        for (uint64_t seq : f.evidence_observation_seqs) {
                            out << " seq=" << seq;
                        }
                        out << "\n";
                    }
                }
            }
        } else {
            out << "No findings.\n";
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
                    out << "Data: " << obs.data_type << " = " << obs.data_snippet;
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

    void Reporter::serialize_findings(const FindingList& findings, nlohmann::json& findings_arr, const ReportingOptions& opts) {
        for (const auto& f : findings) {
            nlohmann::json fj;
            fj["severity"] = severity_to_string(f.severity);
            fj["description"] = f.description;
            fj["evidence"] = f.evidence;
            fj["evidence_observation_seqs"] = f.evidence_observation_seqs;

            std::visit([&](const auto& details) {
                using T = std::decay_t<decltype(details)>;
                if constexpr (std::is_same_v<T, HardeningFindingDetails>) {
                    fj["type"] = "hardening";
                    fj["details"]["feature"] = details.feature;
                    fj["details"]["status"] = details.status;
                } else if constexpr (std::is_same_v<T, DangerousApiFindingDetails>) {
                    fj["type"] = "dangerous_api";
                    fj["details"]["api_name"] = details.api;
                    fj["details"]["reason"] = details.reason;
                    fj["details"]["recommendation"] = details.recommendation;
                    fj["cwe"] = details.cwe_id;
                } else if constexpr (std::is_same_v<T, SensitiveFileAccessDetails>) {
                    fj["type"] = "sensitive_file";
                    fj["details"]["path"] = details.path;
                    fj["details"]["reason"] = details.reason;
                    fj["details"]["outcome"] = details.outcome;
                    fj["details"]["err"] = details.err;
                } else if constexpr (std::is_same_v<T, NetworkConnectionDetails>) {
                    fj["type"] = "network";
                    fj["details"]["remote_addr"] = details.remote_addr;
                    fj["details"]["port"] = details.port;
                    fj["details"]["reason"] = details.reason;
                } else if constexpr (std::is_same_v<T, SensitiveDataWriteDetails>) {
                    fj["type"] = "sensitive_data";
                    fj["details"]["data_snippet"] = details.data_snippet;
                    fj["details"]["reason"] = details.reason;
                } else if constexpr (std::is_same_v<T, MemorySecretFindingDetails>) {
                    fj["type"] = "memory_secret";
                    fj["details"]["secret_type"] = details.secret_type;
                    fj["details"]["location"] = details.location;
                    if (details.address != 0) fj["address"] = details.address;
                    fj["length"] = details.secret_length;
                    fj["fingerprint"] = details.fingerprint;
                    if (opts.show_secrets) {
                        fj["value"] = details.raw_secret;
                        fj["snippet"] = details.raw_snippet;
                        fj["secret_exposed"] = true;
                    } else {
                        fj["value"] = nullptr;
                        fj["snippet"] = redact_secret(details.raw_snippet, details.raw_secret);
                        fj["secret_exposed"] = false;
                    }
                }
            }, f.details);

            findings_arr.push_back(fj);
        }
    }

    std::string Reporter::to_json(const Report& r, const nlohmann::json* extra) {
        nlohmann::json j;

        j["schema_version"] = "1.3";
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
        std::map<std::string, int> by_type;
        for (const auto& f : r.findings) {
            by_severity[severity_to_string(f.severity)]++;
            std::visit([&](const auto& details) {
                using T = std::decay_t<decltype(details)>;
                if constexpr (std::is_same_v<T, HardeningFindingDetails>) by_type["hardening"]++;
                else if constexpr (std::is_same_v<T, DangerousApiFindingDetails>) by_type["dangerous_api"]++;
                else if constexpr (std::is_same_v<T, SensitiveFileAccessDetails>) by_type["sensitive_file"]++;
                else if constexpr (std::is_same_v<T, NetworkConnectionDetails>) by_type["network"]++;
                else if constexpr (std::is_same_v<T, SensitiveDataWriteDetails>) by_type["sensitive_data"]++;
                else if constexpr (std::is_same_v<T, MemorySecretFindingDetails>) by_type["memory_secret"]++;
            }, f.details);
        }

        j["summary"]["total"] = r.findings.size();
        for (const auto& [k, v] : by_severity) j["summary"]["by_severity"][k] = v;
        for (const auto& [k, v] : by_type) j["summary"]["by_type"][k] = v;

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