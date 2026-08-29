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

#include <nlohmann/json.hpp>

#include <iostream>
#include <sstream>
#include <map>
#include <chrono>
#include <iomanip>
#include <ctime>

namespace runtimexray {

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

    std::string Reporter::to_text(const FindingList& findings,
                                const ReportContext& context,
                                const nlohmann::json* extra) {
        std::ostringstream out;

        // ---- Header ----
        out << "RuntimeXRay Analysis\n";
        out << "=====================\n";
        out << "Tool:    " << context.tool_name << " v" << context.tool_version << "\n";
        out << "Command: " << context.command << "\n";
        out << "Target:  " << context.target << "\n";
        out << "Started: " << context.started_at << "\n";
        out << "Duration: " << context.duration_ms << " ms\n";

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

        if (findings.empty()) {
            out << "No findings.\n";
            return out.str();
        }

        // ---- Command-specific formatting ----
        if (context.command == "analyze") {
            // --- Hardening checks ---
            out << ">  Hardening checks:\n";
            bool has_hardening = false;
            for (const auto& f : findings) {
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
            for (const auto& f : findings) {
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
        } else if (context.command == "mem") {
            // ---- Memory scanning specific output ----
            if (findings.empty()) {
                out << "No sensitive data found in memory of PID " << context.target << ".\n";
            } else {
                size_t pages_scanned = 0;
                if (extra && extra->contains("pages_scanned")) {
                    pages_scanned = (*extra)["pages_scanned"].get<size_t>();
                }
                out << "Found " << findings.size() << " potential secrets (scanned " << pages_scanned << " pages):\n";
                for (const auto& f : findings) {
                    std::visit([&](const auto& details) {
                        using T = std::decay_t<decltype(details)>;
                        if constexpr (std::is_same_v<T, SensitiveDataWriteDetails>) {
                            out << " - " << f.description
                                << " data=\"" << details.data_snippet << "\"\n";
                        } else if constexpr (std::is_same_v<T, MemorySecretFindingDetails>) {
                            out << " - " << f.description
                                << " type=" << details.secret_type
                                << " location=" << details.location
                                << " data=\"" << details.snippet << "\"\n";
                        } else {
                            out << " - " << f.description << "\n";
                        }
                    }, f.details);
                }
            }
        } else {
            out << "Findings (" << findings.size() << "):\n";
            for (const auto& f : findings) {
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
                            << ", Reason: " << details.reason << "\n";
                    } else if constexpr (std::is_same_v<T, NetworkConnectionDetails>) {
                        out << "      Remote: " << details.remote_addr << ":" << details.port
                            << ", Reason: " << details.reason << "\n";
                    } else if constexpr (std::is_same_v<T, SensitiveDataWriteDetails>) {
                        out << "      Data: " << details.data_snippet
                            << ", Reason: " << details.reason << "\n";
                    } else if constexpr (std::is_same_v<T, MemorySecretFindingDetails>) {
                        out << "      Type: " << details.secret_type
                            << ", Location: " << details.location
                            << ", Snippet: " << details.snippet << "\n";
                    }
                }, f.details);
            }
        }

        return out.str();
    }

    void Reporter::serialize_findings(const FindingList& findings, nlohmann::json& findings_arr) {
        for (const auto& f : findings) {
            nlohmann::json fj;
            fj["severity"] = severity_to_string(f.severity);
            fj["description"] = f.description;
            fj["evidence"] = f.evidence;

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
                    fj["details"]["snippet"] = details.snippet;
                }
            }, f.details);

            findings_arr.push_back(fj);
        }
    }

    std::string Reporter::to_json(const FindingList& findings, const ReportContext& context,
                                  const nlohmann::json* extra) {
        nlohmann::json j;

        j["schema_version"] = "1.1";
        j["tool"] = context.tool_name;
        j["tool_version"] = context.tool_version;
        j["command"] = context.command;
        j["target"] = context.target;
        j["started_at"] = context.started_at;
        j["duration_ms"] = context.duration_ms;

        nlohmann::json findings_arr = nlohmann::json::array();
        serialize_findings(findings, findings_arr);
        j["findings"] = findings_arr;

        // Summary
        std::map<std::string, int> by_severity;
        std::map<std::string, int> by_type;
        for (const auto& f : findings) {
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

        j["summary"]["total"] = findings.size();
        for (const auto& [k, v] : by_severity) j["summary"]["by_severity"][k] = v;
        for (const auto& [k, v] : by_type) j["summary"]["by_type"][k] = v;

        if (extra) {
           for (auto& [key, value] : extra->items()) {
                j[key] = value;
            }
        }

        return j.dump(4);
    }    

} // namespace runtimexray