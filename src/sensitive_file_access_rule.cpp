/**
 * @file    sensitive_file_access_rule.cpp
 * @brief   Implementation of sensitive filesystem access detection.
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

#include "sensitive_file_access_rule.hpp"

#include <cerrno>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <utility>

namespace {

std::optional<runtimexray::FindingSeverity>
classify_sensitive_path(const std::string& path)
{
    //
    // Preserve the policy previously implemented by SensitiveFileAnalyzer.
    //
    static const std::vector<std::string> critical = {
        "/etc/sudoers",
        "/etc/shadow",
        "/root/",
        "/.ssh",
        ".ssh",
        ".aws/credentials",
        ".gnupg",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519"
    };

    for (const auto& pattern : critical) {
        if (path.find(pattern) != std::string::npos) {
            return runtimexray::FindingSeverity::Critical;
        }
    }

    static const std::vector<std::string> high = {
        "secret",
        "token",
        "password",
        "credential",
        "api_key"
    };

    for (const auto& pattern : high) {
        if (path.find(pattern) != std::string::npos) {
            return runtimexray::FindingSeverity::High;
        }
    }

    static const std::vector<std::string> medium = {
        "/etc/passwd",
        "/etc/group"
    };

    for (const auto& pattern : medium) {
        if (path.find(pattern) != std::string::npos) {
            return runtimexray::FindingSeverity::Medium;
        }
    }

    static const std::vector<std::string> low = {
        "/etc/hosts",
        "/etc/resolv.conf"
    };

    for (const auto& pattern : low) {
        if (path.find(pattern) != std::string::npos) {
            return runtimexray::FindingSeverity::Low;
        }
    }

    static const std::vector<std::string> info = {
        "/etc/hostname",
        "/etc/machine-id"
    };

    for (const auto& pattern : info) {
        if (path.find(pattern) != std::string::npos) {
            return runtimexray::FindingSeverity::Info;
        }
    }

    return std::nullopt;
}

} // anonymous namespace

namespace runtimexray {

std::string SensitiveFileAccessRule::id() const
{
    return "builtin.sensitive_file_access";
}

std::string SensitiveFileAccessRule::description() const
{
    return "Detects attempts to access known sensitive filesystem paths";
}

DetectionStage SensitiveFileAccessRule::stage() const
{
    return DetectionStage::Primary;
}

FindingList SensitiveFileAccessRule::detect(
    const DetectionContext& context) const
{
    FindingList findings;

    for (const auto& observation : context.graph.observations) {
        if (observation.type != ObservationType::Event) {
            continue;
        }

        if (observation.syscall_name != "open" &&
            observation.syscall_name != "openat") {
            continue;
        }

        //
        // Path resolution is evidence collection responsibility. If the
        // collector could not resolve the pathname, this rule does not guess.
        //
        if (observation.source.empty()) {
            continue;
        }

        const auto severity =
            classify_sensitive_path(observation.source);

        if (!severity.has_value()) {
            continue;
        }

        Finding finding;

        //
        // rule_id is assigned by DetectionEngine from id().
        //
        finding.kind = "sensitive_resource_access";
        finding.severity = *severity;

        finding.attributes["path"] =
            observation.source;

        if (observation.return_value >= 0) {
            finding.title =
                "Sensitive file opened";

            finding.summary =
                "Process successfully opened a known sensitive filesystem path.";

            finding.attributes["outcome"] =
                std::string("opened");

            finding.attributes["errno"] =
                static_cast<int64_t>(0);
        } else {
            const int err =
                static_cast<int>(-observation.return_value);

            finding.attributes["errno"] =
                static_cast<int64_t>(err);

            if (err == EACCES || err == EPERM) {
                finding.title =
                    "Sensitive file access denied";

                finding.summary =
                    "Process attempted to access a known sensitive filesystem "
                    "path but the kernel denied access.";

                finding.attributes["outcome"] =
                    std::string("denied");
            } else if (err == ENOENT) {
                finding.title =
                    "Sensitive file access attempted";

                finding.summary =
                    "Process attempted to open a known sensitive filesystem "
                    "path that was not present.";

                finding.attributes["outcome"] =
                    std::string("failed");
            } else {
                finding.title =
                    "Sensitive file access failed";

                finding.summary =
                    "Process attempted to access a known sensitive filesystem "
                    "path but the open operation failed.";

                finding.attributes["outcome"] =
                    std::string("failed");
            }
        }

        //
        // This is a unary Finding: one syscall Observation proves the access
        // attempt. No graph edge evidence is required.
        //
        if (observation.seq != 0) {
            finding.evidence_observation_seqs.push_back(
                observation.seq);
        }

        findings.push_back(std::move(finding));
    }

    return findings;
}

} // namespace runtimexray