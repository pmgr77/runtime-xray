/**
 * @file    dangerous_api_rule.cpp
 * @brief   Detection rule for potentially dangerous ELF API symbols.
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

#include "dangerous_api_rule.hpp"

#include <optional>
#include <string>

namespace runtimexray {

namespace {

struct ApiRiskInfo {
    FindingSeverity severity;
    std::string description;
    std::string recommendation;
    std::string cwe_id;
};

std::string strip_symbol_version(
    const std::string& name)
{
    const auto pos =
        name.find('@');

    if (pos == std::string::npos) {
        return name;
    }

    return name.substr(0, pos);
}

std::optional<ApiRiskInfo> get_api_risk(
    const std::string& name)
{
    if (name == "strcpy" ||
        name == "strcat" ||
        name == "sprintf" ||
        name == "vsprintf" ||
        name == "gets" ||
        name == "scanf" ||
        name == "sscanf") {

        return ApiRiskInfo{
            FindingSeverity::High,
            "Unsafe string function that does not check bounds or format.",
            "Use bounded operations such as snprintf, fgets, or safer string abstractions.",
            "CWE-119"
        };
    }

    if (name == "strncpy" ||
        name == "strncat") {

        return ApiRiskInfo{
            FindingSeverity::Medium,
            "Potentially unsafe if null termination is not ensured.",
            "Use explicit length checks and guarantee null termination.",
            "CWE-120"
        };
    }

    if (name == "system" ||
        name == "popen") {

        return ApiRiskInfo{
            FindingSeverity::High,
            "Shell execution may become dangerous when influenced by untrusted input.",
            "Avoid shell interpretation; prefer exec-style APIs with explicit arguments.",
            "CWE-78"
        };
    }

    if (name == "mktemp" ||
        name == "tmpnam" ||
        name == "tempnam") {

        return ApiRiskInfo{
            FindingSeverity::Medium,
            "Predictable temporary file naming may enable filesystem attacks.",
            "Use mkstemp or another race-resistant temporary-file API.",
            "CWE-377"
        };
    }

    if (name == "rand" ||
        name == "random" ||
        name == "srand") {

        return ApiRiskInfo{
            FindingSeverity::Medium,
            "Predictable random-number generators are unsuitable for security-sensitive values.",
            "Use getrandom(), /dev/urandom, or another cryptographically secure source.",
            "CWE-338"
        };
    }

    if (name.find("MD5_") == 0 ||
        name.find("SHA1_") == 0) {

        return ApiRiskInfo{
            FindingSeverity::High,
            "Weak cryptographic hash API referenced.",
            "Use SHA-256 or a stronger modern primitive where appropriate.",
            "CWE-327"
        };
    }

    if (name.find("DES_") == 0 ||
        name.find("RC4") == 0) {

        return ApiRiskInfo{
            FindingSeverity::High,
            "Weak encryption API referenced.",
            "Use a modern authenticated encryption construction.",
            "CWE-327"
        };
    }

    if (name == "SSLv3_client_method" ||
        name == "SSLv3_server_method" ||
        name == "TLSv1_client_method" ||
        name == "TLSv1_server_method" ||
        name == "TLSv1_1_client_method" ||
        name == "TLSv1_1_server_method") {

        return ApiRiskInfo{
            FindingSeverity::High,
            "Deprecated TLS protocol API referenced.",
            "Use TLS 1.2 or TLS 1.3.",
            "CWE-326"
        };
    }

    if (name == "memcpy" ||
        name == "memmove" ||
        name == "memset") {

        return ApiRiskInfo{
            FindingSeverity::Low,
            "Memory operation may become unsafe when size calculations are incorrect.",
            "Validate sizes and object boundaries.",
            "CWE-805"
        };
    }

    if (name == "alloca") {
        return ApiRiskInfo{
            FindingSeverity::Medium,
            "Unbounded stack allocation may exhaust stack space.",
            "Prefer bounded storage or controlled dynamic allocation.",
            "CWE-770"
        };
    }

    if (name == "getopt" ||
        name == "getopt_long") {

        return ApiRiskInfo{
            FindingSeverity::Info,
            "Command-line argument parsing API referenced.",
            "Validate parsed inputs and error conditions.",
            "CWE-20"
        };
    }

    if (name == "atoi" ||
        name == "atol" ||
        name == "atoll") {

        return ApiRiskInfo{
            FindingSeverity::Low,
            "Numeric conversion API provides limited error reporting.",
            "Use strtol/strtoul-style APIs with explicit validation.",
            "CWE-190"
        };
    }

    if (name == "strtok") {
        return ApiRiskInfo{
            FindingSeverity::Low,
            "String tokenization API modifies its input and has shared-state semantics.",
            "Use strtok_r or a safer parsing abstraction.",
            "CWE-366"
        };
    }

    if (name == "gethostbyname" ||
        name == "gethostbyaddr") {

        return ApiRiskInfo{
            FindingSeverity::Medium,
            "Legacy hostname-resolution API referenced.",
            "Use getaddrinfo/getnameinfo.",
            "CWE-362"
        };
    }

    if (name == "inet_ntoa") {
        return ApiRiskInfo{
            FindingSeverity::Low,
            "Legacy address formatting API uses shared static storage.",
            "Use inet_ntop.",
            "CWE-362"
        };
    }

    return std::nullopt;
}

} // anonymous namespace

std::string DangerousApiRule::id() const
{
    return "builtin.dangerous_api";
}

std::string DangerousApiRule::description() const
{
    return "Detects ELF symbols associated with potentially dangerous APIs";
}

DetectionStage DangerousApiRule::stage() const
{
    return DetectionStage::Primary;
}

FindingList DangerousApiRule::detect(
    const DetectionContext& context) const
{
    FindingList findings;

    for (const auto& observation :
        context.graph.observations) {

        if (observation.type !=
            ObservationType::Static) {
            continue;
        }

        if (observation.static_category !=
            "imported_symbol") {
            continue;
        }

        if (observation.static_field.empty()) {
            continue;
        }

        const std::string api =
            strip_symbol_version(
                observation.static_field);

        const auto risk =
            get_api_risk(api);

        if (!risk) {
            continue;
        }

        Finding finding;

        finding.kind =
            "dangerous_api_reference";

        finding.severity =
            risk->severity;

        // Preserve the existing CLI-visible contract.
        finding.title =
            "Dangerous API: " + api;

        finding.summary =
            risk->description;

        finding.attributes["api"] =
            api;

        finding.attributes["recommendation"] =
            risk->recommendation;

        if (!risk->cwe_id.empty()) {
            finding.cwe_ids.push_back(
                risk->cwe_id);
        }

        if (observation.seq != 0) {
            finding.evidence_observation_seqs.push_back(
                observation.seq);
        }

        findings.push_back(
            std::move(finding));
    }

    return findings;
}

} // namespace runtimexray