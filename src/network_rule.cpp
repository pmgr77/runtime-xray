/**
 * @file    network_rule.cpp
 * @brief   Detection rule for connections to security-sensitive network ports.
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

#include "network_rule.hpp"

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>

namespace runtimexray {

namespace {

struct Endpoint {
    std::string address;
    uint64_t port = 0;
};

std::optional<Endpoint> parse_endpoint(
    const std::string& value)
{
    const std::size_t separator =
        value.rfind(':');

    if (separator == std::string::npos ||
        separator + 1 >= value.size()) {

        return std::nullopt;
    }

    Endpoint endpoint;

    endpoint.address =
        value.substr(
            0,
            separator);

    const std::string port_text =
        value.substr(
            separator + 1);

    uint64_t port = 0;

    const auto result =
        std::from_chars(
            port_text.data(),
            port_text.data() +
                port_text.size(),
            port);

    if (result.ec != std::errc{} ||
        result.ptr !=
            port_text.data() +
                port_text.size()) {

        return std::nullopt;
    }

    endpoint.port = port;

    return endpoint;
}

bool is_sensitive_port(
    uint64_t port)
{
    switch (port) {
    case 22:
    case 3389:
    case 445:
    case 1433:
    case 3306:
        return true;

    default:
        return false;
    }
}

} // anonymous namespace

std::string NetworkRule::id() const
{
    return "builtin.network";
}

std::string NetworkRule::description() const
{
    return "Detects connection attempts to security-sensitive network services";
}

DetectionStage NetworkRule::stage() const
{
    return DetectionStage::Primary;
}

FindingList NetworkRule::detect(
    const DetectionContext& context) const
{
    FindingList findings;

    for (const auto& observation :
        context.graph.observations) {

        if (observation.type !=
            ObservationType::Event) {
            continue;
        }

        if (observation.syscall_name !=
            "connect") {
            continue;
        }

        if (observation.source.empty()) {
            continue;
        }

        const auto endpoint =
            parse_endpoint(
                observation.source);

        if (!endpoint) {
            continue;
        }

        if (!is_sensitive_port(
                endpoint->port)) {
            continue;
        }

        Finding finding;

        finding.kind =
            "suspicious_network_connection";

        finding.severity =
            FindingSeverity::Medium;

        finding.title =
            "Suspicious network connection";

        finding.summary =
            "Process attempted a connection to " +
            observation.source +
            ".";

        finding.attributes["endpoint"] =
            observation.source;

        finding.attributes["remote_address"] =
            endpoint->address;

        finding.attributes["remote_port"] =
            endpoint->port;

        finding.attributes["return_value"] =
            static_cast<int64_t>(
                observation.return_value);

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