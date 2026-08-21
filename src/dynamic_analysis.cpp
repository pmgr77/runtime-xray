/**
 * @file    dynamic_analysis.cpp
 * @brief   Implements helper functions for dynamic analysis.
 *
 * @author  Peter Magram
 * @date    2026-08-20
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

#include "dynamic_analysis.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>
#include <cctype>

namespace runtimexray {

    std::optional<FindingSeverity> get_sensitive_path_severity(const std::string& path) {
        // Critical: extremely sensitive files (e.g., sudoers, shadow)
        const std::vector<std::string> critical = {
            "/etc/sudoers", "/etc/shadow", "/root/", "/.ssh", ".ssh",
            ".aws/credentials", ".gnupg", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"
        };
        for (const auto& sub : critical) {
            if (path.find(sub) != std::string::npos) {
                return FindingSeverity::Critical;
            }
        }

        // High: files containing secrets or sensitive tokens
        const std::vector<std::string> high = {
            "secret", "token", "password", "credential", "api_key"
        };
        for (const auto& sub : high) {
            if (path.find(sub) != std::string::npos) {
                return FindingSeverity::High;
            }
        }

        // Medium: user/group databases, system configuration files
        const std::vector<std::string> medium = {
            "/etc/passwd", "/etc/group"
        };
        for (const auto& sub : medium) {
            if (path.find(sub) != std::string::npos) {
                return FindingSeverity::Medium;
            }
        }

        // Low: less sensitive but still interesting files
        const std::vector<std::string> low = {
            "/etc/hosts", "/etc/resolv.conf"
        };
        for (const auto& sub : low) {
            if (path.find(sub) != std::string::npos) {
                return FindingSeverity::Low;
            }
        }

        // Info: files that give basic system information
        const std::vector<std::string> info = {
            "/etc/hostname", "/etc/machine-id"
        };
        for (const auto& sub : info) {
            if (path.find(sub) != std::string::npos) {
                return FindingSeverity::Info;
            }
        }

        return std::nullopt;
    }

    std::string sanitize_data(const std::vector<std::byte>& data, size_t max_len) {
        std::string out;
        out.reserve(std::min(data.size(), max_len));
        for (size_t i = 0; i < data.size() && i < max_len; ++i) {
            unsigned char c = static_cast<unsigned char>(data[i]);
            if (c >= 0x20 && c <= 0x7E) {
                out.push_back(static_cast<char>(c));
            } else {
                out.push_back('.');
            }
        }
        if (data.size() > max_len) {
            out += "...";
        }
        return out;
    }

    std::string to_lower_case(const std::string& input) {
        std::string result = input;

        std::transform(input.begin(), input.end(), result.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return result;
    }

    bool contains_sensitive_keyword(const std::string& text) {
        static const std::vector<std::string> keywords = {
            "password", "passwd", "pwd", "pass", "pswd",
            "password_hash", "password_salt", "password_encrypted",
            "hashed_password", "secret", "api_key", "token", "credentials"
        };

        std::string lowered = to_lower_case(text);
        for (const auto& kw : keywords) {
            if (lowered.find(kw) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    ParsedSockaddr parse_sockaddr(const std::vector<std::byte>& data) {
        ParsedSockaddr out;
        if (data.size() < sizeof(sa_family_t)) {
            return out;
        }

        sa_family_t family = *reinterpret_cast<const sa_family_t*>(data.data());
        if (family == AF_INET) {
            if (data.size() < sizeof(sockaddr_in)) {
                return out;
            }
            const sockaddr_in* addr = reinterpret_cast<const sockaddr_in*>(data.data());
            char ip_str[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
            out.ip = ip_str;
            out.port = ntohs(addr->sin_port);
            out.valid = true;
        } else if (family == AF_INET6) {
            if (data.size() < sizeof(sockaddr_in6)) {
                return out;
            }
            const sockaddr_in6* addr = reinterpret_cast<const sockaddr_in6*>(data.data());
            char ip_str[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, &addr->sin6_addr, ip_str, sizeof(ip_str));
            out.ip = ip_str;
            out.port = ntohs(addr->sin6_port);
            out.valid = true;
        }
        return out;
    }

} // namespace runtimexray