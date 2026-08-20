/**
 * @file    test_dynamic_helpers.cpp
 * @brief   Unit tests for dynamic analysis helper functions.
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
#include <iostream>
#include <vector>
#include <cstddef>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

int test_sanitize_data() {
    std::vector<std::byte> data = {std::byte{'H'}, std::byte{'i'}, std::byte{0x01}, std::byte{'!'}};
    std::string res = runtimexray::sanitize_data(data, 100);
    if (res != "hi.!") {
        return 1;
    }
    return 0;
}

int test_contains_sensitive_keyword() {
    if (!runtimexray::contains_sensitive_keyword("password=abc123")) {
        return 1;
    }
    if (!runtimexray::contains_sensitive_keyword("api_key=xyz")) {
        return 1;
    }
    if (runtimexray::contains_sensitive_keyword("just a normal string")) {
        return 1;
    }
    return 0;
}

int test_parse_sockaddr_ipv4() {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "1.2.3.4", &addr.sin_addr);
    addr.sin_port = htons(8080);
    std::vector<std::byte> bytes(sizeof(sockaddr_in));
    std::memcpy(bytes.data(), &addr, sizeof(addr));
    auto parsed = runtimexray::parse_sockaddr(bytes);
    if (!parsed.valid) {
        return 1;
    }
    if (parsed.ip != "1.2.3.4") {
        return 1;
    }
    if (parsed.port != 8080) {
        return 1;
    }
    return 0;
}

int test_parse_sockaddr_ipv6() {
    sockaddr_in6 addr6{};
    addr6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:db8::1", &addr6.sin6_addr);
    addr6.sin6_port = htons(443);
    std::vector<std::byte> bytes(sizeof(sockaddr_in6));
    std::memcpy(bytes.data(), &addr6, sizeof(addr6));
    auto parsed = runtimexray::parse_sockaddr(bytes);
    if (!parsed.valid) {
        return 1;
    }
    if (parsed.ip != "2001:db8::1") {
        return 1;
    }
    if (parsed.port != 443) {
        return 1;
    }
    return 0;
}

int main() {
    if (test_sanitize_data()) { std::cerr << "sanitize_data failed\n"; return 1; }
    if (test_contains_sensitive_keyword()) { std::cerr << "keyword test failed\n"; return 1; }
    if (test_parse_sockaddr_ipv4()) { std::cerr << "IPv4 parse failed\n"; return 1; }
    if (test_parse_sockaddr_ipv6()) { std::cerr << "IPv6 parse failed\n"; return 1; }
    return 0;
}