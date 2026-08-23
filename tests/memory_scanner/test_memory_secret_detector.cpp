/**
 * @file    test_memory_secret_detector.cpp
 * @brief   Unit tests for memory secret detectors via registry.
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

#include "memory_secret_detector.hpp"

#include <iostream>
#include <string>
#include <vector>

using runtimexray::SecretMatch;

// Helper: check if a vector contains a match with a given secret_type.
bool contains_type(const std::vector<SecretMatch>& matches, const std::string& type) {
    for (const auto& m : matches) {
        if (m.secret_type == type) {
            return true;
        }
    }
    return false;
}

int test_password_detector_finds_secret() {
    auto matches = runtimexray::detect_secrets_in_chunk("some data password=supersecret123 more data");
    if (!contains_type(matches, "password")) {
        std::cerr << "Password detector did not find password=...\n";
        return 1;
    }
    return 0;
}

int test_password_detector_avoids_false_positive_pass() {
    auto matches = runtimexray::detect_secrets_in_chunk("the function passed the test");
    if (!matches.empty()) {
        std::cerr << "False positive on 'passed'\n";
        return 1;
    }
    return 0;
}

int test_password_detector_avoids_pwd_without_separator() {
    auto matches = runtimexray::detect_secrets_in_chunk("PyInit_pwd");
    if (!matches.empty()) {
        std::cerr << "False positive on 'pwd' without separator\n";
        return 1;
    }
    return 0;
}

int test_password_detector_avoids_word_boundary_false_positive() {
    auto matches = runtimexray::detect_secrets_in_chunk("struct_passwd: Results from getpw*()");
    if (!matches.empty()) {
        std::cerr << "False positive on 'struct_passwd:'\n";
        return 1;
    }
    return 0;
}

int test_password_detector_finds_api_key_with_colon() {
    auto matches = runtimexray::detect_secrets_in_chunk("config api_key: abc123");
    if (!contains_type(matches, "api_key")) {
        std::cerr << "Password detector did not find api_key: ...\n";
        return 1;
    }
    return 0;
}

int test_private_key_detector_finds_pem() {
    std::string chunk = "random data -----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY----- tail";
    auto matches = runtimexray::detect_secrets_in_chunk(chunk);
    if (!contains_type(matches, "private_key")) {
        std::cerr << "PrivateKeyDetector did not find PEM marker\n";
        return 1;
    }
    return 0;
}

int test_registry_disable_enable() {
    auto& reg = runtimexray::DetectorRegistry::instance();

    // Initially both detectors should be active.
    auto initial = runtimexray::detect_secrets_in_chunk("password=abc");
    bool has_password_initial = contains_type(initial, "password");
    if (!has_password_initial) {
        std::cerr << "Initial password detection failed\n";
        return 1;
    }

    // Disable password detector.
    reg.disable_detector("password");
    auto after_disable = runtimexray::detect_secrets_in_chunk("password=abc");
    if (contains_type(after_disable, "password")) {
        std::cerr << "Password detector still active after disable\n";
        return 1;
    }

    // Re-enable.
    reg.enable_detector("password");
    auto after_enable = runtimexray::detect_secrets_in_chunk("password=abc");
    if (!contains_type(after_enable, "password")) {
        std::cerr << "Password detector not active after re-enable\n";
        return 1;
    }

    return 0;
}

int main() {
    if (test_password_detector_finds_secret()) { std::cerr << "test_password_detector_finds_secret failed\n"; return 1; }
    if (test_password_detector_avoids_false_positive_pass()) { std::cerr << "test_password_detector_avoids_false_positive_pass failed\n"; return 1; }
    if (test_password_detector_avoids_pwd_without_separator()) { std::cerr << "test_password_detector_avoids_pwd_without_separator failed\n"; return 1; }
    if (test_password_detector_avoids_word_boundary_false_positive()) { std::cerr << "test_password_detector_avoids_word_boundary_false_positive failed\n"; return 1; }
    if (test_password_detector_finds_api_key_with_colon()) { std::cerr << "test_password_detector_finds_api_key_with_colon failed\n"; return 1; }
    if (test_private_key_detector_finds_pem()) { std::cerr << "test_private_key_detector_finds_pem failed\n"; return 1; }
    if (test_registry_disable_enable()) { std::cerr << "test_registry_disable_enable failed\n"; return 1; }
    return 0;
}