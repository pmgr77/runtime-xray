/**
 * @file    test_memory_secret_detector.cpp
 * @brief   Unit tests for memory secret detectors.
 *
 * @author  Peter Magram
 * @date    2026-08-22
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

#include "memory_secret_detector.hpp"

#include <iostream>
#include <string>

int test_password_detector_finds_secret() {
    runtimexray::PasswordDetector detector;
    auto matches = detector.detect("some data password=supersecret123 more data");
    if (matches.empty()) {
        std::cerr << "PasswordDetector did not find password=...\n";
        return 1;
    }
    if (matches[0].secret_type != "password") {
        std::cerr << "Expected secret_type=password, got " << matches[0].secret_type << "\n";
        return 1;
    }
    if (matches[0].snippet.find("password=supersecret123") == std::string::npos) {
        std::cerr << "Snippet does not contain expected secret\n";
        return 1;
    }
    return 0;
}

int test_password_detector_avoids_false_positive_pass() {
    runtimexray::PasswordDetector detector;
    auto matches = detector.detect("the function passed the test");
    if (!matches.empty()) {
        std::cerr << "False positive on 'passed'\n";
        return 1;
    }
    return 0;
}

int test_password_detector_avoids_pwd_without_separator() {
    runtimexray::PasswordDetector detector;
    auto matches = detector.detect("PyInit_pwd");
    if (!matches.empty()) {
        std::cerr << "False positive on 'pwd' without separator\n";
        return 1;
    }
    return 0;
}

int test_password_detector_avoids_word_boundary_false_positive() {
    runtimexray::PasswordDetector detector;
    auto matches = detector.detect("struct_passwd: Results from getpw*()");
    if (!matches.empty()) {
        std::cerr << "False positive on 'struct_passwd:'\n";
        return 1;
    }
    return 0;
}

int test_password_detector_finds_api_key_with_colon() {
    runtimexray::PasswordDetector detector;
    auto matches = detector.detect("config api_key: abc123");
    if (matches.empty()) {
        std::cerr << "PasswordDetector did not find api_key: ...\n";
        return 1;
    }
    return 0;
}

int test_private_key_detector_finds_pem() {
    runtimexray::PrivateKeyDetector detector;
    std::string chunk = "random data -----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY----- tail";
    auto matches = detector.detect(chunk);
    if (matches.empty()) {
        std::cerr << "PrivateKeyDetector did not find PEM marker\n";
        return 1;
    }
    if (matches[0].secret_type != "private_key") {
        std::cerr << "Expected secret_type=private_key, got " << matches[0].secret_type << "\n";
        return 1;
    }
    return 0;
}

int test_detect_secrets_in_chunk_combines_detectors() {
    std::string chunk = "abc password=hidden def -----BEGIN OPENSSH PRIVATE KEY----- xyz";
    auto matches = runtimexray::detect_secrets_in_chunk(chunk);
    bool has_password = false;
    bool has_key = false;
    for (const auto& m : matches) {
        if (m.secret_type == "password") has_password = true;
        if (m.secret_type == "private_key") has_key = true;
    }
    if (!has_password || !has_key) {
        std::cerr << "Combined detector missed some secrets\n";
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
    if (test_detect_secrets_in_chunk_combines_detectors()) { std::cerr << "test_detect_secrets_in_chunk_combines_detectors failed\n"; return 1; }
    return 0;
}