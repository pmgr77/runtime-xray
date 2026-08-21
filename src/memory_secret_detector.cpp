/**
 * @file    memory_secret_detector.cpp
 * @brief   Implements memory secret detectors.
 *
 * @author  Peter Magram
 * @date    2026-08-21
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

#include "memory_secret_detector.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace runtimexray {

namespace {
    // Helper: returns true if the character is a valid separator after a keyword.
    bool is_separator(char c) {
        //return c == '=' || c == ':' || c == '"' || c == '\'' || c == ' ';
        return c == '=' || c == ':';
    }

    // Helper: extracts a clean printable snippet of length up to max_len.
    std::string clean_snippet(const std::string& input, size_t start, size_t len) {
        std::string snippet = input.substr(start, len);
        std::string out;
        out.reserve(snippet.size());
        for (char c : snippet) {
            if (c >= 0x20 && c <= 0x7E) {
                out.push_back(c);
            } else {
                out.push_back('.');
            }
        }
        return out;
    }
} // namespace

std::vector<SecretMatch> PasswordDetector::detect(const std::string& chunk) const {
    std::vector<SecretMatch> results;
    // Specific keywords with delimiters
    static const std::vector<std::string> keywords = {
        "password", "passwd", "api_key", "secret", "token", "credentials", "credential"
    };

    for (const auto& kw : keywords) {
        size_t pos = 0;
        while ((pos = chunk.find(kw, pos)) != std::string::npos) {
            // Check that the next character is a separator (or end of string)
            size_t next = pos + kw.size();
            if (next < chunk.size() && is_separator(chunk[next])) {
                // Find the end of the value (up to 128 chars, stop at whitespace or comma)
                size_t value_start = next + 1; // skip the separator
                // Skip spaces if separator was space
                while (value_start < chunk.size() && chunk[value_start] == ' ') {
                    ++value_start;
                }
                size_t value_end = value_start;
                size_t max_val_len = 128;
                while (value_end < chunk.size() && value_end - value_start < max_val_len) {
                    char c = chunk[value_end];
                    if (c == '\0' || c == '\n' || c == '\r' || c == ',' || c == ';' ||
                        (c == ' ' && value_end > value_start && chunk[value_end-1] != '\\')) {
                        break;
                    }
                    value_end++;
                }
                size_t snippet_start = (pos > 20) ? pos - 20 : 0;
                size_t snippet_len = std::min<size_t>(160, chunk.size() - snippet_start);
                std::string snippet = clean_snippet(chunk, snippet_start, snippet_len);
                results.push_back({kw, snippet, "Potential password-like secret"});
                pos = next;
            } else {
                pos = next; // move past keyword
            }
        }
    }
    return results;
}

std::vector<SecretMatch> PrivateKeyDetector::detect(const std::string& chunk) const {
    std::vector<SecretMatch> results;
    static const std::vector<std::string> begin_markers = {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----"
    };
    static const std::vector<std::string> end_markers = {
        "-----END RSA PRIVATE KEY-----",
        "-----END OPENSSH PRIVATE KEY-----",
        "-----END EC PRIVATE KEY-----",
        "-----END DSA PRIVATE KEY-----"
    };

    for (size_t i = 0; i < begin_markers.size(); ++i) {
        size_t pos = chunk.find(begin_markers[i]);
        if (pos != std::string::npos) {
            // Capture up to the end marker or limited bytes
            size_t start = pos;
            size_t end = chunk.find(end_markers[i], pos + begin_markers[i].size());
            size_t capture_len = (end != std::string::npos)
                                     ? (end - start + end_markers[i].size())
                                     : std::min<size_t>(256, chunk.size() - start);
            std::string snippet = clean_snippet(chunk, start, capture_len);
            results.push_back({"private_key", snippet, "Private key found in memory"});
        }
    }
    return results;
}

std::vector<SecretMatch> detect_secrets_in_chunk(const std::string& chunk) {
    std::vector<SecretMatch> all;
    PasswordDetector pwd_detector;
    PrivateKeyDetector key_detector;

    auto pwd_matches = pwd_detector.detect(chunk);
    all.insert(all.begin(), pwd_matches.begin(), pwd_matches.end());

    auto key_matches = key_detector.detect(chunk);
    all.insert(all.begin(), key_matches.begin(), key_matches.end());

    return all;
}

} // namespace runtimexray