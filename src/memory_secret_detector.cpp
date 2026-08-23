/**
 * @file    memory_secret_detector.cpp
 * @brief   Implements memory secret detectors.
 *
 * @author  Peter Magram
 * @date    2026-08-21
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

    // Built-in detectors defined here
    class PasswordDetector : public MemorySecretDetector {
    public:
        std::string name() const override { return "password"; }
        
        std::string description() const override {
            return "Detects key=value or key: value pairs with sensitive keywords";
        }

        std::vector<SecretMatch> detect(const std::string& chunk) const override {
            std::vector<SecretMatch> results;
            // Specific keywords with delimiters
            static const std::vector<std::string> keywords = {
                "password", "passwd", "api_key", "secret", "token", "credentials", "credential"
            };

            for (const auto& kw : keywords) {
                size_t pos = 0;
                while ((pos = chunk.find(kw, pos)) != std::string::npos) {
                    // Skip if the keyword is part of a larger identifier
                    // (e.g., struct_passwd, my_password_hash)
                    if (pos > 0 &&
                        (std::isalnum(static_cast<unsigned char>(chunk[pos - 1])) ||
                        chunk[pos - 1] == '_')) {
                        pos += kw.size();
                        continue;
                    }

                    size_t next = pos + kw.size();

                    // Check that the next character is a separator
                    if (next < chunk.size() && is_separator(chunk[next])) {
                        // Find the end of the value (up to 128 chars, stop at whitespace or comma)
                        size_t value_start = next + 1; // skip the separator

                        // Skip spaces if separator was space
                        while (value_start < chunk.size() && chunk[value_start] == ' ') {
                            ++value_start;
                        }

                        size_t value_end = value_start;
                        const size_t max_val_len = 128;
                        while (value_end < chunk.size() && (value_end - value_start) < max_val_len) {
                            char c = chunk[value_end];
                            if (c == '\0' || c == '\n' || c == '\r' || c == ',' || c == ';' ||
                                (c == ' ' && value_end > value_start && chunk[value_end - 1] != '\\')) {
                                break;
                            }
                            ++value_end;
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
    };
    class PrivateKeyDetector : public MemorySecretDetector {
    public:
        std::string name() const override { return "private_key"; }
        std::string description() const override {
            return "Detects PEM private key blocks";
        }
        std::vector<SecretMatch> detect(const std::string& chunk) const override {
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
    };
} // anonymous namespace

// Singleton implementation
DetectorRegistry& DetectorRegistry::instance() {
    static DetectorRegistry registry;
    return registry;
}

DetectorRegistry::DetectorRegistry() {
    // Register built-in detectors
    register_detector(std::make_unique<PasswordDetector>());
    register_detector(std::make_unique<PrivateKeyDetector>());
}

void DetectorRegistry::register_detector(std::unique_ptr<MemorySecretDetector> detector) {
    if (!detector) {
        return;
    }
    // Avoid duplicate names
    for (const auto& d : detectors_) {
        if (d->name() == detector->name()) {
            return; // already registered
        }
    }
    detectors_.push_back(std::move(detector));
}

void DetectorRegistry::unregister_detector(const std::string& name) {
    detectors_.erase(
        std::remove_if(detectors_.begin(), detectors_.end(),
                        [&](const std::unique_ptr<MemorySecretDetector>& d) {
                            return d->name() == name;
                        }),
        detectors_.end());
    // also remove from disabled set if present
    disabled_detectors_.erase(name);
}

void DetectorRegistry::disable_detector(const std::string& name) {
    disabled_detectors_.insert(name);
}

void DetectorRegistry::enable_detector(const std::string& name) {
    disabled_detectors_.erase(name);
}

std::vector<const MemorySecretDetector*> DetectorRegistry::active_detectors() const {
    std::vector<const MemorySecretDetector*> active;
    for (const auto& d : detectors_) {
        if (disabled_detectors_.find(d->name()) == disabled_detectors_.end()) {
            active.push_back(d.get());
        }
    }
    return active;
}

std::vector<std::string> DetectorRegistry::list_detectors() const {
    std::vector<std::string> names;
    for (const auto& d : detectors_) {
        names.push_back(d->name());
    }
    return names;
}

std::vector<SecretMatch> detect_secrets_in_chunk(const std::string& chunk) {
    std::vector<SecretMatch> all;
    auto& registry = DetectorRegistry::instance();
    for (const auto* detector : registry.active_detectors()) {
        auto matches = detector->detect(chunk);
        all.insert(all.end(), matches.begin(), matches.end());
    }
    return all;
}

} // namespace runtimexray