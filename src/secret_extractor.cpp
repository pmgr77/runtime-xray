/**
 * @file    secret_extractor.cpp
 * @brief   Extracts secret evidence from raw byte buffers.
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

#include "secret_extractor.hpp"

#include "logger.hpp"
#include "secret_fingerprinter.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>
#include <iterator>
#include <exception>
#include <chrono>

namespace runtimexray {

namespace {

struct SecretMatch {
    std::string type;
    std::string value;
    std::string snippet;
    size_t offset = 0;
};

std::string clean_extracted_secret(const std::string& raw)
{
    const size_t start =
        raw.find_first_not_of(" \t\n\r");

    if (start == std::string::npos) {
        return {};
    }

    size_t end =
        raw.find_last_not_of(" \t\n\r");

    std::string result =
        raw.substr(start, end - start + 1);

    while (!result.empty() &&
           std::strchr(".,!?:;", result.back()) != nullptr) {
        result.pop_back();
    }

    end = result.find_last_not_of(" \t\n\r");

    if (end != std::string::npos) {
        result.resize(end + 1);
    }

    return result;
}

std::vector<SecretMatch>
extract_password_matches(const std::string& data)
{
    std::vector<SecretMatch> results;

    static const std::vector<std::string> keywords = {
        "password",
        "passwd",
        "pwd",
        "pass",
        "pswd",
        "password_hash",
        "password_salt",
        "password_encrypted",
        "hashed_password",
        "api_key",
        "secret",
        "token",
        "credentials",
        "credential",
        "auth"
    };

    std::string lowered;
    lowered.reserve(data.size());

    for (unsigned char c : data) {
        lowered.push_back(
            static_cast<char>(std::tolower(c)));
    }

    constexpr size_t kMinValueLength = 6;

    for (const auto& keyword : keywords) {
        size_t pos = 0;

        while ((pos = lowered.find(keyword, pos))
               != std::string::npos) {

            if (pos > 0 &&
                std::isalnum(
                    static_cast<unsigned char>(
                        data[pos - 1]))) {
                pos += keyword.size();
                continue;
            }

            const size_t next =
                pos + keyword.size();

            size_t separator = next;

            if (separator < data.size() &&
                (data[separator] == '"' ||
                 data[separator] == '\'')) {
                ++separator;
            }

            if (separator >= data.size() ||
                (data[separator] != '=' &&
                 data[separator] != ':')) {
                pos = next;
                continue;
            }

            size_t value_start =
                separator + 1;

            while (value_start < data.size() &&
                   data[value_start] == ' ') {
                ++value_start;
            }

            if (value_start < data.size() &&
                (data[value_start] == '"' ||
                 data[value_start] == '\'')) {
                ++value_start;
            }

            size_t value_end = value_start;

            constexpr size_t kMaxValueLength = 128;

            while (value_end < data.size() &&
                   value_end - value_start < kMaxValueLength) {

                const char c = data[value_end];

                if (c == '\0' ||
                    c == '\n' ||
                    c == '\r' ||
                    c == ',' ||
                    c == ';' ||
                    c == ' ' ||
                    c == '"' ||
                    c == '\'') {
                    break;
                }

                ++value_end;
            }

            const std::string raw_value =
                data.substr(
                    value_start,
                    value_end - value_start);

            const std::string value =
                clean_extracted_secret(raw_value);

            if (value.size() >= kMinValueLength) {
                const size_t snippet_start =
                    (pos > 20) ? pos - 20 : 0;

                const size_t snippet_length =
                    std::min<size_t>(
                        160,
                        data.size() - snippet_start);

                std::string snippet =
                    data.substr(
                        snippet_start,
                        snippet_length);

                for (char& c : snippet) {
                    if (c < 0x20 || c > 0x7e) {
                        c = '.';
                    }
                }

                results.push_back({
                    keyword,
                    value,
                    snippet,
                    value_start
                });
            }

            pos = next;
        }
    }

    return results;
}

std::vector<SecretMatch>
extract_private_key_matches(const std::string& data)
{
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
        const size_t begin =
            data.find(begin_markers[i]);

        if (begin == std::string::npos) {
            continue;
        }

        const size_t end =
            data.find(
                end_markers[i],
                begin + begin_markers[i].size());

        const size_t length =
            (end != std::string::npos)
                ? end - begin + end_markers[i].size()
                : std::min<size_t>(
                      256,
                      data.size() - begin);

        //
        // Fingerprint exact observed bytes.
        //
        const std::string value =
            data.substr(begin, length);

        //
        // Keep printable context separately.
        //
        std::string snippet = value;

        for (char& c : snippet) {
            if (c < 0x20 || c > 0x7e) {
                c = '.';
            }
        }

        results.push_back({
            "private_key",
            value,
            snippet,
            begin
        });
    }

    return results;
}

} // anonymous namespace

std::vector<Observation> extract_secret_observations(
    const std::string& data,
    const std::string& location,
    pid_t pid,
    uintptr_t base_address)
{
    const auto observed_at = std::chrono::steady_clock::now();

    std::vector<SecretMatch> matches = extract_password_matches(data);

    auto private_keys = extract_private_key_matches(data);

    matches.insert(
        matches.end(),
        std::make_move_iterator(private_keys.begin()),
        std::make_move_iterator(private_keys.end()));

    std::vector<Observation> observations;
    observations.reserve(matches.size());

    for (const auto& match : matches) {
        std::string fingerprint;

        try {
            fingerprint = SecretFingerprinter::instance().fingerprint(match.value);
        } catch (const std::exception& e) {
            Logger::log(
                LogLevel::Error,
                "Secret fingerprint computation failed: " +
                    std::string(e.what()));

            continue;
        }

        Observation observation;
        observation.type = ObservationType::Data;
        observation.start_time = observed_at;
        observation.end_time = observed_at;

        //
        // Preserve the evidence source independently from the semantic
        // secret classification.
        //
        observation.data_type = location;
        observation.source = location;

        observation.secret_type =
            match.type;

        observation.fingerprint =
            std::move(fingerprint);

        //
        // This context may contain the raw secret. Reporters must never expose
        // it unless the configured secret-display policy allows that.
        //
        observation.data_snippet =
            match.snippet;

        observation.size =
            match.value.size();

        if (base_address != 0) {
            observation.address =
                base_address + match.offset;
        }

        observation.pid = pid;
        observation.tid = pid;
        observation.tgid = pid;

        observations.push_back(
            std::move(observation));
    }

    return observations;
}

} // namespace runtimexray