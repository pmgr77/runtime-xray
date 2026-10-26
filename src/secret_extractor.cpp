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
#include "netrc_extractor.hpp"
#include "curl_config_extractor.hpp"

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
    TransformationType transformation = TransformationType::None;
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

int base64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool decode_base64(const std::string& input, std::string& output)
{
    output.clear();

    if (input.empty() ||
        input.size() > 4096 ||
        input.size() % 4 != 0) {
        return false;
    }

    for (size_t i = 0; i < input.size(); i += 4) {
        int v[4] = {};

        for (size_t j = 0; j < 4; ++j) {
            if (input[i + j] == '=') {
                if ((i + 4) != input.size() || j < 2) {
                    return false;
                }

                v[j] = -2;
            } else {
                v[j] = base64_value(input[i + j]);

                if (v[j] < 0) {
                    return false;
                }
            }
        }

        if (v[2] == -2 && v[3] != -2) {
            return false;
        }

        const unsigned a = static_cast<unsigned>(v[0]);
        const unsigned b = static_cast<unsigned>(v[1]);
        const unsigned c = v[2] < 0 ? 0U : static_cast<unsigned>(v[2]);
        const unsigned d = v[3] < 0 ? 0U : static_cast<unsigned>(v[3]);

        if ((v[2] == -2 && (b & 15U) != 0) ||
            (v[3] == -2 && v[2] != -2 && (c & 3U) != 0)) {
            return false;
        }

        output.push_back(static_cast<char>((a << 2) | (b >> 4)));

        if (v[2] != -2) {
            output.push_back(static_cast<char>(((b & 15U) << 4) | (c >> 2)));
        }

        if (v[3] != -2) {
            output.push_back(static_cast<char>(((c & 3U) << 6) | d));
        }
    }

    return true;
}

std::vector<SecretMatch>
extract_http_basic_matches(const std::string& data)
{
    std::vector<SecretMatch> results;

    size_t start = 0;

    while (start < data.size()) {
        const size_t newline = data.find('\n', start);
        const size_t end =
            newline == std::string::npos ? data.size() : newline;

        std::string line = data.substr(start, end - start);

        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        std::string lowered = line;

        std::transform(
            lowered.begin(),
            lowered.end(),
            lowered.begin(),
            [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });

        size_t prefix_length = 0;
        std::string secret_type;

        if (lowered.compare(0, 14, "authorization:") == 0) {
            prefix_length = 14;
            secret_type = "http_basic_password";
        } else if (lowered.compare(0, 20, "proxy-authorization:") == 0) {
            prefix_length = 20;
            secret_type = "http_proxy_basic_password";
        }

        if (prefix_length != 0) {
            size_t pos = prefix_length;

            while (pos < line.size() &&
                   (line[pos] == ' ' || line[pos] == '\t')) {
                ++pos;
            }

            if (lowered.compare(pos, 5, "basic") == 0) {
                pos += 5;

                if (pos < line.size() &&
                    (line[pos] == ' ' || line[pos] == '\t')) {

                    while (pos < line.size() &&
                           (line[pos] == ' ' || line[pos] == '\t')) {
                        ++pos;
                    }

                    const size_t token_start = pos;
                    const size_t token_end = line.find_first_of(" \t", pos);

                    const std::string encoded = line.substr(
                        pos,
                        token_end == std::string::npos
                            ? std::string::npos
                            : token_end - pos);

                    std::string decoded;

                    if (decode_base64(encoded, decoded)) {
                        const size_t colon = decoded.find(':');

                        if (colon != std::string::npos &&
                            decoded.size() - colon - 1 >= 6) {

                            results.push_back({
                                secret_type,
                                decoded.substr(colon + 1),
                                "[HTTP Basic credential]",
                                start + token_start,
                                TransformationType::Base64Decoded // transformed!
                            });
                        }
                    }
                }
            }
        }

        if (newline == std::string::npos) {
            break;
        }

        start = newline + 1;
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

    // Recognize structured credentials in file-read buffers.
    // Fingerprinting and Observation creation remain centralized here.
    if (location == "read") {
        //
        // Recognize .netrc credentials.
        //
        const auto netrc_passwords = extract_netrc_passwords(data);

        for (const auto& password : netrc_passwords) {
            matches.push_back({"password", password.value, "[netrc password]", password.offset});
        }

        //
        // Recognize curl configuration credentials.
        //
        // The extractor returns only the password portion of a
        // user:password directive, preserving its byte offset.
        //
        const auto curl_config_passwords = extract_curl_config_passwords(data);

        for (const auto& password :  curl_config_passwords) {
            matches.push_back({"password", password.value, "[curl config password]", password.offset});
        }
    }

    auto basic_matches = extract_http_basic_matches(data);

    matches.insert(
        matches.end(),
        std::make_move_iterator(basic_matches.begin()),
        std::make_move_iterator(basic_matches.end()));

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

        observation.secret_type = match.type;
        observation.transformation = match.transformation;

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

        if (base_address != 0 &&
            match.transformation == TransformationType::None) {
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