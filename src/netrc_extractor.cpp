
/**
 * @file    netrc_extractor.cpp
 * @brief   Implements password extraction from .netrc-formatted content.
 *
 * @author  Peter Magram
 * @date    2026-10-17
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

#include "netrc_extractor.hpp"

#include <cctype>
#include <string>
#include <vector>

namespace runtimexray {

namespace {

/**
 * @brief Token extracted from the input buffer.
 *
 * Preserves the original byte offset to support evidence provenance.
 * Unsupported escaped syntax is flagged rather than interpreted
 * incorrectly.
 */
struct Token {
    std::string value;
    size_t offset = 0;
    bool supported = true;
};

/**
 * @brief Tokenize a subset of .netrc syntax.
 *
 * Supports whitespace separation, comments at token boundaries,
 * and quoted values without escape sequences.
 *
 * @param data Raw input content.
 * @return Parsed tokens with their original offsets.
 */
std::vector<Token> tokenize(const std::string& data)
{
    std::vector<Token> tokens;
    size_t pos = 0;

    while (pos < data.size()) {
        const unsigned char c = static_cast<unsigned char>(data[pos]);

        // Reject binary content.
        if (c == '\0') {
            return {};
        }

        if (std::isspace(c)) {
            ++pos;
            continue;
        }

        // Comments begin at token boundaries.
        if (data[pos] == '#') {
            const size_t end = data.find('\n', pos);

            pos = (end == std::string::npos)
                ? data.size()
                : end + 1;

            continue;
        }

        bool supported = true;
        size_t start = pos;

        if (data[pos] == '"') {
            start = ++pos;

            while (pos < data.size() && data[pos] != '"') {
                if (data[pos] == '\\') {
                    supported = false;

                    // Skip escaped characters so escaped quotes
                    // do not terminate the current token.
                    pos += (pos + 1 < data.size()) ? static_cast<size_t>(2) : static_cast<size_t>(1);
                } else {
                    ++pos;
                }
            }

            if (pos >= data.size()) {
                return {};
            }

            const std::string value = data.substr(start, pos - start);

            ++pos; // Skip closing quote.

            // A quoted token must be followed by whitespace
            // or the end of the buffer.
            if (pos < data.size() &&
                !std::isspace(
                    static_cast<unsigned char>(data[pos]))) {
                supported = false;
            }

            tokens.push_back({
                value,
                start,
                supported
            });

            continue;
        }

        while (pos < data.size() &&
               !std::isspace(
                   static_cast<unsigned char>(data[pos])) &&
               data[pos] != '\0') {
            ++pos;
        }

        const std::string value = data.substr(start, pos - start);

        // Unquoted escape sequences are not decoded.
        if (value.find('\\') != std::string::npos) {
            supported = false;
        }

        tokens.push_back({
            value,
            start,
            supported
        });
    }

    return tokens;
}

/**
 * @brief Determine whether a token begins a .netrc stanza.
 *
 * @param token Token to inspect.
 * @return True for supported machine/default keywords.
 */
bool is_stanza(const Token& token)
{
    return token.supported &&
           (token.value == "machine" ||
            token.value == "default");
}

} // anonymous namespace

std::vector<NetrcPassword> extract_netrc_passwords(const std::string& data)
{
    std::vector<NetrcPassword> results;

    const auto tokens = tokenize(data);

    for (size_t i = 0; i < tokens.size();) {
        if (!is_stanza(tokens[i])) {
            ++i;
            continue;
        }

        const bool machine = tokens[i].value == "machine";

        size_t begin = i + 1;

        if (machine) {
            // A machine stanza must have a hostname.
            if (begin >= tokens.size() ||
                !tokens[begin].supported) {
                ++i;
                continue;
            }

            ++begin;
        }

        size_t end = begin;

        while (end < tokens.size() &&
               !is_stanza(tokens[end])) {
            ++end;
        }

        // Only accept passwords inside stanzas containing
        // a valid login field.
        bool has_login = false;

        for (size_t j = begin; j + 1 < end; ++j) {
            if (tokens[j].supported &&
                tokens[j].value == "login" &&
                tokens[j + 1].supported &&
                !tokens[j + 1].value.empty()) {
                has_login = true;
                break;
            }
        }

        if (has_login) {
            for (size_t j = begin; j + 1 < end; ++j) {
                if (!tokens[j].supported ||
                    tokens[j].value != "password" ||
                    !tokens[j + 1].supported) {
                    continue;
                }

                const Token& value = tokens[j + 1];

                constexpr size_t kMinLength = 6;
                constexpr size_t kMaxLength = 128;

                if (value.value.size() < kMinLength ||
                    value.value.size() > kMaxLength) {
                    continue;
                }

                results.push_back({
                    value.value,
                    value.offset
                });
            }
        }

        i = end;
    }

    return results;
}

} // namespace runtimexray
