/**
 * @file    curl_config_extractor.cpp
 * @brief   Implements password extraction from curl configuration content.
 *
 * @author  Peter Magram
 * @date    2026-10-26
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

#include "curl_config_extractor.hpp"

#include <optional>
#include <string>
#include <vector>

namespace runtimexray {

namespace {

/**
 * @brief Check for horizontal whitespace.
 *
 * Curl configuration directives are parsed line by line.
 * Newlines are handled separately.
 */
bool is_horizontal_space(char c)
{
    return c == ' ' || c == '\t';
}

/**
 * @brief Advance past horizontal whitespace.
 */
size_t skip_horizontal_space(const std::string& data, size_t pos, size_t end)
{
    while (pos < end && is_horizontal_space(data[pos])) {
        ++pos;
    }

    return pos;
}

/**
 * @brief Recognize a supported curl user directive on one complete line.
 *
 * This deliberately accepts only a subset of curl configuration syntax.
 *
 * The parser does not perform unescaping because the extracted value
 * must represent exact bytes found in the original input buffer.
 */
std::optional<CurlConfigPassword> parse_user_directive(const std::string& data, size_t line_begin, size_t line_end)
{
    // Support CRLF line endings.
    if (line_end > line_begin && data[line_end - 1] == '\r') {
        --line_end;
    }

    size_t pos = skip_horizontal_space(data, line_begin, line_end);

    // Empty lines and full-line comments.
    if (pos == line_end || data[pos] == '#') {
        return std::nullopt;
    }

    // Extract the option name.
    const size_t option_begin = pos;

    while (pos < line_end &&
           !is_horizontal_space(data[pos]) &&
           data[pos] != '=' &&
           data[pos] != ':') {
        ++pos;
    }

    const std::string option = data.substr(option_begin, pos - option_begin);

    const bool bare_user = (option == "user");

    const bool dashed_user = (option == "--user" || option == "-u");

    if (!bare_user && !dashed_user) {
        return std::nullopt;
    }

    if (pos == line_end) {
        return std::nullopt;
    }

    // Curl permits '=' and ':' separators for option names without
    // leading dashes. Dashed forms require whitespace separation.
    if (is_horizontal_space(data[pos])) {
        pos = skip_horizontal_space(data, pos, line_end);

        if (pos < line_end && (data[pos] == '=' || data[pos] == ':')) {
            if (!bare_user) {
                return std::nullopt;
            }

            ++pos;
            pos = skip_horizontal_space(data, pos, line_end);
        }
    } else {
        if (!bare_user) {
            return std::nullopt;
        }

        ++pos;
        pos = skip_horizontal_space(data, pos, line_end);
    }

    if (pos == line_end) {
        return std::nullopt;
    }

    size_t value_begin = 0;
    size_t value_end = 0;

    if (data[pos] == '"') {
        // Quoted parameter.
        ++pos;
        value_begin = pos;

        while (pos < line_end && data[pos] != '"') {
            // Escaped values require decoding and cannot be
            // represented as one exact contiguous byte sequence.
            // Skip them conservatively.
            if (data[pos] == '\\') {
                return std::nullopt;
            }

            ++pos;
        }

        // Missing closing quote.
        if (pos == line_end) {
            return std::nullopt;
        }

        value_end = pos;
        ++pos;
    } else {
        // Unquoted parameter.
        //
        // Parameters beginning with ':' or '=' require quoting
        // in curl configuration syntax.
        if (data[pos] == ':' || data[pos] == '=') {
            return std::nullopt;
        }

        value_begin = pos;

        while (pos < line_end && !is_horizontal_space(data[pos])) {
            ++pos;
        }

        value_end = pos;
    }

    // Reject extra tokens after the parameter.
    pos = skip_horizontal_space(data, pos, line_end);

    if (pos != line_end) {
        return std::nullopt;
    }

    // The first colon separates username from password.
    const size_t separator = data.find(':', value_begin);

    if (separator == std::string::npos ||
        separator >= value_end ||
        separator == value_begin ||
        separator + 1 >= value_end) {
        return std::nullopt;
    }

    // Reject control characters in the parsed parameter.
    // This also avoids treating arbitrary binary data as config.
    for (size_t i = value_begin; i < value_end; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);

        if (c < 0x20 || c == 0x7f) {
            return std::nullopt;
        }
    }

    const size_t password_begin = separator + 1;

    return CurlConfigPassword{
        data.substr(password_begin, value_end - password_begin), password_begin
    };
}

} // anonymous namespace

std::vector<CurlConfigPassword> extract_curl_config_passwords(const std::string& data)
{
    std::vector<CurlConfigPassword> results;

    size_t line_begin = 0;

    while (line_begin < data.size()) {
        const size_t newline = data.find('\n', line_begin);

        // A trailing fragment may be an incomplete read buffer.
        // Without stream framing, do not treat it as a complete
        // credential-bearing configuration directive.
        if (newline == std::string::npos) {
            break;
        }

        if (auto password = parse_user_directive(data, line_begin, newline)) {
            results.push_back(*password);
        }

        line_begin = newline + 1;
    }

    return results;
}

} // namespace runtimexray