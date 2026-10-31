
/**
 * @file    url_credential_extractor.cpp
 * @brief   Extracts passwords from HTTP(S) URL userinfo.
 *
 * @author  Peter Magram
 * @date    2026-10-31
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 *
 * Copyright 2026 Peter Magram
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "url_credential_extractor.hpp"

#include <cstddef>
#include <string>
#include <utility>

namespace runtimexray {

namespace {

/**
 * @brief Convert a hexadecimal digit to its numeric value.
 *
 * @return Value in the range [0, 15], or -1 for an invalid digit.
 */
int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;

    return -1;
}

/**
 * @brief Decode percent-encoded bytes in a URL component.
 *
 * Converts %HH sequences into their corresponding bytes.
 * Rejects malformed escapes and ASCII control characters.
 *
 * Unlike form decoding, '+' remains a literal plus sign.
 *
 * @param encoded Input URL component.
 * @param decoded Decoded result on success.
 * @return true if decoding succeeded.
 */
bool percent_decode_url_component(const std::string& encoded, std::string& decoded)
{
    std::string result;
    result.reserve(encoded.size());

    for (size_t i = 0; i < encoded.size(); ++i) {
        unsigned char value = static_cast<unsigned char>(encoded[i]);

        if (encoded[i] == '%') {
            if (i + 2 >= encoded.size()) {
                return false;
            }

            const int hi = hex_value(encoded[i + 1]);
            const int lo = hex_value(encoded[i + 2]);

            if (hi < 0 || lo < 0) {
                return false;
            }

            value = static_cast<unsigned char>((hi << 4) | lo);

            i += 2;
        }

        if (value < 0x20 || value == 0x7f) {
            return false;
        }

        result.push_back(static_cast<char>(value));
    }

    decoded = std::move(result);
    return true;
}

} // anonymous namespace

bool extract_http_url_password(const std::string& url, std::string& password)
{
    size_t start = 0;

    if (url.compare(0, 7, "http://") == 0) {
        start = 7;
    } else if (url.compare(0, 8, "https://") == 0) {
        start = 8;
    } else {
        return false;
    }

    // Only inspect the URL authority.
    const size_t boundary = url.find_first_of("/?#", start);

    const size_t end = (boundary == std::string::npos) ? url.size() : boundary;

    // Locate the userinfo separator.
    const size_t at = url.rfind('@', end - 1);

    if (at == std::string::npos || at < start) {
        return false;
    }

    // Locate the username/password separator.
    const size_t colon = url.find(':', start);

    if (colon == std::string::npos || colon >= at) {
        return false;
    }

    // Extract only the password portion.
    const std::string encoded = url.substr(colon + 1, at - colon - 1);

    // Normalize percent-encoded credentials before fingerprinting.
    return percent_decode_url_component(encoded, password) && !password.empty();
}

} // namespace runtimexray
