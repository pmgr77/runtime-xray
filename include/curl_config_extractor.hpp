/**
 * @file    curl_config_extractor.hpp
 * @brief   Extracts password values from curl configuration content.
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

#ifndef RUNTIMEXRAY_CURL_CONFIG_EXTRACTOR_HPP
#define RUNTIMEXRAY_CURL_CONFIG_EXTRACTOR_HPP

#include <cstddef>
#include <string>
#include <vector>

namespace runtimexray {

/**
 * @brief A password extracted from a curl configuration directive.
 *
 * The value contains the exact plaintext password bytes.
 * The offset identifies the beginning of the password within
 * the original input buffer.
 *
 * The extractor does not generate fingerprints or Observations.
 */
struct CurlConfigPassword {
    std::string value;
    size_t offset = 0;
};

/**
 * @brief Extract passwords from supported curl configuration directives.
 *
 * Recognizes complete, line-oriented user directives such as:
 *
 *   user = "username:password"
 *   user: username:password
 *   --user username:password
 *   -u username:password
 *
 * The first colon in the parameter separates the username
 * from the password. Subsequent colons belong to the password.
 *
 * Full-line comments and unrelated directives are ignored.
 *
 * Only values whose password bytes are represented literally
 * in the input are supported. Escaped quoted values are skipped
 * conservatively to preserve exact-byte fingerprint semantics.
 *
 * This is a bounded-format credential recognizer, not a complete
 * implementation of the curl configuration grammar.
 *
 * @param data Raw content potentially containing curl configuration.
 *
 * @return Passwords with offsets into the original input buffer.
 *         Returns an empty vector if no supported passwords are found.
 *
 * @note The extractor performs extraction only. Fingerprinting,
 *       classification, and Observation creation are handled by
 *       the general secret extraction pipeline.
 *
 * @note Input buffers containing incomplete directives may produce
 *       false negatives. Cross-buffer reconstruction is not performed.
 */
std::vector<CurlConfigPassword> extract_curl_config_passwords(const std::string& data);

} // namespace runtimexray

#endif // RUNTIMEXRAY_CURL_CONFIG_EXTRACTOR_HPP