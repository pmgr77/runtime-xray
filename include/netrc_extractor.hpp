
/**
 * @file    netrc_extractor.hpp
 * @brief   Extracts password values from .netrc-formatted content.
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

#ifndef RUNTIMEXRAY_NETRC_EXTRACTOR_HPP
#define RUNTIMEXRAY_NETRC_EXTRACTOR_HPP

#include <cstddef>
#include <string>
#include <vector>

namespace runtimexray {

/**
 * @brief A password extracted from .netrc content.
 *
 * The value contains the exact plaintext password bytes.
 * The offset identifies where those bytes occur in the original
 * input buffer.
 *
 * The extractor does not generate fingerprints or Observations.
 */
struct NetrcPassword {
    std::string value;
    size_t offset = 0;
};

/**
 * @brief Extract password values from .netrc-formatted content.
 *
 * Recognizes machine/default stanzas containing login and password
 * fields. Supports ordinary unquoted tokens and simple quoted tokens.
 *
 * Escaped values and unsupported syntax are not decoded.
 *
 * This is a bounded-format credential recognizer, not a complete
 * implementation of the .netrc grammar.
 *
 * @param data Raw content potentially containing .netrc credentials.
 *
 * @return Passwords with offsets into the original input buffer.
 *         Returns an empty vector if no supported passwords are found.
 *
 * @note This function performs extraction only. Secret fingerprinting,
 *       classification, and Observation creation are handled by the
 *       general secret extraction pipeline.
 */
std::vector<NetrcPassword> extract_netrc_passwords(const std::string& data);

} // namespace runtimexray

#endif // RUNTIMEXRAY_NETRC_EXTRACTOR_HPP
