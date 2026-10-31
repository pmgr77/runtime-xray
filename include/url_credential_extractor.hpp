
/**
 * @file    url_credential_extractor.hpp
 * @brief   Extracts credentials from HTTP(S) URL userinfo.
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

#ifndef RUNTIMEXRAY_URL_CREDENTIAL_EXTRACTOR_HPP
#define RUNTIMEXRAY_URL_CREDENTIAL_EXTRACTOR_HPP

#include <string>

namespace runtimexray {

/**
 * @brief Extract a password from HTTP(S) URL userinfo.
 *
 * Supported examples:
 *   http://user:password@host/path
 *   https://user:p%40ssword@host/path
 *
 * The extracted password is percent-decoded before being returned,
 * allowing correlation with decoded credentials observed in memory
 * and HTTP Basic Authorization headers.
 *
 * Rules:
 * - Only HTTP and HTTPS URLs are supported.
 * - Only the URL authority is examined.
 * - Malformed percent-encoding is rejected.
 * - Control characters are rejected.
 * - '+' remains '+' (not converted to a space).
 * - Empty passwords are not reported.
 *
 * This function does not access process memory or create observations.
 *
 * @param url Input URL.
 * @param password Receives the decoded password on success.
 * @return true if a valid non-empty password was extracted.
 */
bool extract_http_url_password(const std::string& url, std::string& password);

} // namespace runtimexray

#endif // RUNTIMEXRAY_URL_CREDENTIAL_EXTRACTOR_HPP
