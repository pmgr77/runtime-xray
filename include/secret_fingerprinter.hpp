/**
 * @file    secret_fingerprinter.hpp
 * @brief   Per‑run HMAC‑SHA256 fingerprinter for secrets.
 *
 * @author  Peter Magram
 * @date    2026-09-05
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

#ifndef RUNTIMEXRAY_SECRET_FINGERPRINTER_HPP
#define RUNTIMEXRAY_SECRET_FINGERPRINTER_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace runtimexray {

/**
 * @brief Generates HMAC‑SHA256 fingerprints using a per‑process random key.
 *
 * The fingerprint is deterministic within a single execution, but different
 * runs produce different fingerprints. This prevents offline dictionary
 * attacks against the fingerprint.
 */
class SecretFingerprinter {
public:
    static SecretFingerprinter& instance();

    /**
     * @brief Compute HMAC‑SHA256 fingerprint of the exact secret.
     * @param secret The exact secret value (non‑empty).
     * @return "hmac-sha256:<hex>" string.
     * @throws std::runtime_error if key generation or HMAC computation fails.
     */
    std::string fingerprint(const std::string& secret) const;

private:
    SecretFingerprinter();
    std::vector<uint8_t> key_;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_SECRET_FINGERPRINTER_HPP