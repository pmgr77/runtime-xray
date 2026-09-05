/**
 * @file    secret_fingerprinter.cpp
 * @brief   Implementation of SecretFingerprinter.
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

#include "secret_fingerprinter.hpp"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <iomanip>
#include <sstream>

namespace runtimexray {

SecretFingerprinter& SecretFingerprinter::instance() {
    static SecretFingerprinter instance;   // thread‑safe since C++11
    return instance;
}

SecretFingerprinter::SecretFingerprinter() : key_(32) {
    if (RAND_bytes(key_.data(), static_cast<int>(key_.size())) != 1) {
        throw std::runtime_error("Failed to generate fingerprint key");
    }
}

std::string SecretFingerprinter::fingerprint(const std::string& secret) const {
    if (secret.empty()) {
        // Not a valid secret, but we still need a deterministic empty fingerprint?
        // We'll return a special marker (or throw). Let's throw for clarity.
        throw std::runtime_error("Fingerprint called with empty secret");
    }

    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    unsigned char* output = HMAC(EVP_sha256(),
                                 key_.data(),
                                 static_cast<int>(key_.size()),
                                 reinterpret_cast<const unsigned char*>(secret.data()),
                                 secret.size(),
                                 result,
                                 &len);
    if (output == nullptr) {
        throw std::runtime_error("Failed to compute HMAC");
    }

    std::ostringstream oss;
    oss << "hmac-sha256:";
    for (unsigned int i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
    return oss.str();
}

} // namespace runtimexray