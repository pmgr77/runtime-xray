/**
 * @file    test_secret_fingerprinter.cpp
 * @brief   Unit tests for SecretFingerprinter.
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
#include <cassert>
#include <iostream>
#include <string>

int main() {
    try {
        runtimexray::SecretFingerprinter& fp = runtimexray::SecretFingerprinter::instance();

        // Test 1: Same secret → same fingerprint
        std::string secret1 = "password123";
        std::string fp1 = fp.fingerprint(secret1);
        std::string fp2 = fp.fingerprint(secret1);
        assert(fp1 == fp2);
        std::cout << "Test 1 passed: same secret → same fingerprint\n";

        // Test 2: Different secrets → different fingerprints
        std::string secret2 = "password456";
        std::string fp3 = fp.fingerprint(secret2);
        assert(fp1 != fp3);
        std::cout << "Test 2 passed: different secrets → different fingerprints\n";

        // Test 3: Fingerprint format
        assert(fp1.substr(0, 12) == "hmac-sha256:");
        assert(fp1.length() > 12);
        std::cout << "Test 3 passed: fingerprint format is correct\n";

        // Test 4: Empty secret throws
        try {
            fp.fingerprint("");
            assert(false && "Empty secret should throw");
        } catch (const std::runtime_error& e) {
            std::cout << "Test 4 passed: empty secret throws as expected\n";
        }

        // Test 5: Deterministic across calls (again)
        std::string fp4 = fp.fingerprint(secret1);
        assert(fp1 == fp4);
        std::cout << "Test 5 passed: deterministic\n";

        std::cout << "All tests passed.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << "\n";
        return 1;
    }
}