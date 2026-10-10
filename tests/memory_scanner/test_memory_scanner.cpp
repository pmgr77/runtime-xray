/**
 * @file    test_memory_scanner.cpp
 * @brief   Unit tests for sensitive-data extraction from runtime memory.
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
#include "lineage.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

namespace {

bool contains_secret_type(
    const std::vector<runtimexray::Observation>& observations,
    const std::string& secret_type)
{
    for (const auto& observation : observations) {
        if (observation.type !=
            runtimexray::ObservationType::Data) {
            continue;
        }

        if (observation.secret_type ==
            secret_type) {
            return true;
        }
    }

    return false;
}

} // anonymous namespace

int main()
{
    const pid_t pid = getpid();

    const auto password_observations =
        runtimexray::extract_secret_observations(
            "some text password=supersecret123 more text",
            "memory",
            pid);

    if (!contains_secret_type(
            password_observations,
            "password")) {

        std::cerr
            << "Secret extractor failed to detect password.\n";
        return 1;
    }

    const auto key_observations =
        runtimexray::extract_secret_observations(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEow...\n"
            "-----END RSA PRIVATE KEY-----",
            "memory",
            pid);

    if (!contains_secret_type(
            key_observations,
            "private_key")) {

        std::cerr
            << "Secret extractor failed to detect private key.\n";
        return 1;
    }

    std::cout
        << "Secret extractor tests passed.\n";

    return 0;
}