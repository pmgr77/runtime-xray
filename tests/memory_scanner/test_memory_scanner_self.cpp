/**
 * @file    test_memory_scanner_self.cpp
 * @brief   Integration test for scanning our own process.
 *
 * @author  Peter Magram
 * @date    2026-08-22
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

#include "memory_scanner.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>

static const char* memory_secret = "password=memory_secret_test";

int main(int argc, char* argv[]) {
    // Read environment secret
    const char* env = std::getenv("TEST_SECRET");
    std::string env_secret = env ? env : "";

    // Read cmdline secret
    std::string cmdline_secret;
    if (argc > 1) {
        cmdline_secret = argv[1];
    }

    runtimexray::FindingList findings;
    runtimexray::scan_process_for_secrets(getpid(), findings, 100);

    bool found_memory = false;
    bool found_env = false;
    bool found_cmdline = false;

    for (const auto& f : findings) {
        std::visit([&](const auto& details) {
            using T = std::decay_t<decltype(details)>;
            if constexpr (std::is_same_v<T, runtimexray::MemorySecretFindingDetails>) {
                if (details.location == "memory" &&
                    details.snippet.find(memory_secret) != std::string::npos) {
                    found_memory = true;
                }
                if (details.location == "environment" &&
                    !env_secret.empty() &&
                    details.snippet.find(env_secret) != std::string::npos) {
                    found_env = true;
                }
                if (details.location == "cmdline" &&
                    !cmdline_secret.empty() &&
                    details.snippet.find(cmdline_secret) != std::string::npos) {
                    found_cmdline = true;
                }
            }
        }, f.details);
    }

    bool success = true;
    if (!found_memory) {
        std::cerr << "Memory secret not found\n";
        success = false;
    }
    if (!found_env) {
        std::cerr << "Environment secret not found\n";
        success = false;
    }
    if (!cmdline_secret.empty() && !found_cmdline) {
        std::cerr << "Cmdline secret not found\n";
        success = false;
    }

    return success ? 0 : 1;
}