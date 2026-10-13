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
#include <vector>
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

    std::vector<runtimexray::Observation> observations;

    const long page_size_value = sysconf(_SC_PAGESIZE);
    if (page_size_value <= 0) {
        std::cerr << "Unable to determine page size\n";
        return 1;
    }

    const size_t page_size = static_cast<size_t>(page_size_value);
    size_t max_pages = 0;

    for (const auto& region : runtimexray::get_readable_regions(getpid())) {
        const uint64_t bytes = region.end - region.start;
        max_pages += static_cast<size_t>(
            (bytes + page_size - 1) / page_size);
    }

    if (max_pages == 0) {
        std::cerr << "No readable memory pages found\n";
        return 1;
    }

    runtimexray::scan_process_for_secrets(
        getpid(),
        observations,
        100,
        max_pages);

    bool found_memory = false;
    bool found_env = false;
    bool found_cmdline = false;

    for (const auto& observation : observations) {
        if (observation.type != runtimexray::ObservationType::Data) {
            continue;
        }

        if (observation.data_type == "memory" &&
            observation.data_snippet.find(memory_secret) != std::string::npos) {

            found_memory = true;
        }

        if (observation.data_type == "environment" &&
            !env_secret.empty() &&
            observation.data_snippet.find(env_secret) != std::string::npos) {

            found_env = true;
        }

        if (observation.data_type == "cmdline" &&
            !cmdline_secret.empty() &&
            observation.data_snippet.find(cmdline_secret) != std::string::npos) {

            found_cmdline = true;
        }
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