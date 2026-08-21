/**
 * @file    main_mem.cpp
 * @brief   CLI for scanning process memory for secrets.
 *
 * @author  Peter Magram
 * @date    2026-08-21
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
#include <iostream>
#include <string>
#include <cstdlib>
#include <variant>
#include <type_traits>

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " <pid>\n";
    std::cout << "Scans readable memory of the given process for secrets.\n";
    std::cout << "Options:\n";
    std::cout << "  --help    Show this help message.\n";
}

int main(int argc, char* argv[]) {
    if (argc != 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        print_usage(argv[0]);
        return (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) ? 0 : 1;
    }

    pid_t pid;
    try {
        pid = std::stoi(argv[1]);
    } catch (...) {
        std::cerr << "Invalid PID: " << argv[1] << "\n";
        print_usage(argv[0]);
        return 1;
    }
    runtimexray::FindingList findings;
    runtimexray::scan_memory_for_secrets(pid, findings);

    if (findings.empty()) {
        std::cout << "No sensitive data found in memory of PID " << pid << ".\n";
    } else {
        std::cout << "Found " << findings.size() << " potential secrets:\n";
        for (const auto& f : findings) {
            std::visit([&](const auto& details) {
                using T = std::decay_t<decltype(details)>;
                if constexpr (std::is_same_v<T, runtimexray::SensitiveDataWriteDetails>) {
                    std::cout << " - " << f.description
                            << " data=\"" << details.data_snippet << "\"\n";
                } else {
                    std::cout << " - " << f.description << "\n";
                }
            }, f.details);
        }
    }
    
    return 0;
}