/**
 * @file    main.cpp
 * @brief   Entry point for RuntimeXRay – analyzes binary files for security findings.
 *
 * Currently implements a minimal ELF detector that checks the first four bytes
 * (the ELF magic number). Later it will orchestrate static and dynamic analysis
 * pipelines and generate developer-friendly security reports.
 *
 * @author  Peter Magram
 * @date    2026-08-10
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

// src/main.cpp
#include "mapped_file.hpp"
#include "elf_parser.hpp"
#include "finding.hpp"
#include <iostream>
#include <string>
#include <optional>

namespace {
    
    void print_help(const char* prog_name) {
        std::cout
            << "RuntimeXRay - Security posture analyzer for ELF binaries\n\n"
            << "Usage: " << prog_name << " [options] <binary>\n\n"
            << "Options:\n"
            << "  --min-severity <level>  Show findings at or above severity level.\n"
            << "                          Levels: Critical, High, Medium, Low, Info\n"
            << "                          Default: Medium\n"
            << "  --verbose               Show all findings (equivalent to --min-severity=Info)\n"
            << "  --help                  Show this help message\n";
    }

    std::optional<runtimexray::FindingSeverity> parse_severity(const std::string& s) {
        if (s == "Critical") return runtimexray::FindingSeverity::Critical;
        if (s == "High")     return runtimexray::FindingSeverity::High;
        if (s == "Medium")   return runtimexray::FindingSeverity::Medium;
        if (s == "Low")      return runtimexray::FindingSeverity::Low;
        if (s == "Info")     return runtimexray::FindingSeverity::Info;
        return std::nullopt;        
    }
}

int main(int argc, char* argv[]) {
    runtimexray::FindingSeverity min_severity = runtimexray::FindingSeverity::Medium;
    std::string path;

    const std::string prefix = "--min-severity=";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            return 0;
        } else if (arg.rfind(prefix, 0) == 0) {
            // Handle --min-severity=Level
            std::string level = arg.substr(prefix.size());
            auto severity = parse_severity(level);
            if (!severity) {
                std::cerr << "Invalid severity value. Use Critical, High, Medium, Low, or Info.\n";
                return 1;
            }
            min_severity = *severity;
        } else if (arg == "--min-severity" && ((i + 1) < argc)) {
            // Handle --min-severity Level
            auto severity = parse_severity(argv[++i]);
            if (!severity) {
                std::cerr << "Invalid severity value. Use Critical, High, Medium, Low, or Info.\n";
                return 1;
            }
            min_severity = *severity;
        } else if (arg == "--verbose") {
            min_severity = runtimexray::FindingSeverity::Info;
        } else if (!path.empty()) {
            std::cerr << "Unexpected argument: " << arg << '\n';
            print_help(argv[0]);
            return 1;
        } else {
            path = arg;
        }
    }

    if (path.empty()) {
        print_help(argv[0]);
        return 1;
    }

    try {
        runtimexray::parse_elf(path, min_severity);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}