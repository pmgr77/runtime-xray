/**
 * @file    elf_parser.hpp
 * @brief   Declares the ELF parsing interface for RuntimeXRay.
 *
 * @author  Peter Magram
 * @date    2026-08-12
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

#ifndef RUNTIMEXRAY_ELF_PARSER_HPP
#define RUNTIMEXRAY_ELF_PARSER_HPP

#include "finding.hpp"   // for FindingSeverity
#include <string>

namespace runtimexray {

struct ElfMetadata {
    std::string path;
    std::size_t size_bytes = 0;
    std::string elf_class;
    std::string data_encoding;
    std::string elf_type;
    std::string machine;
    uint32_t version = 0;
    uint64_t entry_point = 0;
};

/**
 * @brief Analyzes an ELF binary and returns collected findings.
 * @param path Path to the ELF file.
 * @param min_severity Minimum severity threshold for findings.
 * @param verbose If true, include informational findings.
 * @param metadata Optional output parameter; if not null, filled with ELF metadata.
 * @return FindingList with static analysis results.
 * @throws std::runtime_error on fatal errors (cannot open, not ELF, unsupported, etc.).
 */
FindingList analyze_binary(const std::string& path,
                           FindingSeverity min_severity = FindingSeverity::Medium,
                           bool verbose = false,
                           ElfMetadata* metadata = nullptr);

} // namespace runtimexray

#endif // RUNTIMEXRAY_ELF_PARSER_HPP