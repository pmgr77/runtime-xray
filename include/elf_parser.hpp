/**
 * @file    elf_parser.hpp
 * @brief   Declares ELF evidence collection for RuntimeXRay.
 *
 * The ELF parser is a collector. It extracts factual static observations
 * from an ELF binary but does not make security decisions.
 *
 * Security conclusions are produced later by DetectionEngine rules.
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

#ifndef RUNTIMEXRAY_ELF_PARSER_HPP
#define RUNTIMEXRAY_ELF_PARSER_HPP

#include "lineage.hpp"

#include <cstddef>
#include <cstdint>
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
 * @brief Collect factual static observations from an ELF binary.
 *
 * The collector performs no security classification and creates no Findings.
 * Hardening properties and imported symbols are represented as Static
 * Observations in the returned LineageGraph.
 *
 * @param path Path to the ELF binary.
 * @param metadata Optional ELF metadata output.
 * @return LineageGraph containing static observations.
 * @throws std::runtime_error if the file cannot be parsed as a supported ELF.
 */
LineageGraph collect_elf_observations(
    const std::string& path,
    ElfMetadata* metadata = nullptr);

} // namespace runtimexray

#endif // RUNTIMEXRAY_ELF_PARSER_HPP