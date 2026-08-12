
/**
 * @file    elf_parser.cpp
 * @brief   Implements ELF parsing using RuntimeXRay's MappedFile.
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

#include "elf_parser.hpp"
#include "mapped_file.hpp"
#include <iostream>
#include <cstddef>
#include <cstring>
#include <array>

namespace runtimexray {
    /// Simplified ELF header structures (64-bit, native endian for now)
    struct Elf64_Ehdr {
        unsigned char e_ident[16]; // Magic number and other info
        // ... we will add more fields later
    };

    /**
     * @brief Quick check: is this an ELF file?
     * @param data Pointer to the beginning of the mapped file.
     * @param size Size of the file in bytes.
     * @return true if the file starts with the ELF magic bytes.
     */
    bool is_elf(const std::byte* data, std::size_t size) {
        constexpr std::array<std::byte, 4> magic = {
            std::byte{0x7F}, std::byte{'E'}, std::byte{'L'}, std::byte{'F'}
        };
        if (size < magic.size()) {
            return false;
        }
        return std::memcmp(data, magic.data(), magic.size()) == 0;
    }

    /**
     * @brief Parse an ELF file and print basic information.
     * @param path Path to the file.
     */
    void parse_elf(const std::string& path) {
        MappedFile mapped(path);
        if (!mapped.is_valid()) {
            std::cerr << "Failed to map file " << path <<'\n';
	        return;
        }

	    if (!is_elf(mapped.data(), mapped.size())) {
	        std::cout << path << " is not an ELF file.\n";
	        return;
	    }

	    std::cout << path << " is an ELF file. Size: " << mapped.size() << " bytes\n";
	    // Future: parse header, sections, etc.
    }

} // namespace runtimexray