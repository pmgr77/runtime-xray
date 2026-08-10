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

#include <iostream>
#include <fstream>
#include <array>
#include <cstddef>

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
	return 1;
    }

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << argv[1] << '\n';
	return 1;
    }

    // ELF magic: 0x7F, 'E', 'L', 'F'
    constexpr std::array<std::byte, 4> elf_magic = {
	    std::byte{0x7F}, std::byte{'E'}, std::byte{'L'}, std::byte{'F'}
    };
    
    std::array<std::byte, 4> header{};
    file.read(reinterpret_cast<char*>(header.data()), header.size());
    // Check the stream state after reading
    if (!file) {
        // If the stream is in an error state, either the file is too short,
        // or another I/O error occurred.
	if (file.eof()) {
            std::cerr << "Error: file " << argv[1] << " is too short (less than 4 bytes).\n";
	} else {
	    std::cerr << "Error: reading from file " << argv[1] << " failed.\n";
	}
	return 1;
    }

    // Additional check: make sure exactly 4 bytes were read
    if (file.gcount() != header.size()) {
        std::cerr << "Error: read " << file.gcount() << " bytes instead of " << header.size() << ".\n";
	return 1;
    }

    if (header == elf_magic) {
        std::cout << argv[1] << " is an ELF file.\n";
    } else {
        std::cout << argv[1] << " is NOT an ELF file.\n";
    }
}
