
/**
 * @file    test_memory_region_priority.cpp
 * @brief   Unit tests for memory mapping parsing and scan ordering.
 *
 * @author  Peter Magram
 * @date    2026-10-17
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

#include "memory_region_policy.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using runtimexray::MemoryRegion;

/**
 * @brief Fail a test when its condition is false.
 *
 * @param condition Required condition.
 * @param message Diagnostic message on failure.
 */
void require(
    bool condition,
    const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/**
 * @brief Verify parsing of memory ranges and paths.
 */
void test_maps_parsing()
{
    MemoryRegion region{};

    require(
        runtimexray::parse_readable_memory_region(
            "00010000-00012000 rw-p 00000000 00:00 0 [heap]",
            region),
        "Failed to parse heap mapping");

    require(
        region.start == 0x10000 &&
        region.end == 0x12000,
        "Incorrect memory addresses");

    require(
        region.perms == "rw-p" &&
        region.path == "[heap]",
        "Incorrect mapping fields");

    require(
        runtimexray::parse_readable_memory_region(
            "00012000-00013000 r--p 00000000 08:01 42 /opt/test library.so",
            region),
        "Failed to parse file-backed mapping");

    require(
        region.path == "/opt/test library.so",
        "Incorrect pathname extraction");

    require(
        runtimexray::parse_readable_memory_region(
            "00014000-00015000 rw-p 00000000 00:00 0",
            region),
        "Failed to parse anonymous mapping");

    require(
        region.path.empty(),
        "Anonymous mapping must have an empty pathname");

    require(
        !runtimexray::parse_readable_memory_region(
            "00014000-00015000 ---p 00000000 00:00 0",
            region),
        "Non-readable mapping was accepted");

    require(
        !runtimexray::parse_readable_memory_region(
            "not a maps line",
            region),
        "Malformed mapping was accepted");
}

/**
 * @brief Verify deterministic and stable memory scan priorities.
 */
void test_region_priorities()
{
    std::vector<MemoryRegion> regions = {
        {0x1000, 0x2000, "r-xp", "/usr/lib/libfoo.so"},
        {0x2000, 0x3000, "rw-p", ""},
        {0x3000, 0x4000, "r--p", "/etc/something"},
        {0x4000, 0x5000, "rw-p", "[heap]"},
        {0x5000, 0x6000, "rw-p", "/tmp/mapped_file"},
        {0x6000, 0x7000, "rw-p", "[stack]"},
        {0x7000, 0x8000, "rw-p", "[anon:credentials]"},
        {0x8000, 0x9000, "rw-p", ""}
    };

    runtimexray::prioritize_memory_regions(regions);

    const std::vector<std::string> expected = {
        "[stack]",
        "[heap]",
        "",
        "[anon:credentials]",
        "",
        "/tmp/mapped_file",
        "/etc/something",
        "/usr/lib/libfoo.so"
    };

    require(
        regions.size() == expected.size(),
        "Region count changed");

    for (size_t i = 0; i < expected.size(); ++i) {
        require(
            regions[i].path == expected[i],
            "Incorrect priority order at index " +
                std::to_string(i));
    }

    // Stable sorting must preserve the original order
    // of equally prioritized anonymous regions.
    require(
        regions[2].start == 0x2000 &&
        regions[4].start == 0x8000,
        "Stable ordering was not preserved");
}

} // anonymous namespace

/**
 * @brief Execute memory region policy unit tests.
 *
 * @return 0 on success, 1 on failure.
 */
int main()
{
    try {
        test_maps_parsing();
        test_region_priorities();

        std::cout
            << "PASS: memory region policy tests\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr
            << "FAIL: " << e.what() << '\n';

        return 1;
    }
}
