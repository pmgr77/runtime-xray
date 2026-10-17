
/**
 * @file    memory_region_policy.cpp
 * @brief   Implements process memory region parsing and scan priorities.
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

#include <algorithm>
#include <sstream>
#include <string>
#include <utility>

namespace runtimexray {

namespace {

/**
 * @brief Test whether a string starts with a prefix.
 *
 * @param value String to inspect.
 * @param prefix Prefix to match.
 * @return True if the prefix matches.
 */
bool starts_with(const std::string& value, const std::string& prefix)
{
    return value.compare(0, prefix.size(), prefix) == 0;
}

/**
 * @brief Permission character positions in /proc/<pid>/maps.
 *
 * Linux represents mapping permissions as "rwxp" or "rwxs".
 */
constexpr std::string::size_type kWritePermissionIndex = 1;
constexpr std::string::size_type kExecutePermissionIndex = 2;

/**
 * @brief Priority classes for memory scanning.
 *
 * Declaration order defines scan priority:
 * highest priority first, lowest priority last.
 */
enum class RegionScanPriority {
    WritableStack,
    WritableHeap,
    WritableAnonymous,
    WritableFileBacked,
    ReadOnly,
    Executable
};

/**
 * @brief Determine the scan priority of a memory region.
 *
 * @param region Region to classify.
 * @return Priority class used to order memory scanning.
 */
RegionScanPriority region_priority(const MemoryRegion& region)
{
    const bool writable =
        region.perms.size() > kWritePermissionIndex &&
        region.perms[kWritePermissionIndex] == 'w';

    const bool executable =
        region.perms.size() > kExecutePermissionIndex &&
        region.perms[kExecutePermissionIndex] == 'x';

    const bool stack =
        region.path == "[stack]" ||
        starts_with(region.path, "[stack:");

    const bool heap =
        region.path == "[heap]";

    const bool anonymous =
        region.path.empty() ||
        starts_with(region.path, "[anon:") ||
        starts_with(region.path, "[anon_shmem:");

    if (writable && stack) {
        return RegionScanPriority::WritableStack;
    }

    if (writable && heap) {
        return RegionScanPriority::WritableHeap;
    }

    if (writable && anonymous) {
        return RegionScanPriority::WritableAnonymous;
    }

    if (writable) {
        return RegionScanPriority::WritableFileBacked;
    }

    if (executable) {
        return RegionScanPriority::Executable;
    }

    return RegionScanPriority::ReadOnly;
}

} // anonymous namespace

bool parse_readable_memory_region(
    const std::string& line,
    MemoryRegion& region)
{
    std::istringstream input(line);

    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t offset = 0;
    uint64_t inode = 0;

    char separator = '\0';

    std::string permissions;
    std::string device;

    // /proc/<pid>/maps format:
    //
    // address-range perms offset dev inode pathname
    //
    // The pathname is optional and may contain spaces.
    if (!(input >> std::hex
          >> start
          >> separator
          >> end
          >> permissions
          >> offset
          >> device
          >> std::dec
          >> inode)) {
        return false;
    }

    if (separator != '-' ||
        start >= end ||
        permissions.size() != 4 ||
        permissions[0] != 'r') {
        return false;
    }

    std::string path;
    std::getline(input, path);

    const auto first =
        path.find_first_not_of(" \t");

    if (first == std::string::npos) {
        path.clear();
    } else {
        path.erase(0, first);
    }

    region = {
        start,
        end,
        std::move(permissions),
        std::move(path)
    };

    return true;
}

void prioritize_memory_regions(std::vector<MemoryRegion>& regions)
{
    std::stable_sort(
        regions.begin(),
        regions.end(),
        [](const MemoryRegion& lhs, const MemoryRegion& rhs) {
            return region_priority(lhs) < region_priority(rhs);
        });
}

} // namespace runtimexray
