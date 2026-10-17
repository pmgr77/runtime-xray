
/**
 * @file    memory_region_policy.hpp
 * @brief   Parses and prioritizes process memory regions for scanning.
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

#ifndef RUNTIMEXRAY_MEMORY_REGION_POLICY_HPP
#define RUNTIMEXRAY_MEMORY_REGION_POLICY_HPP

#include "memory_scanner.hpp"

#include <string>
#include <vector>

namespace runtimexray {

/**
 * @brief Parse a readable memory mapping from /proc/<pid>/maps.
 *
 * Extracts the memory range, permissions, and optional pathname.
 * Non-readable and malformed mappings are rejected.
 *
 * @param line One line from /proc/<pid>/maps.
 * @param region Receives the parsed region on success.
 * @return True if a readable mapping was successfully parsed.
 */
bool parse_readable_memory_region(const std::string& line, MemoryRegion& region);

/**
 * @brief Order readable regions by their expected relevance to secrets.
 *
 * Prioritizes writable stacks, heap, anonymous mappings, and then
 * lower-priority regions. Preserves the original /proc/maps order
 * within each priority group.
 *
 * @param regions Memory regions to reorder in place.
 *
 * @note This function does not read process memory or modify scan
 *       budgets. It only determines traversal order.
 */
void prioritize_memory_regions(std::vector<MemoryRegion>& regions);

} // namespace runtimexray

#endif // RUNTIMEXRAY_MEMORY_REGION_POLICY_HPP
