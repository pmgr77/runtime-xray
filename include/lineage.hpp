/**
 * @file    lineage.hpp
 * @brief   Unified lineage graph structures for events, data, and static findings.
 *
 * @author  Peter Magram
 * @date    2026-08-30
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

#ifndef RUNTIMEXRAY_LINEAGE_HPP
#define RUNTIMEXRAY_LINEAGE_HPP

#include <chrono>
#include <string>
#include <vector>
#include <cstdint>
#include <sys/types.h>

namespace runtimexray {

enum class ObservationType {
    Event,  // syscall, fork, exec, etc.
    Data,   // memory content, file content, env var
    Static  // static analysis finding (hardening, dangerous API)
};

struct Observation {
    ObservationType type;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    std::chrono::microseconds duration; // end_time - start_time (if applicable)
    pid_t pid;
    pid_t tid;
    std::string program_name;           // if known (from execve)

    // Event-specific fields
    std::string syscall_name;
    uint64_t arg0, arg1, arg2, arg3, arg4, arg5;
    long long return_value;
    bool is_entry;

    // Data-specific fields
    std::string data_type;              // "secret", "key", "file_content", "env_var"
    std::string data_snippet;           // first 64 bytes (or less)
    uintptr_t address;
    size_t size;
    std::string source;                 // e.g., "file:/etc/passwd", "env:API_KEY"
    
    // Static-specific fields
    std::string static_field;
    std::string static_category;        // "hardening", "dangerous_api"
    std::string static_description;
    std::string static_recommendation;
    std::string cwe_id;
};

enum class RelationType {
    Chronological,   // A happened before B
    Causality,       // A caused B (fork → child process)
    DataFlow,        // A's data was used by B (read → buffer)
    Calls,           // Process A called syscall B
    StaticAssociated // Static finding associated with a node    
};

struct LineageEdge {
    size_t from_index;
    size_t to_index;
    RelationType relation;
    std::chrono::microseconds time_delta;
    std::string details;
};

struct LineageGraph {
    std::string summary;
    std::vector<Observation> observations;
    std::vector<LineageEdge> edges;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_LINEAGE_HPP