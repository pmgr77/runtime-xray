/**
 * @file    evidence.hpp
 * @brief   Defines evidence types used by analyzers in RuntimeXRay.
 *
 * @author  Peter Magram
 * @date    2026-08-24
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

#ifndef RUNTIMEXRAY_EVIDENCE_HPP
#define RUNTIMEXRAY_EVIDENCE_HPP

#include <string>
#include <variant>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <sys/types.h>   // pid_t

namespace runtimexray {

/**
 * @brief Describes a symbol imported or exported by a binary.
 */
struct SymbolEvidence {
    std::string symbol_name;
    std::string origin; // "dynsym", "symtab", or "" if unknown
};

/**
 * @brief Describes file system access observed at runtime.
 */
struct FileAccessEvidence {
    std::string path;
    int flags = 0; // open() flags or -1 if not applicable
    pid_t pid;
};

/**
 * @brief Describes a network connection or data transfer.
 */
struct NetworkEvidence {
    std::string remote_addr;
    uint16_t remote_port;
    pid_t pid;
    std::string direction; // "outbound", "inbound", "unknown"
};

/**
 * @brief Describes a chunk of memory that was read and may contain secrets.
 */
struct MemoryChunkEvidence {
    std::string chunk;      // already sanitised printable fragment
    std::string location;   // "cmdline", "environment", "memory"
    pid_t pid;
};

/**
 * @brief Describes a system call event captured by the tracer.
 */
struct SyscallEventEvidence {
    unsigned long long syscall_number = 0;
    std::string syscall_name;
    pid_t pid;
    bool is_entry = true;
    // Arguments as raw values (architecture-independent interpretation is done by analyzers)
    unsigned long long arg0 = 0;
    unsigned long long arg1 = 0;
    unsigned long long arg2 = 0;
    unsigned long long arg3 = 0;
    unsigned long long arg4 = 0;
    unsigned long long arg5 = 0;
    long long return_value = 0;
};

/**
 * @brief Describes a static hardening property of an ELF binary.
 */
struct HardeningEvidence {
    std::string feature;    // "NX", "PIE", "RELRO", "Canary"
    std::string status;     // "Enabled", "Disabled", "Partial", "Full"
};

/**
 * @brief All supported evidence types.
 */
using Evidence = std::variant<
    SymbolEvidence,
    FileAccessEvidence,
    NetworkEvidence,
    MemoryChunkEvidence,
    SyscallEventEvidence,
    HardeningEvidence
>;

} // namespace runtimexray

#endif // RUNTIMEXRAY_EVIDENCE_HPP 