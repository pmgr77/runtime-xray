/**
 * @file    memory_scanner.hpp
 * @brief   Declaration of memory scanning functions for processes.
 *
 * @author  Peter Magram
 * @date    2026-08-21
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

#ifndef RUNTIMEXRAY_MEMORY_SCANNER_HPP
#define RUNTIMEXRAY_MEMORY_SCANNER_HPP


#include "finding.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace runtimexray {

    struct MemoryRegion {
        uint64_t start;
        uint64_t end;
        std::string perms;
        std::string path; // may be empty
    };

    /**
     * @brief Returns readable memory regions of a process.
     * @param pid Process ID.
     * @return Vector of readable regions (empty if error).
     */
    std::vector<MemoryRegion> get_readable_regions(pid_t pid);

    /**
     * @brief Scans /proc/<pid>/cmdline for secrets.
     * @param pid Process ID.
     * @param findings Output list to append findings to.
     * @param max_findings Maximum number of findings to add.
     */
    void scan_cmdline_for_secrets(pid_t pid, FindingList& findings, size_t max_findings = 20);

    /**
     * @brief Scans /proc/<pid>/environ for secrets.
     * @param pid Process ID.
     * @param findings Output list to append findings to.
     * @param max_findings Maximum number of findings to add.
     */
    void scan_environ_for_secrets(pid_t pid, FindingList& findings, size_t max_findings = 20);

    /**
     * @brief Scans all primary process data (memory, cmdline, environ) for secrets.
     * @param pid Process ID.
     * @param findings Output list to append findings to.
     * @param max_findings Total maximum number of findings.
     * @param max_pages Maximum number of memory pages to scan.
     * @param pages_scanned Optional output parameter; set to number of memory pages actually scanned.
     */
    void scan_process_for_secrets(pid_t pid, FindingList& findings,
                                size_t max_findings = 50,
                                size_t max_pages = 1000,
                                size_t* pages_scanned = nullptr);

    /**
     * @brief Scans readable memory of a process for secrets.
     * @param pid Process ID.
     * @param findings Output list to append findings to.
     * @param max_findings Maximum number of findings to add.
     * @param max_pages Maximum number of memory pages to scan.
     * @param pages_scanned Optional output parameter; will be set to the number of pages actually scanned.
     */
    void scan_memory_for_secrets(pid_t pid, FindingList& findings,
                                 size_t max_findings = 50,
                                 size_t max_pages = 1000,
                                 size_t* pages_scanned = nullptr);

    /**
     * @brief Get the process name (comm) for a given PID.
     * @param pid Process ID.
     * @return Process name (or empty string on failure).
     */
    std::string get_process_name(pid_t pid);
} // namespace runtimexray

#endif // RUNTIMEXRAY_MEMORY_SCANNER_HPP