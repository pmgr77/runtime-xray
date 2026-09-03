/**
 * @file    memory_scanner.cpp
 * @brief   Implements process memory scanning for secrets.
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

#include "memory_scanner.hpp"
#include "analyzer_registry.hpp"
#include "evidence.hpp"
#include "logger.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

namespace runtimexray {

namespace {

// Reads the contents of /proc/<pid>/<name> as a string.
std::string read_proc_file(pid_t pid, const std::string& name) {
    std::ifstream file("/proc/" + std::to_string(pid) + "/" + name, std::ios::binary);
    if (!file) {
        return "";
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

// Splits a NUL-separated string into a vector of strings.
std::vector<std::string> split_nul_strings(const std::string& data) {
    std::vector<std::string> parts;
    if (data.empty()) {
        return parts;
    }

    size_t start = 0;
    while (start <= data.size()) {
        size_t end = data.find('\0', start);
        if (end == std::string::npos) {
            end = data.size();
        }
        if (end > start) {
            parts.emplace_back(data.substr(start, end - start));
        }
        if (end == data.size()) {
            break;
        }
        start = end + 1;
    }
    return parts;
}

} // namespace

std::vector<MemoryRegion> get_readable_regions(pid_t pid) {
    std::vector<MemoryRegion> regions;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps) return regions;

    std::string line;
    while (std::getline(maps, line)) {
        // Log every line from maps (for debugging)
        Logger::log(LogLevel::Debug, "Maps line: " + line);

        // Try to parse the line manually to handle any format
        std::istringstream iss(line);
        uint64_t start, end;
        char dash;
        char perms[5] = {0};
        uint64_t offset;
        std::string rest;

        if (!(iss >> std::hex >> start >> dash >> end >> perms >> offset)) {
            Logger::log(LogLevel::Debug, "Failed to parse maps line: " + line);
            continue;
        }

        // Read the rest (device, inode, pathname)
        std::getline(iss, rest);
        size_t pos = rest.find_first_not_of(" \t");
        if (pos != std::string::npos) {
            rest.erase(0, pos);
        }

        // Log every region (including non-readable)
        Logger::log(LogLevel::Debug, "Maps entry: 0x" + std::to_string(start) + " - 0x" + std::to_string(end) + " (" + perms + ")");        

        // Only include regions that are readable.
        if (perms[0] == 'r') {
            regions.push_back({start, end, perms, rest});
        }
    }
    return regions;
}

void scan_memory_for_secrets(pid_t pid, FindingList& findings,
                             size_t max_findings,
                             size_t max_pages,
                             size_t* pages_scanned) {
    // Fast path: no memory pages should be scanned
    if (max_pages == 0) {
        if (pages_scanned) {
            *pages_scanned = 0;
        }
        return;
    }

    auto regions = get_readable_regions(pid);
    if (regions.empty()) {
        if (pages_scanned) {
            *pages_scanned = 0;
        }
        return; // No readable regions or failed to read maps
    }

    // Compute total pages
    size_t total_pages = 0;
    for (const auto& region : regions) {
        total_pages += (region.end - region.start) / 4096;
    }
    Logger::log(LogLevel::Debug, "Total readable pages: " + std::to_string(total_pages) +
               ", max_pages: " + std::to_string(max_pages));

    constexpr size_t chunk_size = 4096;
    std::vector<std::byte> buffer(chunk_size);
    size_t found = 0;
    size_t scanned = 0;

    for (const auto& region : regions) {
        if (scanned >= max_pages) {
            break;
        }
        uint64_t address = region.start;
        Logger::log(LogLevel::Debug, "Scanning region 0x" + std::to_string(address) +
                   " - 0x" + std::to_string(region.end) + " (" + region.perms + ")");        
        while (address < region.end && found < max_findings && scanned < max_pages) {
            size_t to_read = std::min<size_t>(chunk_size, region.end - address);

            struct iovec local;
            local.iov_base = buffer.data();
            local.iov_len = to_read;

            struct iovec remote;
            remote.iov_base = reinterpret_cast<void*>(address);
            remote.iov_len = to_read;

            ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (n <= 0) {
                Logger::log(LogLevel::Debug, "process_vm_readv failed at 0x" + std::to_string(address) +
                " errno=" + std::to_string(errno) + " (" + std::strerror(errno) + ")");
                address += 4096; // skip inaccessible page
                ++scanned;
                if (scanned % 100 == 0) {
                    Logger::log(LogLevel::Debug, "Scanned " + std::to_string(scanned) + " pages (skipped)");
                }                
                continue;
            }

            ++scanned;
            if (scanned % 100 == 0) {
                Logger::log(LogLevel::Debug, "Scanned " + std::to_string(scanned) + " pages (read ok)");
            }

            std::string chunk(reinterpret_cast<char*>(buffer.data()), static_cast<size_t>(n));
            if (chunk.find("password=") != std::string::npos) {
                Logger::log(LogLevel::Debug, "Found 'password=' in chunk at 0x" + std::to_string(address));
            }
            // Create evidence and send to registry
            MemoryChunkEvidence ev{chunk, "memory", pid, address};
            FindingList results = AnalyzerRegistry::instance().analyze_evidence(ev);
            for (const auto& f : results) {
                if (found >= max_findings) break;
                findings.push_back(f);
                ++found;
            }

            address += static_cast<uint64_t>(n);
        }
    }

    if (pages_scanned) {
        *pages_scanned = scanned;
    }
}

void scan_cmdline_for_secrets(pid_t pid, FindingList& findings, size_t max_findings) {
    std::string cmdline = read_proc_file(pid, "cmdline");
    if (cmdline.empty()) {
        return;
    }

    auto args = split_nul_strings(cmdline);
    size_t found = 0;
    for (const auto& arg : args) {
        // Create evidence from this argument string.
        MemoryChunkEvidence ev{arg, "cmdline", pid, 0};
        FindingList results = AnalyzerRegistry::instance().analyze_evidence(ev);
        for (const auto& f : results) {
            if (found >= max_findings) {
                return;
            }
            findings.push_back(f);
            ++found;
        }
    }
}

void scan_environ_for_secrets(pid_t pid, FindingList& findings, size_t max_findings) {
    std::string environ = read_proc_file(pid, "environ");
    if (environ.empty()) {
        return;
    }

    auto env_vars = split_nul_strings(environ);
    size_t found = 0;
    for (const auto& var : env_vars) {
        // Create evidence from this environment variable string.
        MemoryChunkEvidence ev{var, "environment", pid, 0};
        FindingList results = AnalyzerRegistry::instance().analyze_evidence(ev);
        for (const auto& f : results) {
            if (found >= max_findings) {
                return;
            }
            findings.push_back(f);
            ++found;
        }
    }
}

void scan_process_for_secrets(pid_t pid, FindingList& findings,
                              size_t max_findings,
                              size_t max_pages,
                              size_t* pages_scanned) {
    size_t before = findings.size();
    // cmdline and environ do not scan memory page by page, so pages_scanned is counted only for memory
    scan_cmdline_for_secrets(pid, findings, max_findings);
    size_t after_cmd = findings.size();
    if ((after_cmd - before) >= max_findings) {
        if (pages_scanned) {
            *pages_scanned = 0;
        }
        return;
    }

    scan_environ_for_secrets(pid, findings, max_findings - (after_cmd - before));
    size_t after_env = findings.size();
    if ((after_env - before) >= max_findings) {
        if (pages_scanned) {
            *pages_scanned = 0;
        }
        return;
    }

    size_t remaining = max_findings - (after_env - before);
    size_t scanned = 0;
    scan_memory_for_secrets(pid, findings, remaining, max_pages, &scanned);
    if (pages_scanned) {
        *pages_scanned = scanned;
    }
}

std::string get_process_name(pid_t pid) {
    return read_proc_file(pid, "comm");
}

} // namespace runtimexray