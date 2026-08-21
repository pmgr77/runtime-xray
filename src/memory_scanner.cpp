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
#include "memory_secret_detector.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/uio.h>
#include <unistd.h>

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

// Converts a SecretMatch into a Finding and appends it to the list.
void add_secret_finding(FindingList& findings,
                        const SecretMatch& match,
                        const std::string& source) {
    findings.emplace_back(
        FindingSeverity::High,
        "Sensitive data found in process",
        "Potential secret detected in " + source + ".",
        MemorySecretFindingDetails{match.snippet, match.secret_type, source}
    );
}

} // namespace

std::vector<MemoryRegion> get_readable_regions(pid_t pid) {
    std::vector<MemoryRegion> regions;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps) return regions;

    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream iss(line);
        uint64_t start, end;
        char dash;
        char perms[5] = {0};
        uint64_t offset;
        std::string rest;

        if (!(iss >> std::hex >> start >> dash >> end >> perms >> offset)) {
            continue;
        }

        // The rest of the line contains device, inode, and optional pathname.
        std::getline(iss, rest);
        rest.erase(0, rest.find_first_not_of(" \t"));
        std::string pathname = rest;

        // Only include regions that are readable.
        if (perms[0] == 'r') {
            regions.push_back({start, end, perms, pathname});
        }
    }
    return regions;
}

void scan_memory_for_secrets(pid_t pid, FindingList& findings, size_t max_findings) {
    auto regions = get_readable_regions(pid);
    if (regions.empty()) return;

    constexpr size_t chunk_size = 4096;
    std::vector<std::byte> buffer(chunk_size);
    size_t found = 0;

    for (const auto& region : regions) {
        uint64_t address = region.start;
        while (address < region.end && found < max_findings) {
            size_t to_read = std::min<size_t>(chunk_size, region.end - address);

            struct iovec local;
            local.iov_base = buffer.data();
            local.iov_len = to_read;

            struct iovec remote;
            remote.iov_base = reinterpret_cast<void*>(address);
            remote.iov_len = to_read;

            ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (n <= 0) {
                address += 4096; // skip inaccessible page
                continue;
            }

            std::string chunk(reinterpret_cast<char*>(buffer.data()), static_cast<size_t>(n));
            auto matches = detect_secrets_in_chunk(chunk);
            for (const auto& match : matches) {
                if (found >= max_findings) break;
                add_secret_finding(findings, match, "memory");
                ++found;
            }

            address += static_cast<uint64_t>(n);
        }
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
        auto matches = detect_secrets_in_chunk(arg);
        for (const auto& match : matches) {
            if (found >= max_findings) {
                return;
            }
            add_secret_finding(findings, match, "cmdline");
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
        auto matches = detect_secrets_in_chunk(var);
        for (const auto& match : matches) {
            if (found >= max_findings) {
                return;
            }
            add_secret_finding(findings, match, "environment");
            ++found;
        }
    }
}

void scan_process_for_secrets(pid_t pid, FindingList& findings, size_t max_findings) {
    size_t before = findings.size();
    scan_cmdline_for_secrets(pid, findings, max_findings);
    size_t after_cmd = findings.size();
    if (after_cmd - before >= max_findings) {
        return;
    }

    scan_environ_for_secrets(pid, findings, max_findings - (after_cmd - before));
    size_t after_env = findings.size();
    if (after_env - before >= max_findings) {
        return;
    }

    scan_memory_for_secrets(pid, findings, max_findings - (after_env - before));
}

} // namespace runtimexray