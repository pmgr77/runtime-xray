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
#include "secret_extractor.hpp"
#include "logger.hpp"

#include <chrono>
#include <utility>
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

size_t append_secret_observations(
    std::vector<Observation>& output,
    const std::string& data,
    const std::string& location,
    pid_t pid,
    uintptr_t address,
    size_t max_to_add)
{
    if (max_to_add == 0) {
        return 0;
    }

    auto extracted =
        extract_secret_observations(
            data,
            location,
            pid,
            address);

    size_t added = 0;

    for (auto& observation : extracted) {
        if (added >= max_to_add) {
            break;
        }

        const auto now =
            std::chrono::steady_clock::now();

        observation.start_time = now;
        observation.end_time = now;

        output.push_back(
            std::move(observation));

        ++added;
    }

    return added;
}

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

void scan_memory_for_secrets(
    pid_t pid,
    std::vector<Observation>& observations,
    size_t max_observations,
    size_t max_pages,
    size_t* pages_scanned)
{
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
    size_t read_ok = 0;
    size_t read_failed = 0;
    size_t bytes_read = 0;
    size_t password_chunks = 0;
    size_t fail_efault = 0;
    size_t fail_eperm = 0;
    size_t fail_esrch = 0;
    size_t fail_enosys = 0;
    size_t fail_other = 0;

    for (const auto& region : regions) {
        if (scanned >= max_pages) {
            break;
        }
        uint64_t address = region.start;
        Logger::log(LogLevel::Debug, "Scanning region 0x" + std::to_string(address) +
                   " - 0x" + std::to_string(region.end) + " (" + region.perms + ")");        
        while (address < region.end && found < max_observations && scanned < max_pages) {
            size_t to_read = std::min<size_t>(chunk_size, region.end - address);

            struct iovec local;
            local.iov_base = buffer.data();
            local.iov_len = to_read;

            struct iovec remote;
            remote.iov_base = reinterpret_cast<void*>(address);
            remote.iov_len = to_read;

            ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (n <= 0) {
                ++read_failed;

                switch (errno) {
                    case EFAULT: ++fail_efault; break;
                    case EPERM:  ++fail_eperm;  break;
                    case ESRCH:  ++fail_esrch;  break;
                    case ENOSYS: ++fail_enosys; break;
                    default:     ++fail_other;  break;
                }

                Logger::log(LogLevel::Debug, "process_vm_readv failed at 0x" + std::to_string(address) +
                " errno=" + std::to_string(errno) + " (" + std::strerror(errno) + ")");
                address += 4096; // skip inaccessible page
                ++scanned;
                if (scanned % 100 == 0) {
                    Logger::log(LogLevel::Debug, "Scanned " + std::to_string(scanned) + " pages (skipped)");
                }                
                continue;
            }

            ++read_ok;
            bytes_read += static_cast<size_t>(n);

            ++scanned;
            if (scanned % 100 == 0) {
                Logger::log(LogLevel::Debug, "Scanned " + std::to_string(scanned) + " pages (read ok)");
            }

            std::string chunk(reinterpret_cast<char*>(buffer.data()), static_cast<size_t>(n));
            if (chunk.find("password=") != std::string::npos) {
                ++password_chunks;
                Logger::log(LogLevel::Debug, "Found 'password=' in chunk at 0x" + std::to_string(address));
            }

            const size_t remaining = max_observations - found;
            found += append_secret_observations(
                observations,
                chunk,
                "memory",
                pid,
                static_cast<uintptr_t>(address),
                remaining);

            address += static_cast<uint64_t>(n);
        }
    }

    Logger::log(
        LogLevel::Info,
        "Memory read diagnostics for PID " + std::to_string(pid) +
        ": attempted=" + std::to_string(scanned) +
        ", ok=" + std::to_string(read_ok) +
        ", failed=" + std::to_string(read_failed) +
        ", bytes=" + std::to_string(bytes_read) +
        ", password_chunks=" + std::to_string(password_chunks) +
        ", observations=" + std::to_string(found) +
        ", EFAULT=" + std::to_string(fail_efault) +
        ", EPERM=" + std::to_string(fail_eperm) +
        ", ESRCH=" + std::to_string(fail_esrch) +
        ", ENOSYS=" + std::to_string(fail_enosys) +
        ", other=" + std::to_string(fail_other));

    if (pages_scanned) {
        *pages_scanned = scanned;
    }
}

void scan_cmdline_for_secrets(
    pid_t pid,
    std::vector<Observation>& observations,
    size_t max_observations)
{
    std::string cmdline = read_proc_file(pid, "cmdline");
    if (Logger::is_enabled(LogLevel::Debug)) {
        Logger::log_sensitive(
            LogLevel::Debug,
            "scan_cmdline_for_secrets: cmdline length = " +
                std::to_string(cmdline.size()) +
                ", content=<redacted>",
            "scan_cmdline_for_secrets: cmdline = " +
                cmdline);
    }
    if (cmdline.empty()) {
        return;
    }

    auto args = split_nul_strings(cmdline);

    static const std::vector<std::pair<std::string, std::string>> credential_flags = {
        {"-a",            "password"},
        {"-p",            "password"},
        {"--password",    "password"},
        {"--passwd",      "password"},
        {"--pass",        "password"},
        {"--requirepass", "password"},
        {"--api-key",     "api_key"},
        {"--api_key",     "api_key"},
        {"--token",       "token"},
    };

    size_t found = 0;

    auto emit = [&](const std::string& content) -> bool {
        if (found >= max_observations) {
            return false;
        }

        found += append_secret_observations(
            observations,
            content,
            "cmdline",
            pid,
            0,
            max_observations - found);

        return found < max_observations;
    };

    for (size_t i = 0; i < args.size(); ++i) {
        if (!emit(args[i]))
            return;

        for (const auto& [flag, keyword] : credential_flags) {
            if (args[i] == flag && i + 1 < args.size()) {
                std::string synthesized = keyword + "=" + args[i + 1];
                if (!emit(synthesized))
                    return;
                break;
            }
        }
    }
}

void scan_environ_for_secrets(
    pid_t pid,
    std::vector<Observation>& observations,
    size_t max_observations)
{
    std::string environ = read_proc_file(pid, "environ");
    Logger::log(LogLevel::Debug, "scan_environ_for_secrets: environ length = " + std::to_string(environ.size()));
    if (environ.empty()) {
        Logger::log(LogLevel::Debug, "scan_environ_for_secrets: empty or failed to read");
        return;
    }

    auto env_vars = split_nul_strings(environ);
    size_t found = 0;

    for (const auto& var : env_vars) {
        if (found >= max_observations) {
            return;
        }

        Logger::log(
            LogLevel::Debug,
            "scan_environ_for_secrets: checking environment variable");

        found += append_secret_observations(
            observations,
            var,
            "environment",
            pid,
            0,
            max_observations - found);
    }
}

void scan_process_for_secrets(
    pid_t pid,
    std::vector<Observation>& observations,
    size_t max_observations,
    size_t max_pages,
    size_t* pages_scanned)
{
    const size_t before = observations.size();

    scan_cmdline_for_secrets(
        pid,
        observations,
        max_observations);

    size_t produced =
        observations.size() - before;

    if (produced >= max_observations) {
        if (pages_scanned) {
            *pages_scanned = 0;
        }
        return;
    }

    scan_environ_for_secrets(
        pid,
        observations,
        max_observations - produced);

    produced =
        observations.size() - before;

    if (produced >= max_observations) {
        if (pages_scanned) {
            *pages_scanned = 0;
        }
        return;
    }

    size_t scanned = 0;

    scan_memory_for_secrets(
        pid,
        observations,
        max_observations - produced,
        max_pages,
        &scanned);

    if (pages_scanned) {
        *pages_scanned = scanned;
    }
}

std::string get_process_name(pid_t pid) {
    return read_proc_file(pid, "comm");
}

} // namespace runtimexray