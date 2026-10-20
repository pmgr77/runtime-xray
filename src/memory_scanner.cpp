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
#include "memory_region_policy.hpp"
#include "memory_reader.hpp"
#include "logger.hpp"

#include <chrono>
#include <utility>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
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

// Experimental, process-wide backend selection. This is intentionally
// explicit: never silently switch methods after a read/open failure.
// The default remains the project's original process_vm_readv() path.
bool select_memory_read_backend(MemoryReadBackend& backend)
{
    backend = MemoryReadBackend::ProcessVmReadv;
    const char* selected = std::getenv("RXRAY_MEMORY_READ_BACKEND");

    if (selected == nullptr || selected[0] == '\0' ||
        std::strcmp(selected, "vmread") == 0) {
        return true;
    }

    if (std::strcmp(selected, "proc") == 0) {
        backend = MemoryReadBackend::ProcMem;
        return true;
    }

    Logger::log(
        LogLevel::Error,
        "Invalid RXRAY_MEMORY_READ_BACKEND (expected 'vmread' or 'proc')");
    return false;
}

const char* backend_name(MemoryReadBackend backend)
{
    switch (backend) {
    case MemoryReadBackend::ProcessVmReadv:
        return "process_vm_readv";
    case MemoryReadBackend::ProcMem:
        return "/proc/<pid>/mem";
    }
    return "unknown";
}

} // namespace

std::vector<MemoryRegion> get_readable_regions(pid_t pid) {
    std::vector<MemoryRegion> regions;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps) {
        return regions;
    }

    std::string line;

    while (std::getline(maps, line)) {
        MemoryRegion region{};

        if (parse_readable_memory_region(line, region)) {
            regions.push_back(std::move(region));
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
    // Fast path: no memory pages should be scanned.
    if (max_pages == 0 || max_observations == 0) {
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
        return; // No readable regions or failed to read maps.
    }

    // Prioritize memory likely to contain runtime credentials.
    // The existing page and observation limits remain unchanged.
    prioritize_memory_regions(regions);

    MemoryReadBackend backend;
    if (!select_memory_read_backend(backend)) {
        if (pages_scanned) {
            *pages_scanned = 0;
        }
        return;
    }

    // One reader per scan: do not retain an mm_struct across execve().
    auto reader = open_memory_reader(pid, backend);
    if (!reader) {
        const int saved_errno = errno;
        Logger::log(LogLevel::Error,
            "Unable to open memory reader for pid=" + std::to_string(pid) +
            " backend=" + backend_name(backend) +
            " errno=" + std::to_string(saved_errno) +
            " (" + std::strerror(saved_errno) + ")");
        if (pages_scanned) {
            *pages_scanned = 0;
        }
        return;
    }

    // Compute total pages.
    size_t total_pages = 0;
    for (const auto& region : regions) {
        total_pages += (region.end - region.start + 4095) / 4096;
    }
    Logger::log(LogLevel::Debug,
                "Memory reader=" + std::string(backend_name(backend)) +
                "; total readable pages=" + std::to_string(total_pages) +
                "; max_pages=" + std::to_string(max_pages));

    // Retain 4 KiB extraction chunks to avoid changing secret-recognition
    // behavior while introducing an alternative memory-read mechanism.
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
        while (address < region.end && found < max_observations && scanned < max_pages) {
            size_t to_read = std::min<size_t>(chunk_size, region.end - address);

            const ssize_t n = reader->read(static_cast<std::uintptr_t>(address), buffer.data(), to_read);
            if (n <= 0) {
                const int saved_errno = (n < 0) ? errno : 0;
                Logger::log(LogLevel::Debug,
                    "Memory read failed at address=" + std::to_string(address) +
                    " backend=" + backend_name(backend) +
                    " errno=" + std::to_string(saved_errno) +
                    " (" + (n < 0 ? std::strerror(saved_errno) : "EOF") + ")");
                address += 4096; // Skip inaccessible page.
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

        // Recognize user:password arguments without fingerprinting
        // the username as part of the credential.
        auto emit_user_password = [&](const std::string& value) -> bool {
            const size_t colon = value.find(':');

            if (colon == std::string::npos ||
                (colon + 1) > value.size()) {
                return true;
            }

            return emit("password=" + value.substr(colon + 1));
        };

        if ((args[i] == "-u" ||
            args[i] == "--user" ||
            args[i] == "--proxy-user") &&
            (i + 1) < args.size()) {

            if (!emit_user_password(args[i+1])) {
                return;
            }
        }

        for (const char* prefix : {"--user=", "--proxy-user="}) {
            const std::string p(prefix);

            if (args[i].compare(0, p.size(), p) == 0) {
                if (!emit_user_password(args[i].substr(p.size()))) {
                    return;
                }
            }
        }

        for (const auto& [flag, keyword] : credential_flags) {
            if (args[i] == flag && (i + 1) < args.size()) {
                std::string synthesized = keyword + "=" + args[i + 1];
                if (!emit(synthesized)) {
                    return;
                }
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
