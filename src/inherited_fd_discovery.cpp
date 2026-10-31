
/**
 * @file    inherited_fd_discovery.cpp
 * @brief   Discovers pre-existing Linux process file descriptors.
 *
 * @author  Peter Magram
 * @date    2026-10-31
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

#include "inherited_fd_discovery.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>

namespace runtimexray {

namespace {

/**
 * @brief Parse a numeric /proc/<pid>/fd directory entry.
 *
 * Rejects non-numeric names, negative numbers and overflow.
 */
bool parse_fd_number(const char* name, int& fd)
{
    if (!name || !*name) {
        return false;
    }

    // numeric only
    for (const char *p = name; *p; ++p) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }

    errno = 0;
    char *end = nullptr;
    const long value = std::strtol(name, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value < 0 || value > INT_MAX) {
        return false;
    }

    fd = static_cast<int>(value);
    return true;
}

/**
 * @brief Read the symbolic target of /proc/<pid>/fd/<fd>.
 *
 * Does not open or duplicate the target descriptor.
 */
bool read_fd_target(const std::string& path, std::string& target) {
    std::array<char, 4096> buffer{};

    const ssize_t length = ::readlink(path.c_str(), buffer.data(), buffer.size());
    if (length < 0 || static_cast<size_t>(length) == buffer.size()) {
        return false;
    }

    target.assign(buffer.data(), static_cast<size_t>(length));
    return true;
}

/**
 * @brief Read descriptor flags from /proc/<pid>/fdinfo/<fd>.
 *
 * The flags field is octal and includes the current
 * close-on-exec descriptor flag on modern Linux kernels.
 *
 * Missing or malformed flags must not silently become zero.
 */
bool read_fd_flags(const std::string& path, uint64_t& flags)
{
    std::ifstream input(path);
    if (!input.is_open()) {
        return false;
    }

    std::string line;

    while (std::getline(input, line)) {
        if (line.compare(0, 6, "flags:") != 0) {
            continue;
        }

        std::istringstream parser(line.substr(6));

        uint64_t parsed_flags = 0;
        parser >> std::oct >> parsed_flags;

        if (!parser) {
            return false;
        }

        parser >> std::ws;

        if (!parser.eof()) {
            return false;
        }

        flags = parsed_flags;
        return true;
    }

    return false;
}

/**
 * @brief Classify the descriptor using its /proc symlink target.
 *
 * The target string is used only for classification.
 * It is not exported as a source path.
 */
std::string classify_fd_type(const std::string& target)
{
    if (target.compare(0, 6, "pipe:[") == 0) {
        return "pipe";
    }

    if (target.compare(0, 8, "socket:[") == 0) {
        return "socket";
    }

    if (!target.empty() && target.front() == '/') {
        return "file";
    }

    return "unknown";
}

/**
 * @brief Determine descriptor access mode from fdinfo flags.
 */
std::string classify_fd_role(uint64_t flags)
{
#ifdef O_PATH
    if ((flags & O_PATH) == O_PATH) {
        return "unknown";
    }
#endif

    switch (flags & O_ACCMODE) {
        case O_RDONLY:
            return "read";

        case O_WRONLY:
            return "write";

        case O_RDWR:
            return "readwrite";

        default:
            return "unknown";
    }
}

/**
 * @brief Extract a supported kernel-object identity from an FD target.
 *
 * Linux /proc/<pid>/fd/<fd> symlinks can expose identities such as:
 *
 *   pipe:[123456]
 *   socket:[789012]
 *
 * We intentionally do not use file paths as kernel-object identities:
 * different open file descriptions may refer to the same pathname.
 *
 * @param target Resolved readlink() target.
 * @return Kernel-object key, or empty when unsupported.
 */
std::string extract_kernel_object_key(const std::string& target)
{
    const bool is_pipe = target.compare(0, 6, "pipe:[") == 0;

    const bool is_socket = target.compare(0, 8, "socket:[") == 0;

    if (!is_pipe && !is_socket) {
        return {};
    }

    // Reject incomplete or malformed link targets.
    if (target.empty() || target.back() != ']') {
        return {};
    }

    const std::size_t prefix_size = is_pipe ? 6U : 8U;

    if (target.size() <= prefix_size + 1U) {
        return {};
    }

    for (std::size_t i = prefix_size; i + 1U < target.size(); ++i) {
        if (target[i] < '0' || target[i] > '9') {
            return {};
        }
    }

    return target;
}

/**
 * @brief Inspect one existing descriptor.
 *
 * If either the target or flags cannot be read, skip the
 * descriptor rather than returning misleading metadata.
 */
bool inspect_fd(pid_t tgid, int fd, InheritedFd& result)
{
    const std::string base = "/proc/" + std::to_string(tgid);

    const std::string fd_path = base + "/fd/" + std::to_string(fd);

    const std::string fdinfo_path = base + "/fdinfo/" + std::to_string(fd);

    std::string target;
    if (!read_fd_target(fd_path, target)) {
        return false;
    }

    uint64_t flags = 0;
    if (!read_fd_flags(fdinfo_path, flags)) {
        return false;
    }

    result.fd = fd;
    result.type = classify_fd_type(target);
    result.role = classify_fd_role(flags);
    result.cloexec = (flags & O_CLOEXEC) != 0;
    result.kernel_object_key = extract_kernel_object_key(target);

    return true;
}

} // anonymous namespace

/**
 * @brief Discover descriptors already open in a target process.
 *
 * Best-effort inspection: concurrent FD changes may cause
 * individual entries to disappear or be skipped.
 *
 * This function never opens, reads from, or duplicates a
 * target descriptor. It only accesses /proc metadata.
 *
 * No resource identities or causal relationships are assigned.
 */
std::vector<InheritedFd> discover_preexisting_fds(pid_t tgid)
{
    std::vector<InheritedFd> discovered;

    if (tgid <= 0) {
        return discovered;
    }

    const std::string directory_path = "/proc/" + std::to_string(tgid) + "/fd";

    auto close_directory = [](DIR* dir) noexcept {
        if (dir) {
            ::closedir(dir);
        }
    };

    using DirectoryPtr = std::unique_ptr<DIR, decltype(close_directory)>;

    DirectoryPtr directory(::opendir(directory_path.c_str()), close_directory);
    if (!directory) {
        return discovered;
    }

    while (dirent* entry = ::readdir(directory.get())) {
        int fd = -1;

        if (!parse_fd_number(entry->d_name, fd)) {
            continue;
        }

        InheritedFd descriptor;

        if (inspect_fd(tgid, fd, descriptor)) {
            discovered.push_back(std::move(descriptor));
        }
    }

    std::sort(
        discovered.begin(),
        discovered.end(),
        [](const InheritedFd& a, const InheritedFd& b) {
            return a.fd < b.fd;
        }
    );

    return discovered;
}

} // namespace runtimexray