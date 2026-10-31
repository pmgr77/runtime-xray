/**
 * @file    inherited_fd_discovery.hpp
 * @brief   Discovers already-open Linux process file descriptors.
 *
 * @author  Peter Magram
 * @date    2026-10-31
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 *
 * Copyright 2026 Peter Magram
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RUNTIMEXRAY_INHERITED_FD_DISCOVERY_HPP
#define RUNTIMEXRAY_INHERITED_FD_DISCOVERY_HPP

#include <sys/types.h>

#include <string>
#include <vector>

namespace runtimexray {

/**
 * @brief Metadata for an already-open process descriptor.
 *
 * Describes an observed descriptor state, not the syscall
 * that originally created it.
 *
 * "Inherited" means pre-existing at the observation boundary.
 * It does not prove inheritance from a parent process.
 *
 * This structure does not establish relationships between
 * processes or prove data flow.
 */
struct InheritedFd {
    int fd = -1;

    // "pipe", "socket", "file", or "unknown".
    std::string type;

    // "read", "write", "readwrite", or "unknown".
    std::string role;

    // Whether the descriptor has FD_CLOEXEC.
    bool cloexec = false;

    // Kernel object identity observed through /proc/<pid>/fd/<fd>.
    //
    // Examples:
    //   "pipe:[123456]"
    //   "socket:[789012]"
    //
    // Empty for regular files and unsupported descriptor types.
    //
    // This is an observation-time identity hint, not a permanent
    // resource ID or evidence of data flow. Kernel inode numbers
    // can be reused after a resource is destroyed.
    std::string kernel_object_key;
};

/**
 * @brief Discover pre-existing descriptors through /proc/<tgid>/fd.
 *
 * Uses:
 *   /proc/<tgid>/fd/<fd>     - descriptor target/type
 *   /proc/<tgid>/fdinfo/<fd> - access flags and CLOEXEC
 *
 * Does not modify target descriptors or their file offsets.
 * Does not duplicate or open target resources.
 *
 * Results represent a best-effort snapshot. Individual FDs may
 * disappear or change while inspection is taking place.
 *
 * Does not return resolved file paths or descriptor contents.
 *
 * @param tgid Linux thread-group ID of the target process.
 * @return Discovered descriptor metadata; empty if unavailable.
 */
std::vector<InheritedFd> discover_preexisting_fds(pid_t tgid);

} // namespace runtimexray

#endif // RUNTIMEXRAY_INHERITED_FD_DISCOVERY_HPP