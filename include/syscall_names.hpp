/**
 * @file    syscall_names.hpp
 * @brief   Architecture-specific system call name mapping.
 *
 * @author  Peter Magram
 * @date    2026-08-20
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

#ifndef RUNTIMEXRAY_SYSCALL_NAMES_HPP
#define RUNTIMEXRAY_SYSCALL_NAMES_HPP

namespace runtimexray {

// Return a human-readable name for a syscall number on x86_64.
const char* syscall_name_x86_64(long num);

// Return a human-readable name for a syscall number on ARM64.
const char* syscall_name_arm64(long name);

// Return the correct name depending on the current architecture.
inline const char* syscall_name(long num)
{
#if defined(__x86_64__)
    return syscall_name_x86_64(num);
#elif defined(__aarch64__)
    return syscall_name_arm64(num);
#else
    (void)num;
    return "unknown";
#endif    
}

bool is_interesting_syscall(long num);

} // namespace RuntimeXray

#endif // RUNTIMEXRAY_SYSCALL_NAMES_HPP