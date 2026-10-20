/**
 * @file    memory_reader.hpp
 * @brief   Backend-independent access to another Linux process's memory.
 *
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

#ifndef RUNTIMEXRAY_MEMORY_READER_HPP
#define RUNTIMEXRAY_MEMORY_READER_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <sys/types.h>

namespace runtimexray {

/**
 * @brief Mechanism used to read a tracee's virtual address space.
 *
 * Neither method is guaranteed to be side-effect-free. In particular,
 * process_vm_readv() can trigger COW unsharing on some Linux kernels.
 * Keep selection explicit so tests can compare behavior and overhead.
 */
enum class MemoryReadBackend {
    ProcessVmReadv,
    ProcMem
};

/**
 * @brief One read session for one target process address space.
 *
 * Instances are intentionally scoped to a memory scan, not cached by PID.
 * A successful execve() replaces the address space: a previously opened
 * /proc/<pid>/mem descriptor must not be reused for the new image.
 *
 * Implementations own any acquired kernel resources (for example, a
 * /proc/<pid>/mem file descriptor) and release them on destruction.
 *
 * This interface only transfers bytes. It does not select VMAs, count
 * pages, scan for secrets, or make lineage claims.
 */
class MemoryReader {
public:
    virtual ~MemoryReader() = default;

    MemoryReader(const MemoryReader&) = delete;
    MemoryReader& operator=(const MemoryReader&) = delete;

    /**
     * @brief Read up to size bytes from an address in the target process.
     *
     * Returns the number of bytes copied (which can be less than size),
     * or -1 on failure with errno set. A short read is not automatically
     * an error. A zero-length request returns zero.
     *
     * Callers must handle gaps, inaccessible mappings, partial reads,
     * and target exit independently of the chosen backend.
     */
    virtual ssize_t read(
        std::uintptr_t address,
        void* destination,
        std::size_t size) noexcept = 0;

protected:
    MemoryReader() = default;
};

/**
 * @brief Open a read session for a Linux process.
 *
 * The caller owns the returned reader. A null result means the session
 * could not be opened; errno describes the failure.
 *
 * A ProcMem reader opens /proc/<pid>/mem once per session; the other
 * reader uses process_vm_readv() for individual reads.
 *
 * Backend selection is explicit. This factory must not silently fall back
 * to a different backend, since access and COW behavior can differ.
 *
 * @note Declaration only; implementations will be introduced separately.
 */
std::unique_ptr<MemoryReader> open_memory_reader(
    pid_t pid,
    MemoryReadBackend backend);

} // namespace runtimexray

#endif // RUNTIMEXRAY_MEMORY_READER_HPP
