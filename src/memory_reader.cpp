/**
 * @file    memory_reader.cpp
 * @brief   Linux implementations of backend-independent process memory reads.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "memory_reader.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <new>

#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

namespace runtimexray {

namespace {

/**
 * Validate common read arguments before crossing into the kernel.
 * Zero-length requests are handled by the reader itself.
 */
bool valid_read_request(std::uintptr_t address, const void* destination, std::size_t size) noexcept
{
    if (destination == nullptr) {
        errno = EINVAL;
        return false;
    }

    if (size > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max())) {
        errno = EINVAL;
        return false;
    }

    // A wrapped virtual range must never silently address low memory.
    if (address > (std::numeric_limits<std::uintptr_t>::max() - (size - 1))) {
        errno = EOVERFLOW;
        return false;
    }

    return true;
}

class ProcessVmMemoryReader final : public MemoryReader {
public:
    explicit ProcessVmMemoryReader(pid_t pid) noexcept : pid_(pid) {}

    ssize_t read(std::uintptr_t address, void* destination, std::size_t size) noexcept override
    {
        if (size == 0) {
            return 0;
        }
        if (!valid_read_request(address, destination, size)) {
            return -1;
        }

        struct iovec local{};
        local.iov_base = destination;
        local.iov_len = size;

        struct iovec remote{};
        remote.iov_base = reinterpret_cast<void*>(address);
        remote.iov_len = size;

        // A read-only process_vm_readv() can cause COW unsharing on Linux.
        // Selecting this backend is an explicit caller decision.
        return ::process_vm_readv(pid_, &local, 1, &remote, 1, 0);
    }

private:
    pid_t pid_;
};

class ProcMemMemoryReader final : public MemoryReader {
public:
    explicit ProcMemMemoryReader(int fd) noexcept : fd_(fd) {}

    ~ProcMemMemoryReader() override
    {
        // close() cannot be retried safely after EINTR; never throw here.
        (void)::close(fd_);
    }

    ssize_t read(std::uintptr_t address, void* destination, std::size_t size) noexcept override
    {
        if (size == 0) {
            return 0;
        }
        if (!valid_read_request(address, destination, size)) {
            return -1;
        }

        // pread() uses a signed offset; reject addresses that cannot be
        // represented without truncation. The reader never seeks the fd.
        const auto max_offset = static_cast<std::uintmax_t>(std::numeric_limits<off_t>::max());

        if (static_cast<std::uintmax_t>(address) > max_offset ||
            static_cast<std::uintmax_t>(size - 1) > (max_offset - static_cast<std::uintmax_t>(address))) {
            errno = EOVERFLOW;
            return -1;
        }

        return ::pread(fd_, destination, size, static_cast<off_t>(address));
    }

private:
    int fd_;
};

} // namespace

std::unique_ptr<MemoryReader> open_memory_reader(pid_t pid, MemoryReadBackend backend)
{
    if (pid <= 0) {
        errno = EINVAL;
        return nullptr;
    }

    switch (backend) {
        case MemoryReadBackend::ProcessVmReadv: {
            auto* reader = new (std::nothrow) ProcessVmMemoryReader(pid);
            if (reader == nullptr) {
                errno = ENOMEM;
            }
            return std::unique_ptr<MemoryReader>(reader);
        }

        case MemoryReadBackend::ProcMem: {
            char path[64];
            const int length = std::snprintf(path, sizeof(path), "/proc/%ld/mem", static_cast<long>(pid));
            if (length < 0 || static_cast<std::size_t>(length) >= sizeof(path)) {
                errno = ENAMETOOLONG;
                return nullptr;
            }

            // Opening for each scan avoids retaining the old mm across execve().
            const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                return nullptr;  // open() supplied errno
            }

            auto* reader = new (std::nothrow) ProcMemMemoryReader(fd);
            if (reader == nullptr) {
                const int saved_errno = ENOMEM;
                (void)::close(fd);
                errno = saved_errno;
                return nullptr;
            }
            return std::unique_ptr<MemoryReader>(reader);
        }
    }

    errno = EINVAL;
    return nullptr;
}

} // namespace runtimexray
