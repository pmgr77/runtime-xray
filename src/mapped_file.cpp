/**
 * @file    mapped_file.cpp
 * @brief   Implements memory mapping via mmap with RAII.
 *
 * @author  Peter Magram
 * @date    2026-08-12
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

#include "mapped_file.hpp"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>

namespace runtimexray {
    MappedFile::MappedFile(const std::string& path) {
        int fd = ::open(path.c_str(), O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("Cannot open file " + path + std::strerror(errno));
        }

        struct stat st;
        if (::fstat(fd, &st) == -1) {
            ::close(fd);
            throw std::runtime_error("Cannot stat file " + path + std::strerror(errno));
        }

        if (st.st_size == 0) {
            ::close(fd);
            // Empty file is valid but has no data – leave data_ = nullptr, size_ = 0
            return;
        }

        void* ptr = ::mmap(nullptr, static_cast<std::size_t>(st.st_size),
                            PROT_READ, MAP_PRIVATE, fd, 0);
        ::close(fd); // fd can be closed after mmap

        if (ptr == MAP_FAILED) {
            throw std::runtime_error("mmap failed for " + path + std::strerror(errno));
        }

        m_data = static_cast<const std::byte*>(ptr);
        m_size = static_cast<std::size_t>(st.st_size);
    }

    MappedFile::MappedFile(MappedFile&& other) noexcept :
        m_data(other.m_data), m_size(other.m_size) {
            other.m_data = nullptr;
            other.m_size = 0;
    }

    MappedFile::~MappedFile() {
        if (m_data && m_size > 0) {
            ::munmap(const_cast<std::byte*>(m_data), m_size);
        }
    }

    MappedFile& MappedFile::operator=(MappedFile&& other) noexcept {
        if (this != &other) {
            // Destroy current mapping
            if (m_data && m_size > 0) {
                ::munmap(const_cast<std::byte*>(m_data), m_size);
            }
            // Transfer ownership
            m_data = other.m_data;
            m_size = other.m_size;
            other.m_data = nullptr;
            other.m_size = 0;
        }
        return *this;
    }
} // namespace runtimexray