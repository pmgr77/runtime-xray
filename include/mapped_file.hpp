/**
 * @file    mapped_file.hpp
 * @brief   RAII wrapper for memory-mapped files.
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

#ifndef RUNTIMEXRAY_MAPPED_FILE_HPP
#define RUNTIMEXRAY_MAPPED_FILE_HPP

#include <cstddef>
#include <string>

namespace runtimexray {

/**
 * @brief RAII wrapper for a memory-mapped file (mmap).
 *
 * Owns the mapped region and unmaps it when the MappedFile is destroyed.
 * Supports move semantics but not copy.
 */
class MappedFile {
public:
    /** 
     * @brief Default C-tor.
     */
    MappedFile() = default;

    /**
     * @brief Maps a file into memory (read-only, private).
     * @param path Path to the file.
     * @throws std::runtime_error if the file cannot be opened or mapped.
     */
    explicit MappedFile(const std::string& path);

    /**
     * @brief D-tor.
     */
    ~MappedFile();

    // Movable, not copyable
    MappedFile(MappedFile&& other) noexcept;
    MappedFile& operator=(MappedFile&& other) noexcept;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    /** @return Pointer to the beginning of the mapped data. */
    const std::byte* data() const noexcept { return m_data; }

    /** @return Size of the mapped region in bytes. */
    std::size_t size() const noexcept { return m_size; }

    /** @return true if the file is successfully mapped. */
    bool is_valid() const noexcept { return m_data != nullptr; }

private:
    const std::byte* m_data = nullptr; 
    std::size_t m_size = 0;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_MAPPED_FILE_HPP
