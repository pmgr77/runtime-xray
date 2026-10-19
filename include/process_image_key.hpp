
/**
 * @file    process_image_key.hpp
 * @brief   Defines stable identity for a process executable image.
 *
 * A process image is identified by a RuntimeXRay process instance
 * and an executable-image generation.
 *
 * This identity is independent of memory scanning, tracing
 * backends, and individual Linux task IDs.
 *
 * Components may use it to associate state with a particular
 * process address-space lifetime, including scan budgets and
 * runtime observations.
 *
 * @author  Peter Magram
 * @date    2026-10-19
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

#ifndef RUNTIMEXRAY_PROCESS_IMAGE_KEY_HPP
#define RUNTIMEXRAY_PROCESS_IMAGE_KEY_HPP

#include <cstdint>

namespace runtimexray {

/**
 * @brief Identity of an observed process executable image.
 *
 * A Linux PID or TGID alone cannot uniquely identify a process
 * throughout a trace because the operating system may reuse IDs.
 *
 * RuntimeXRay therefore assigns a monotonically increasing
 * process_instance_id to each observed process lifetime.
 *
 * A successful exec replaces the executable image and advances
 * exec_generation without changing process_instance_id.
 *
 * Multiple threads within the same process share this identity.
 *
 * The value {0, 0} is not a valid assigned process image because
 * process_instance_id == 0 means the instance is unassigned.
 *
 * @note This key identifies RuntimeXRay's model of an executable
 *       image. It does not independently verify that two Linux
 *       tasks have distinct physical memory mappings.
 */
struct ProcessImageKey {
    uint64_t process_instance_id = 0;
    uint64_t exec_generation = 0;

    /**
     * @brief Compare identities for equality.
     *
     * Both the process instance and executable generation must
     * match for two identities to be equal.
     *
     * @param other Identity to compare with.
     * @return True if both identities are identical.
     */
    bool operator==(const ProcessImageKey& other) const noexcept
    {
        return process_instance_id == other.process_instance_id &&
               exec_generation == other.exec_generation;
    }

    /**
     * @brief Compare identities for inequality.
     *
     * @param other Identity to compare with.
     * @return True if the identities differ.
     */
    bool operator!=(const ProcessImageKey& other) const noexcept
    {
        return !(*this == other);
    }

    /**
     * @brief Establish strict ordering between process images.
     *
     * Uses lexicographical ordering:
     *
     * 1. process_instance_id
     * 2. exec_generation
     *
     * The ordering is suitable for std::map and std::set.
     *
     * @param other Identity to compare with.
     * @return True if this identity precedes other.
     */
    bool operator<(const ProcessImageKey& other) const noexcept
    {
        if (process_instance_id != other.process_instance_id) {
            return process_instance_id < other.process_instance_id;
        }

        return exec_generation < other.exec_generation;
    }

    /**
     * @brief Check whether the process instance is assigned.
     *
     * Generation zero is valid: it represents the initial
     * observed executable image.
     *
     * @return True if the process-instance ID is nonzero.
     */
    bool is_valid() const noexcept
    {
        return process_instance_id != 0;
    }
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_PROCESS_IMAGE_KEY_HPP
