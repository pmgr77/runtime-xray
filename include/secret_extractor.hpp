/**
 * @file    secret_extractor.hpp
 * @brief   Extracts sensitive values from raw byte buffers as Data observations.
 *
 * Secret extraction is evidence collection, not security reporting.
 *
 * The extractor identifies values such as passwords and private keys,
 * fingerprints their exact bytes, and produces ObservationType::Data
 * observations suitable for insertion into a LineageGraph.
 *
 * It never creates Findings.
 *
 * @author  Peter Magram
 * @date    2026-10-10
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

#ifndef RUNTIMEXRAY_SECRET_EXTRACTOR_HPP
#define RUNTIMEXRAY_SECRET_EXTRACTOR_HPP

#include "lineage.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace runtimexray {

/**
 * @brief Extract secret-related Data observations from raw content.
 *
 * process_instance_id and exec_generation are intentionally not assigned
 * here. The caller attaching these observations to a completed LineageGraph
 * owns execution identity resolution.
 *
 * @param data Raw bytes represented as a string.
 * @param location Evidence source such as "memory", "cmdline", "environment",
 *                 "read", "sendto_data", etc.
 * @param pid Linux task/process from which the bytes were observed.
 * @param base_address Optional target-process address corresponding to data[0].
 *
 * @return Zero or more Data observations.
 */
std::vector<Observation> extract_secret_observations(
    const std::string& data,
    const std::string& location,
    pid_t pid,
    uintptr_t base_address = 0);

} // namespace runtimexray

#endif // RUNTIMEXRAY_SECRET_EXTRACTOR_HPP