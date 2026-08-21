/**
 * @file    finding.hpp
 * @brief   Defines the data structures for security findings in RuntimeXRay.
 *
 * @author  Peter Magram
 * @date    2026-08-15
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
#ifndef RUNTIMEXRAY_FINDING_HPP
#define RUNTIMEXRAY_FINDING_HPP

#include <string>
#include <variant>
#include <vector>
#include <cstdint>

namespace runtimexray {

/**
* @brief Severity level of a security finding.
*/
enum class FindingSeverity {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Info = 4
};

/**
 * @brief Details specific to a binary hardening finding (NX, PIE, RELRO, Canary).
 */
struct HardeningFindingDetails {
    std::string feature; /**< Name of the hardening feature, e.g., "NX", "PIE", "RELRO", "Canary". */
    std::string status; /**< Current status, e.g., "Disabled", "Enabled", "Partial", "Full". */
};

struct DangerousApiFindingDetails {
    std::string api;
    std::string reason;
    std::string recommendation;
    std::string cwe_id; // Common Weakness Enumeration identifier
};

// ----- Dynamic analysis findings -----

struct SensitiveFileAccessDetails {
    std::string path;
    std::string reason;
};

struct NetworkConnectionDetails {
    std::string remote_addr;
    uint16_t port;
    std::string reason;
};

struct SensitiveDataWriteDetails {
    std::string data_snippet;
    std::string reason;
};

struct MemorySecretFindingDetails {
    std::string snippet;      // extracted fragment
    std::string secret_type;  // e.g., "password", "private_key"
    std::string location;     // "memory", "cmdline", "environment"
};

// Variant type for all possible finding details
using DetailsVariant = std::variant<
    HardeningFindingDetails,
    DangerousApiFindingDetails,
    SensitiveFileAccessDetails,
    NetworkConnectionDetails,
    SensitiveDataWriteDetails,
    MemorySecretFindingDetails
>;

/**
 * @brief Represents a single security finding.
 *
 * Contains common metadata (severity, description, evidence) and specific details
 * stored in a std::variant. Additional detail types can be added later.
 */
class Finding {
public:
    FindingSeverity severity;
    std::string description;
    std::string evidence;
    DetailsVariant details;

    /**
     * @brief Constructs a Finding.
     * @param sev Severity level.
     * @param desc Human-readable description of the finding.
     * @param ev Evidence supporting the finding.
     * @param det Specific details (variant).
     */
    Finding(FindingSeverity sev, std::string desc, std::string ev, DetailsVariant det)
    : severity(sev), description(std::move(desc)), evidence(std::move(ev)), details(std::move(det)) 
    {}
};
    
    /** Container for all findings from a single analysis. */
    using FindingList = std::vector<Finding>;

} // namespace runtimexray

#endif // RUNTIMEXRAY_FINDING_HPP