/**
 * @file    memory_secret_detector.hpp
 * @brief   Detectors for secrets in memory chunks.
 *
 * @author  Peter Magram
 * @date    2026-08-21
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

#ifndef RUNTIMEXRAY_MEMORY_SECRET_DETECTOR_HPP
#define RUNTIMEXRAY_MEMORY_SECRET_DETECTOR_HPP

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace runtimexray {

/**
 * @brief Represents a matched secret fragment in a memory chunk.
 */
struct SecretMatch {
    std::string secret_type;    ///< e.g., "password", "private_key", "token"
    std::string snippet;        ///< Extracted context around the secret
    std::string description;    ///< Human-readable description
};

/**
 * @brief Interface for memory secret detectors.
 */
class MemorySecretDetector {
public:
    virtual ~MemorySecretDetector() = default;

    /** @return Unique detector name, e.g. "password", "private_key". */
    virtual std::string name() const = 0;

    /** @return Short human-readable description. */
    virtual std::string description() const = 0;

    /**
     * @brief Detects secrets in a chunk of memory.
     * @param chunk Memory contents as a string (may contain binary data).
     * @return Vector of SecretMatch objects found.
     */
    virtual std::vector<SecretMatch> detect(const std::string& chunk) const = 0;

};

/**
 * @brief Registry for memory secret detectors.
 *
 * Built-in detectors are registered automatically.
 * Users can add custom detectors, remove them, or disable
 * existing ones by name.
 */
class DetectorRegistry {
public:
    static DetectorRegistry& instance();

    /** @brief Registers a new detector. Takes ownership. */
    void register_detector(std::unique_ptr<MemorySecretDetector> detector);

    /** @brief Unregisters and deletes a detector by name. */
    void unregister_detector(const std::string& name);

    /** @brief Disables a detector by name (keeps it but skips scanning). */
    void disable_detector(const std::string& name);

    /** @brief Re-enables a previously disabled detector. */
    void enable_detector(const std::string& name);

    /** @brief Returns all active detectors (enabled and registered). */
    std::vector<const MemorySecretDetector*> active_detectors() const;
    
    /** @brief Returns a list of all registered detector names. */
    std::vector<std::string> list_detectors() const;

private:
    DetectorRegistry(); // Private constructor for singleton
    std::vector<std::unique_ptr<MemorySecretDetector>> detectors_;
    std::unordered_set<std::string> disabled_detectors_;
};

/**
 * @brief Runs all active detectors over a chunk and combines results.
 */
std::vector<SecretMatch> detect_secrets_in_chunk(const std::string& chunk);

} // namespace runtimexray

#endif // RUNTIMEXRAY_MEMORY_SECRET_DETECTOR_HPP