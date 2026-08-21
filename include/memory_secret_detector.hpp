/**
 * @file    memory_secret_detector.hpp
 * @brief   Detectors for secrets in memory chunks.
 *
 * @author  Peter Magram
 * @date    2026-08-21
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

#ifndef RUNTIMEXRAY_MEMORY_SECRET_DETECTOR_HPP
#define RUNTIMEXRAY_MEMORY_SECRET_DETECTOR_HPP

#include <string>
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

    /**
     * @brief Detects secrets in a chunk of memory.
     * @param chunk Memory contents as a string (may contain binary data).
     * @return Vector of SecretMatch objects found.
     */
    virtual std::vector<SecretMatch> detect(const std::string& chunk) const = 0;
};

/**
 * @brief Detector for password-like key-value pairs (password=..., api_key=..., etc.).
 */
class PasswordDetector : public MemorySecretDetector {
public:
    std::vector<SecretMatch> detect(const std::string& chunk) const override;
};

/**
 * @brief Detector for PEM private key markers (-----BEGIN ... PRIVATE KEY-----).
 */
class PrivateKeyDetector : public MemorySecretDetector {
public:
    std::vector<SecretMatch> detect(const std::string& chunk) const override;
};

/**
 * @brief Runs all detectors and returns combined results.
 * @param chunk Memory chunk to scan.
 * @return Vector of SecretMatch objects.
 */
std::vector<SecretMatch> detect_secrets_in_chunk(const std::string& chunk);

} // namespace runtimexray

#endif // RUNTIMEXRAY_MEMORY_SECRET_DETECTOR_HPP