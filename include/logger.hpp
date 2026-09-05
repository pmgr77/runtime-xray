/**
 * @file    logger.hpp
 * @brief   Simple runtime logger with levels and optional file output.
 *
 * @author  Peter Magram
 * @date    2026-08-29
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

#ifndef RUNTIMEXRAY_LOGGER_HPP
#define RUNTIMEXRAY_LOGGER_HPP

#include <iostream>
#include <mutex>
#include <string>
#include <fstream>
#include <memory>

namespace runtimexray {

enum class LogLevel {
    Error,
    Warning,
    Info,
    Debug,
    Trace
};

/**
 * @brief Converts a string to LogLevel (case-insensitive).
 * @param s String like "error", "warn", "info", "debug", "trace".
 * @return Corresponding LogLevel; defaults to Info on unknown.
 */
LogLevel parse_log_level(const std::string& s);

/**
 * @brief Global logger.
 *
 * Logs to stderr by default, or to a file if a path is provided.
 * All methods are thread-safe.
 */
class Logger {
public:
    /**
     * @brief Initialise the logger with a minimum level and optional file.
     * @param level Minimum level to log.
     * @param file Path to log file (empty = stderr).
     * @param show_secrets If true, log sensitive data; otherwise redact.
     */
    static void init(LogLevel level, const std::string& file = "", bool show_secrets = false);

    /**
     * @brief Log a message at a given level.
     * @param level Severity level.
     * @param msg Message to log.
     */
    static void log(LogLevel level, const std::string& msg);

    /**
     * @brief Log a sensitive message at a given level.
     * @param level Severity level.
     * @param safe_message Message to log (safe version).
     * @param sensitive_message Message to log (sensitive version).
     */
    static void log_sensitive(LogLevel level,
                              const std::string& safe_message,
                              const std::string& sensitive_message);

    /**
     * @brief Check if a level is enabled.
     * @param level Level to check.
     * @return true if messages at this level will be logged.
     */
    static bool is_enabled(LogLevel level);

private:
    static LogLevel current_level_;
    static std::unique_ptr<std::ofstream> file_stream_;
    static std::mutex mutex_;
    static bool show_secrets_;
};
    
} // namespace runtimexray

#endif // RUNTIMEXRAY_LOGGER_HPP