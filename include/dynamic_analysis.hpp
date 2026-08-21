/**
 * @file    dynamic_analysis.hpp
 * @brief   Helper functions for dynamic analysis: data sanitization, sensitive keyword detection, sockaddr parsing.
 *
 * @author  Peter Magram
 * @date    2026-08-20
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

#ifndef RUNTIMEXRAY_DYNAMIC_ANALYSIS_HPP
#define RUNTIMEXRAY_DYNAMIC_ANALYSIS_HPP

#include "finding.hpp"
#include <optional>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace runtimexray {

    /**
     * @brief Determines the severity of a file path based on known sensitive locations.
     * @param path File path to evaluate.
     * @return FindingSeverity if the path is sensitive, otherwise std::nullopt.
     */
    std::optional<FindingSeverity> get_sensitive_path_severity(const std::string& path);

    // Cleaning binary data: printable characters remain, others are replaced with '.'
    std::string sanitize_data(const std::vector<std::byte>& data, size_t max_len = 128);

    // Checks whether the string contains sensitive keywords (passwords, secrets, etc.)
    bool contains_sensitive_keyword(const std::string& text);

    /**
     * @brief Проверяет, указывает ли путь на конфиденциальный файл или каталог.
     */
    bool is_sensitive_path(const std::string& path);
    
    // Разбирает sockaddr (IPv4/IPv6) в IP-строку и порт
    struct ParsedSockaddr {
        std::string ip;
        uint16_t port = 0;
        bool valid = false;
    };

    ParsedSockaddr parse_sockaddr(const std::vector<std::byte>& data);

} // namespace runtimexray

#endif // RUNTIMEXRAY_DYNAMIC_ANALYSIS_HPP