/**
 * @file    logger.cpp
 * @brief   Implementation of the runtime logger.
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

#include "logger.hpp"
#include <chrono>
#include <iomanip>
#include <iostream>

namespace runtimexray {

// Static members
LogLevel Logger::current_level_ = LogLevel::Info;
std::unique_ptr<std::ofstream> Logger::file_stream_;
std::mutex Logger::mutex_;
bool Logger::show_secrets_ = false;

// Helper to convert string to LogLevel
LogLevel parse_log_level(const std::string& s) {
    if (s == "error") return LogLevel::Error;
    if (s == "warn")  return LogLevel::Warning;
    if (s == "debug") return LogLevel::Debug;
    if (s == "trace") return LogLevel::Trace;
    return LogLevel::Info;
}

static std::string log_level_to_str(LogLevel level) {
    switch (level) {
        case LogLevel::Error:   return "ERROR";
        case LogLevel::Warning: return "WARN";
        case LogLevel::Info:    return "INFO";
        case LogLevel::Debug:   return "DEBUG";
        case LogLevel::Trace:   return "TRACE";
        default: return "INFO";
    }
}

void Logger::init(LogLevel level, const std::string& file, bool show_secrets) {
    current_level_ = level;
    show_secrets_ = show_secrets;
    if (!file.empty()) {
        file_stream_ = std::make_unique<std::ofstream>(file); 
    }
}

void Logger::log(LogLevel level, const std::string& msg) {
    if (level > current_level_) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostream* out = file_stream_ ? file_stream_.get() : &std::cerr;
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::string level_str = log_level_to_str(level);
    *out << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
         << " [" << level_str << "] " << msg << "\n";
    out->flush();
}

void Logger::log_sensitive(LogLevel level,
                           const std::string& safe_message,
                           const std::string& sensitive_message) {
    if (!is_enabled(level)) {
        return;
    }
    bool disclosure_allowed = show_secrets_ && (level == LogLevel::Debug || level == LogLevel::Trace);
    log(level, disclosure_allowed ? sensitive_message : safe_message);
}

bool Logger::is_enabled(LogLevel level) {
    return level <= current_level_;
}

} // namespace runtimexray