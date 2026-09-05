
/**
 * @file    builtin_analyzers.cpp
 * @brief   Implementation of built-in analyzers.
 *
 * @author  Peter Magram
 * @date    2026-08-24
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

#include "builtin_analyzers.hpp"
#include "ianalyzer.hpp"
#include "evidence.hpp"
#include "finding.hpp"
#include "elf_parser.hpp"
#include "secret_fingerprinter.hpp"
#include "logger.hpp"

#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace runtimexray {


namespace {

// ---------------------------------------------------------------------------
// Helper functions for dangerous API detection
// ---------------------------------------------------------------------------

// Strip version suffix from a symbol name (e.g., "strcpy@GLIBC_2.2.5" -> "strcpy")
std::string strip_symbol_version(const std::string& name) {
    auto pos = name.find('@');
    if (pos != std::string::npos) {
        return name.substr(0, pos);
    }
    return name;
}

struct ApiRiskInfo {
    FindingSeverity severity;
    std::string description;
    std::string recommendation;
    std::string cwe_id;
};

std::optional<ApiRiskInfo> get_api_risk(const std::string& name) {
    // Unsafe string functions (buffer overflow)
    if (name == "strcpy" || name == "strcat" || name == "sprintf" || name == "vsprintf" ||
        name == "gets" || name == "scanf" || name == "sscanf") {
        return ApiRiskInfo{
            FindingSeverity::High,
            "Unsafe string function that does not check bounds or format.",
            "Use strncpy, snprintf, fgets, or std::string.",
            "CWE-119"
        };
    }
    if (name == "strncpy" || name == "strncat") {
        return ApiRiskInfo{
            FindingSeverity::Medium,
            "Potentially unsafe if null-termination is not ensured.",
            "Use explicit length checks or std::string.",
            "CWE-120"
        };
    }

    // Command execution
    if (name == "system" || name == "popen") {
        return ApiRiskInfo{
            FindingSeverity::High,
            "Potential command injection if input is not sanitized.",
            "Avoid shell interpretation; use exec* with argument arrays.",
            "CWE-78"
        };
    }

    // Insecure temporary files
    if (name == "mktemp" || name == "tmpnam" || name == "tempnam") {
        return ApiRiskInfo{
            FindingSeverity::Medium,
            "Predictable temporary file names may lead to symlink attacks.",
            "Use mkstemp or tmpfile.",
            "CWE-377"
        };
    }

    // Weak random
    if (name == "rand" || name == "random" || name == "srand") {
        return ApiRiskInfo{
            FindingSeverity::Medium,
            "Weak predictable random number generator.",
            "Use getrandom(), /dev/urandom, or std::random_device.",
            "CWE-338"
        };
    }

    // Weak crypto hashes
    if (name.find("MD5_") == 0 || name.find("SHA1_") == 0) {
        return ApiRiskInfo{
            FindingSeverity::High,
            "Weak cryptographic hash function (collisions).",
            "Use SHA-256 or stronger.",
            "CWE-327"
        };
    }

    // Weak encryption
    if (name.find("DES_") == 0 || name.find("RC4") == 0) {
        return ApiRiskInfo{
            FindingSeverity::High,
            "Weak encryption algorithm (known attacks).",
            "Use AES-GCM or ChaCha20-Poly1305.",
            "CWE-327"
        };
    }

    // Deprecated TLS
    if (name == "SSLv3_client_method" || name == "SSLv3_server_method" ||
        name == "TLSv1_client_method" || name == "TLSv1_server_method" ||
        name == "TLSv1_1_client_method" || name == "TLSv1_1_server_method") {
        return ApiRiskInfo{
            FindingSeverity::High,
            "Insecure TLS protocol version (deprecated).",
            "Use TLS 1.2 or TLS 1.3.",
            "CWE-326"
        };
    }

    // Memory functions
    if (name == "memcpy" || name == "memmove" || name == "memset") {
        return ApiRiskInfo{
            FindingSeverity::Low,
            "Memory function often misused (size calculation errors).",
            "Verify size arguments; use safer abstractions where possible.",
            "CWE-805"
        };
    }

    // alloca
    if (name == "alloca") {
        return ApiRiskInfo{
            FindingSeverity::Medium,
            "Non-standard stack allocation can lead to stack overflow.",
            "Use dynamic allocation or fixed-size arrays.",
            "CWE-770"
        };
    }

    // getopt
    if (name == "getopt" || name == "getopt_long") {
        return ApiRiskInfo{
            FindingSeverity::Info,
            "Argument parsing (not inherently dangerous, but misused can cause issues).",
            "Validate inputs and handle errors.",
            "CWE-20"
        };
    }

    // atoi
    if (name == "atoi" || name == "atol" || name == "atoll") {
        return ApiRiskInfo{
            FindingSeverity::Low,
            "Conversion functions without error checking.",
            "Use strtol/strtoul with end pointer validation.",
            "CWE-190"
        };
    }

    // strtok
    if (name == "strtok") {
        return ApiRiskInfo{
            FindingSeverity::Low,
            "Modifies input string and not thread-safe.",
            "Use strtok_r or std::string tokenization.",
            "CWE-366"
        };
    }

    // Network functions
    if (name == "gethostbyname" || name == "gethostbyaddr") {
        return ApiRiskInfo{
            FindingSeverity::Medium,
            "Obsolete and not thread-safe; returns static data.",
            "Use getaddrinfo()/getnameinfo().",
            "CWE-362"
        };
    }
    if (name == "inet_ntoa") {
        return ApiRiskInfo{
            FindingSeverity::Low,
            "Not thread-safe, uses static buffer.",
            "Use inet_ntop().",
            "CWE-362"
        };
    }

    return std::nullopt;
}
struct PasswordMatch {
    std::string keyword;
    std::string value;     // exact secret
    std::string snippet;   // surrounding context
};

// Password detector logic (moved from old PasswordDetector)
std::vector<PasswordMatch> detect_password_matches(const std::string& chunk) {
    std::vector<PasswordMatch> results;
    static const std::vector<std::string> keywords = {
        "password", "passwd", "pwd", "pass", "pswd",
        "password_hash", "password_salt", "password_encrypted",
        "hashed_password", "api_key", "secret", "token", "credentials", "credential"
    };

    for (const auto& kw : keywords) {
        size_t pos = 0;
        while ((pos = chunk.find(kw, pos)) != std::string::npos) {
            // Skip if keyword is part of a larger word
            if (pos > 0 &&
                (std::isalnum(static_cast<unsigned char>(chunk[pos - 1])) ||
                 chunk[pos - 1] == '_')) {
                pos += kw.size();
                continue;
            }

            size_t next = pos + kw.size();
            if (next < chunk.size() && (chunk[next] == '=' || chunk[next] == ':')) {
                size_t value_start = next + 1;
                while (value_start < chunk.size() && chunk[value_start] == ' ') {
                    ++value_start;
                }
                size_t value_end = value_start;
                const size_t max_val_len = 128;
                while (value_end < chunk.size() && (value_end - value_start) < max_val_len) {
                    char c = chunk[value_end];
                    if (c == '\0' || c == '\n' || c == '\r' || c == ',' || c == ';' ||
                        c == ' ') {
                        break;
                    }
                    ++value_end;
                }

                // Extract the exact secret value
                std::string value = chunk.substr(value_start, value_end - value_start);

                // Extract snippet (surrounding context)
                size_t snippet_start = (pos > 20) ? pos - 20 : 0;
                size_t snippet_len = std::min<size_t>(160, chunk.size() - snippet_start);
                std::string snippet = chunk.substr(snippet_start, snippet_len);
                // Clean non-printable
                for (char& c : snippet) {
                    if (c < 0x20 || c > 0x7E) c = '.';
                }
                // Only add if value is non-empty
                if (!value.empty()) {
                    results.emplace_back(PasswordMatch{kw, value, snippet});
                }

                pos = next;
            } else {
                pos = next;
            }
        }
    }
    return results;
}

struct PrivateKeyMatch {
    std::string value;    // full PEM block
    std::string snippet;  // same as value (or trimmed context)
    std::string type;     // e.g., "RSA PRIVATE KEY"
};

// Private key detector logic (moved from old PrivateKeyDetector)
std::vector<PrivateKeyMatch> detect_private_key_matches(const std::string& chunk) {
    std::vector<PrivateKeyMatch> matches;
    static const std::vector<std::string> begin_markers = {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----"
    };
    static const std::vector<std::string> end_markers = {
        "-----END RSA PRIVATE KEY-----",
        "-----END OPENSSH PRIVATE KEY-----",
        "-----END EC PRIVATE KEY-----",
        "-----END DSA PRIVATE KEY-----"
    };

    for (size_t i = 0; i < begin_markers.size(); ++i) {
        size_t pos = chunk.find(begin_markers[i]);
        if (pos != std::string::npos) {
            size_t start = pos;
            size_t end = chunk.find(end_markers[i], pos + begin_markers[i].size());
            size_t capture_len = (end != std::string::npos)
                                 ? (end - start + end_markers[i].size())
                                 : std::min<size_t>(256, chunk.size() - start);
            std::string snippet = chunk.substr(start, capture_len);
            for (char& c : snippet) {
                if (c < 0x20 || c > 0x7E) c = '.';
            }
            // Extract type from begin marker (e.g., "RSA PRIVATE KEY")
            std::string type = begin_markers[i];
            type = type.substr(11); // after "-----BEGIN "
            type = type.substr(0, type.size() - 5); // remove "-----"
            matches.push_back({snippet, snippet, type});
        }
    }
    return matches;
}

std::optional<FindingSeverity> get_sensitive_path_severity(const std::string& path) {
    // Critical: extremely sensitive files (e.g., sudoers, shadow)
    const std::vector<std::string> critical = {
        "/etc/sudoers", "/etc/shadow", "/root/", "/.ssh", ".ssh",
        ".aws/credentials", ".gnupg", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"
    };
    for (const auto& sub : critical) {
        if (path.find(sub) != std::string::npos) {
            return FindingSeverity::Critical;
        }
    }

    // High: files containing secrets or sensitive tokens
    const std::vector<std::string> high = {
        "secret", "token", "password", "credential", "api_key"
    };
    for (const auto& sub : high) {
        if (path.find(sub) != std::string::npos) {
            return FindingSeverity::High;
        }
    }

    // Medium: user/group databases, system configuration files
    const std::vector<std::string> medium = {
        "/etc/passwd", "/etc/group"
    };
    for (const auto& sub : medium) {
        if (path.find(sub) != std::string::npos) {
            return FindingSeverity::Medium;
        }
    }

    // Low: less sensitive but still interesting files
    const std::vector<std::string> low = {
        "/etc/hosts", "/etc/resolv.conf"
    };
    for (const auto& sub : low) {
        if (path.find(sub) != std::string::npos) {
            return FindingSeverity::Low;
        }
    }

    // Info: files that give basic system information
    const std::vector<std::string> info = {
        "/etc/hostname", "/etc/machine-id"
    };
    for (const auto& sub : info) {
        if (path.find(sub) != std::string::npos) {
            return FindingSeverity::Info;
        }
    }

    return std::nullopt;
}

} // anonymous namespace

class HardeningAnalyzer : public IAnalyzer {
public:
    std::string name() const override { return "hardening"; }
    std::string description() const override { return "Evaluates binary hardening features"; }
    AnalyzerCategory category() const override { return AnalyzerCategory::Static; }

    FindingList analyze(const Evidence& evidence) const override {
        FindingList findings;
        if (auto* h = std::get_if<HardeningEvidence>(&evidence)) {
            FindingSeverity severity = FindingSeverity::Info;  // Enabled/Full
            if (h->status == "Disabled") {
                severity = FindingSeverity::High;
            } else if (h->status == "Partial") {
                severity = FindingSeverity::Low;
            }

            findings.emplace_back(
                severity,
                h->feature + " is " + h->status,
                "Hardening property observed in binary",
                HardeningFindingDetails{h->feature, h->status}
            );
        }
        return findings;
    }
};

class DangerousApiAnalyzer : public IAnalyzer {
public:
    std::string name() const override { return "dangerous_api"; }
    std::string description() const override { return "Detects known dangerous imports"; }
    AnalyzerCategory category() const override { return AnalyzerCategory::Static; }

    FindingList analyze(const Evidence& evidence) const override {
        FindingList findings;
        if (auto* s = std::get_if<SymbolEvidence>(&evidence)) {
            std::string base = strip_symbol_version(s->symbol_name);
            auto risk = get_api_risk(base);
            if (risk) {
                findings.emplace_back(
                    risk->severity,
                    "Dangerous/obsolete API used: " + base,
                    "Imported symbol matches known dangerous API list.",
                    DangerousApiFindingDetails{base, risk->description, risk->recommendation, risk->cwe_id}
                );
            }
        }
        return findings;
    }
};

class SensitiveFileAnalyzer : public IAnalyzer {
public:
    std::string name() const override { return "sensitive_file"; }
    std::string description() const override { return "Flags access to sensitive files"; }
    AnalyzerCategory category() const override { return AnalyzerCategory::Dynamic; }

    FindingList analyze(const Evidence& evidence) const override {
        FindingList findings;
        if (auto* f = std::get_if<FileAccessEvidence>(&evidence)) {
            auto severity = get_sensitive_path_severity(f->path);
            if (severity) {
                findings.emplace_back(
                    *severity,
                    "Sensitive file access",
                    "Process attempted to open: " + f->path,
                    SensitiveFileAccessDetails{f->path, "Known sensitive path"}
                );
            }
        }
        return findings;
    }
};

class NetworkAnalyzer : public IAnalyzer {
public:
    std::string name() const override { return "network"; }
    std::string description() const override { return "Flags suspicious network connections"; }
    AnalyzerCategory category() const override { return AnalyzerCategory::Dynamic; }

    FindingList analyze(const Evidence& evidence) const override {
        FindingList findings;
        if (auto* n = std::get_if<NetworkEvidence>(&evidence)) {
            if (n->remote_port == 22 || n->remote_port == 3389 || n->remote_port == 445 ||
                n->remote_port == 1433 || n->remote_port == 3306) {
                findings.emplace_back(
                    FindingSeverity::Medium,
                    "Suspicious network connection",
                    "Connecting to " + n->remote_addr + ":" + std::to_string(n->remote_port),
                    NetworkConnectionDetails{n->remote_addr, n->remote_port, "Potentially sensitive port"}
                );
            }
        }
        return findings;
    }
};

class PasswordMemoryAnalyzer : public IAnalyzer {
public:
    std::string name() const override { return "memory_password"; }
    std::string description() const override { return "Detects password-like strings in memory"; }
    AnalyzerCategory category() const override { return AnalyzerCategory::Memory; }

    FindingList analyze(const Evidence& evidence) const override {
        FindingList findings;
        if (auto* m = std::get_if<MemoryChunkEvidence>(&evidence)) {
            auto matches = detect_password_matches(m->chunk);
            for (const auto& match : matches) {
                MemorySecretFindingDetails details;
                details.raw_secret = match.value;
                details.raw_snippet = match.snippet;
                try {
                    details.fingerprint = SecretFingerprinter::instance().fingerprint(match.value);
                } catch (const std::exception& e) {
                    Logger::log(LogLevel::Error, "Fingerprint computation failed: " + std::string(e.what()));
                    continue; // skip this finding
                }
                details.secret_type = match.keyword;
                details.secret_length = match.value.size();
                details.location = m->location;
                details.address = m->address;
                findings.emplace_back(
                    FindingSeverity::High,
                    "Sensitive data found in memory",
                    "Potential secret in memory: " + match.keyword,
                    details
                );
            }
        }
        return findings;
    }
};

class PrivateKeyMemoryAnalyzer : public IAnalyzer {
public:
    std::string name() const override { return "memory_private_key"; }
    std::string description() const override { return "Detects private key blocks in memory"; }
    AnalyzerCategory category() const override { return AnalyzerCategory::Memory; }

    FindingList analyze(const Evidence& evidence) const override {
        FindingList findings;
        if (auto* m = std::get_if<MemoryChunkEvidence>(&evidence)) {
            auto matches = detect_private_key_matches(m->chunk);
            for (const auto& match : matches) {
                MemorySecretFindingDetails details;
                details.raw_secret = match.value;
                details.raw_snippet = match.snippet;
                try {
                    details.fingerprint = SecretFingerprinter::instance().fingerprint(match.value);
                } catch (const std::exception& e) {
                    Logger::log(LogLevel::Error, "Fingerprint computation failed: " + std::string(e.what()));
                    continue; // skip this finding
                }
                details.secret_type = "private_key"; // or match.type
                details.secret_length = match.value.size();
                details.location = m->location;
                details.address = m->address;                
                findings.emplace_back(
                    FindingSeverity::High,
                    "Sensitive data found in memory",
                    "Private key detected in process memory.",
                    details
                );
            }
        }
        return findings;
    }
};

void register_builtin_analyzers(AnalyzerRegistry& registry) {
    registry.register_analyzer(std::make_unique<HardeningAnalyzer>());
    registry.register_analyzer(std::make_unique<DangerousApiAnalyzer>());
    registry.register_analyzer(std::make_unique<SensitiveFileAnalyzer>());
    registry.register_analyzer(std::make_unique<NetworkAnalyzer>());
    registry.register_analyzer(std::make_unique<PasswordMemoryAnalyzer>());
    registry.register_analyzer(std::make_unique<PrivateKeyMemoryAnalyzer>());
}

} // namespace runtimexray