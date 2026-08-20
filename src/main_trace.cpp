/**
 * @file    main_trace.cpp
 * @brief   CLI entry point for the Tachikoma tracer demo.
 *
 * @author  Peter Magram
 * @date    2026-08-17
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

#include "tachikoma.hpp"
#include "syscall_names.hpp"
#include "finding.hpp"
#include "dynamic_analysis.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace {
    
    runtimexray::FindingList scan_child_output_for_secrets(const std::string& file_path) {
        runtimexray::FindingList results;
        std::ifstream infile(file_path);
        if (!infile) {
            return results; // file does exist or not accessible
        }

        std::string line;
        int line_count = 0;
        const int max_findings_per_file = 5; // limit amount not to overload

        while (std::getline(infile, line) && line_count < max_findings_per_file) {
            if (runtimexray::contains_sensitive_keyword(line)) {
                // Cut the line for snippet
                std::string snippet = line.substr(0, 200);
                if (line.size() > 200) {
                    snippet += "...";
                }

                results.emplace_back(
                    runtimexray::FindingSeverity::High,
                    "Sensitive data found in process output",
                    "The program printed potentially sensitive information to stdout/stderr.",
                    runtimexray::SensitiveDataWriteDetails{snippet, "Keyword match in child output"}
                );
                ++line_count;
            }
        }
        return results;
    }    
};

int main(int argc, char* argv[])
{
    bool verbose = false;
    std::vector<std::string> args;
    runtimexray::FindingList findings;

    // process args
    int i = 1;
    for (; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [--verbose] <program> [args...]\n";
            return 0;
        } else {
            break; // first non-optional argument is program name
        }
    }

    if (i >= argc) {
        std::cerr << "Error: no program specified.\n";
        std::cout << "Usage: " << argv[0] << " [--verbose] <program> [args...]\n";
        return 1;
    }

    std::string program = argv[i];
    // Collect args for traced process: program name and other args
    args.push_back(program);
    for (++i; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    try {
        runtimexray::Tachikoma tracer(program, args);
        tracer.run([&tracer, &findings, verbose](const runtimexray::SyscallEvent& ev) {
            const long num = static_cast<long>(ev.syscall_number);

            if (!verbose && !runtimexray::is_interesting_syscall(num)) {
                return; // skip 
            }

            const char *syscall_name = runtimexray::syscall_name(static_cast<long>(ev.syscall_number));
            std::string extra;

            if (ev.is_entry) {
                if (std::strcmp(syscall_name, "open") == 0 || std::strcmp(syscall_name,"openat") == 0) {
                    uint64_t path_addr = (std::strcmp(syscall_name, "open") == 0) ? ev.arg0 : ev.arg1;
                    std::string path = tracer.read_string(path_addr);
                    if (!path.empty()) {
                        extra = " path=\"" + path + "\"";
                        if (runtimexray::is_sensitive_path(path)) {
                            findings.emplace_back(
                                runtimexray::FindingSeverity::High,
                                "Sensitive file access",
                                "Process attempted to open: " + path,
                                runtimexray::SensitiveFileAccessDetails{path, "Known sensitive path"}
                            );
                        }
                    }
                } else if (std::strcmp(syscall_name, "connect") == 0) {
                    uint64_t sockaddr_ptr = ev.arg1;
                    uint64_t addrlen = ev.arg2;
                    if (sockaddr_ptr > 0 && addrlen > 0 && addrlen <= 256) {
                        auto bytes = tracer.read_memory(sockaddr_ptr, static_cast<size_t>(addrlen));
                        auto parsed = runtimexray::parse_sockaddr(bytes);
                        if (parsed.valid) {
                            extra = " addr=" + parsed.ip + ":" + std::to_string(parsed.port);
                            // check for suspicious ports
                            if (parsed.port == 22 || parsed.port == 3389 || parsed.port == 445 ||
                                parsed.port == 1433 || parsed.port == 3306) {
                                findings.emplace_back(
                                    runtimexray::FindingSeverity::Medium,
                                    "Suspicious network connection",
                                    "Connecting to " + parsed.ip + ":" + std::to_string(parsed.port),
                                    runtimexray::NetworkConnectionDetails{parsed.ip, parsed.port, "Potentially sensitive port"}
                                );
                            }
                        }
                    }
                } else if (std::strcmp(syscall_name, "sendto") == 0) {
                    // sendto: arg4 – dest_addr, arg5 – addrlen (x86_64: r8, r9)
                    uint64_t sockaddr_ptr = ev.arg4;
                    uint64_t addrlen = ev.arg5;
                    if (sockaddr_ptr > 0 && addrlen > 0 && addrlen <= 256) {
                        auto bytes = tracer.read_memory(sockaddr_ptr, static_cast<size_t>(addrlen));
                        auto parsed = runtimexray::parse_sockaddr(bytes);
                        if (parsed.valid) {
                            extra = " dest addr=" + parsed.ip + ":" + std::to_string(parsed.port);
                            // check for suspicious ports
                            if (parsed.port == 22 || parsed.port == 3389 || parsed.port == 445 ||
                                parsed.port == 1433 || parsed.port == 3306) {
                                findings.emplace_back(
                                    runtimexray::FindingSeverity::Medium,
                                    "Suspicious network connection",
                                    "Connecting to " + parsed.ip + ":" + std::to_string(parsed.port),
                                    runtimexray::NetworkConnectionDetails{parsed.ip, parsed.port, "Potentially sensitive port"}
                                );
                            }
                        }
                    }
                }  else if (std::strcmp(syscall_name, "write") == 0) {
                    uint64_t fd = ev.arg0;
                    uint64_t buf_ptr = ev.arg1;
                    uint64_t count = ev.arg2;
                    if (buf_ptr > 0 && count > 0 && count <= 4096) {
                        auto bytes = tracer.read_memory(buf_ptr, static_cast<size_t>(count));
                        if (!bytes.empty()) {
                            std::string data_str = runtimexray::sanitize_data(bytes);
                            extra = " fd=" + std::to_string(fd) + " data=\"" + data_str + "\"";
                            // Search for secrets
                            if (runtimexray::contains_sensitive_keyword(data_str)) {
                                findings.emplace_back(
                                    runtimexray::FindingSeverity::High,
                                    "Sensitive data written",
                                    "Data written may contain credentials or secrets",
                                    runtimexray::SensitiveDataWriteDetails{data_str, "Keyword match"}
                                );
                            }                            
                        }
                    }
                }
                std::cout << "syscall " << ev.syscall_number << ": "
                          << syscall_name
                          << " entry (pid=" << ev.pid << ") " 
                          << extra << '\n';
            } else {
                std::cout << "syscall " << ev.syscall_number << ": "
                          << syscall_name
                          << " exit (pid=" << ev.pid << ") = " 
                          << ev.return_value << '\n';
            }
        });

        std::cout << "\n[Child stdout/stderr saved to " << tracer.child_output_path() << "]\n";
        // Anylyze save child process output
        std::string child_output = tracer.child_output_path();
        if (!child_output.empty()) {
            auto extra_findings = scan_child_output_for_secrets(child_output);
            findings.insert(findings.end(), extra_findings.begin(), extra_findings.end());
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    if (!findings.empty()) {
        std::cout << "\n== Dynamic Findings ==\n";
        for (const auto& f : findings) {
            std::visit([&](const auto& details) {
                using T = std::decay_t<decltype(details)>;
                if constexpr (std::is_same_v<T, runtimexray::NetworkConnectionDetails>) {
                    std::cout << " - " << f.description << " (" << details.remote_addr << ":" << details.port << ")\n";
                } else if constexpr (std::is_same_v<T, runtimexray::SensitiveDataWriteDetails>) {
                    std::cout << " - " << f.description << " data=\"" << details.data_snippet << "\"\n";
                } else if constexpr (std::is_same_v<T, runtimexray::SensitiveFileAccessDetails>) {
                    std::cout << " - " << f.description << " path=" << details.path << "\n";
                } else {
                    std::cout << " - " << f.description << "\n";
                }
            }, f.details);
        }
    }

    return 0;
}