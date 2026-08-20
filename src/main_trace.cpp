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
#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>

namespace {
    std::string format_sockaddr(const std::vector<std::byte>& data)
    {
        if (data.size() < sizeof(sa_family_t)) {
            return {};
        }
        sa_family_t family = *reinterpret_cast<const sa_family_t*>(data.data());

        char ip_str[INET6_ADDRSTRLEN] = { 0 };
        uint16_t port = 0;

        if (family == AF_INET) {
            if (data.size() < sizeof(sockaddr_in)) {
                return "";
            }
            const sockaddr_in* addr = reinterpret_cast<const sockaddr_in*>(data.data());
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
            port = ntohs(addr->sin_port);
        } else if (family == AF_INET6) {
            if (data.size() < sizeof(sockaddr_in6)) {
                return "";
            }
            const sockaddr_in6* addr = reinterpret_cast<const sockaddr_in6*>(data.data());
            inet_ntop(AF_INET6, &addr->sin6_addr, ip_str, sizeof(ip_str));
            port = ntohs(addr->sin6_port);
        } else {
            return "(unknown family)";
        }

        return std::string(ip_str) + ':' + std::to_string(port);
    }

    std::string sanitize_data(const std::vector<std::byte>& data, size_t max_len = 128) 
    {
        std::string out;
        out.reserve(std::min(data.size(), max_len));
        for (size_t i = 0; i < data.size() && i < max_len; ++i) {
            unsigned char c = static_cast<unsigned char>(data[i]);
            if (c >= 0x20 && c <= 0x7E) {
                out.push_back(static_cast<char>(c));
            } else {
                out.push_back('.');
            }
        }
        if (data.size() > max_len) {
            out += "...";
        }
        return out;
    }
};

int main(int argc, char* argv[])
{
    bool verbose = false;
    std::vector<std::string> args;

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
        tracer.run([&tracer, verbose](const runtimexray::SyscallEvent& ev) {
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
                    }
                } else if (std::strcmp(syscall_name, "connect") == 0) {
                    uint64_t sockaddr_ptr = ev.arg1;
                    uint64_t addrlen = ev.arg2;
                    if (sockaddr_ptr > 0 && addrlen > 0 && addrlen <= 256) {
                        auto bytes = tracer.read_memory(sockaddr_ptr, static_cast<size_t>(addrlen));
                        if (!bytes.empty()) {
                            extra = " addr=" + format_sockaddr(bytes);
                        }
                    }
                } else if (std::strcmp(syscall_name, "sendto") == 0) {
                    // sendto: arg4 – dest_addr, arg5 – addrlen (x86_64: r8, r9)
                    uint64_t sockaddr_ptr = ev.arg4;
                    uint64_t addrlen = ev.arg5;
                    if (sockaddr_ptr > 0 && addrlen > 0 && addrlen <= 256) {
                        auto bytes = tracer.read_memory(sockaddr_ptr, static_cast<size_t>(addrlen));
                        if (!bytes.empty()) {
                            extra = " dest addr=" + format_sockaddr(bytes);
                        }
                    }
                }  else if (std::strcmp(syscall_name, "write") == 0) {
                    uint64_t fd = ev.arg0;
                    uint64_t buf_ptr = ev.arg1;
                    uint64_t count = ev.arg2;
                    if (buf_ptr > 0 && count > 0 && count <= 4096) {
                        auto bytes = tracer.read_memory(buf_ptr, static_cast<size_t>(count));
                        if (!bytes.empty()) {
                            extra = " fd=" + std::to_string(fd) + " data=\"" + sanitize_data(bytes) + "\"";
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
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}