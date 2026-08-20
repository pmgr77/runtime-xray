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

// Read path for open/openat
#if defined(__x86_64__)
            const long open_num = 2;
            const long openat_num = 257;
#elif defined(__aarch64__)
            const long open_num = 56;   // в ARM64 openat
            const long openat_num = 56; // open нет, только openat
#endif

            if (ev.is_entry) {
                if (num == open_num || num == openat_num) {
                    uint64_t path_addr = 0;
                    if (num == open_num) {
                        // x86_64 open: path = arg0
                        path_addr = ev.arg0;
                    } else {
                        // openat: path = arg1
                        path_addr = ev.arg1;
                    }
                    std::string path = tracer.read_string(path_addr);
                    if (!path.empty()) {
                        extra = " path=\"" + path + "\"";
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

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}