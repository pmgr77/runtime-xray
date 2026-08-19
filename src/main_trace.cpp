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
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <program> [args...]\n";
        return 1;
    }

    std::string program = argv[1];
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    try {
        runtimexray::Tachikoma tracer(program, args);
        tracer.run([](const runtimexray::SyscallEvent& ev) {
            if (ev.is_entry) {
                std::cout << "syscall " << ev.syscall_number << ": "
                          << runtimexray::syscall_name(static_cast<long>(ev.syscall_number)) 
                          << " entry (pid=" << ev.pid << ")\n";
            } else {
                std::cout << "syscall " << ev.syscall_number << ": "
                          << runtimexray::syscall_name(static_cast<long>(ev.syscall_number))
                          << " exit (pid=" << ev.pid << ") = " << ev.return_value << "\n";
            }
        });

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}