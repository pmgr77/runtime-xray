/**
 * @file    main.cpp
 * @brief   Unified command dispatcher for RuntimeXRay.
 *
 * @author  Peter Magram
 * @date    2026-08-22
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

#include "common_cli.hpp"
#include "icommand.hpp"
#include "commands/analyze_command.hpp"
#include "commands/trace_command.hpp"
#include "commands/mem_command.hpp"
#include "logger.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

int main(int argc, char* argv[]) {
    using namespace runtimexray;

    // Register commmands
    std::unordered_map<std::string, std::unique_ptr<ICommand>> commands;
    commands.emplace("analyze", std::make_unique<AnalyzeCommand>());
    commands.emplace("trace", std::make_unique<TraceCommand>());
    commands.emplace("mem", std::make_unique<MemCommand>());

    if (argc < 2) {
        std::cout << "RuntimeXRay - Security posture analyzer for compiled binaries\n\n";
        std::cout << "Usage: runtimexray <command> [options]\n\n";
        std::cout << "Commands:\n";
        for (const auto& [name, cmd] : commands) {
            std::cout << "  " << name << "\t" << cmd->description() << "\n";
        }
        return 1;
    }

    std::string command_name = argv[1];
    auto it = commands.find(command_name);
    if (it == commands.end()) {
        std::cerr << "Unknown command: " << command_name << "\n\n";
        std::cout << "Commands:\n";
        for (const auto& [name, cmd] : commands) {
            std::cout << "  " << name << "\t" << cmd->description() << "\n";
        }
        return 1;
    }

    // Collect arguments after subcommand
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    // Parse global options
    CommonOptions common_opts;
    std::vector<std::string> specific_args;
    if (!parse_global_options(args, common_opts, specific_args)) {
        return 1; // Error message already printed
    }
    Logger::init(runtimexray::parse_log_level(common_opts.log_level), common_opts.log_file);

    // Pass specific args to the command
    ICommand& cmd = *it->second;
    if (!cmd.parse_specific_args(specific_args)) {
        return 1; // Error message already printed or help shown
    }

    // Execute the command
    return cmd.execute(common_opts);
}