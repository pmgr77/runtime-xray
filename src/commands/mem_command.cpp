/**
 * @file    mem_command.cpp
 * @brief   Implementation of MemCommand for process memory scanning.
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

#include "commands/mem_command.hpp"
#include "reporter.hpp"
#include "finding_filter.hpp"
#include "logger.hpp"
#include "finding_reporter.hpp"
#include "lineage.hpp"
#include <iostream>
#include <chrono>
namespace runtimexray
{

    bool MemCommand::parse_specific_args(const std::vector<std::string>& args) {
        pid_ = -1;
        max_pages_ = 1000;   // default

        for (size_t i = 0; i < args.size(); ++i) {
            const std::string& arg = args[i];

            if (arg == "-h" || arg == "--help") {
                print_help();
                return false; // signal that help was shown
            } else if (arg == "--max-pages" && (i + 1 < args.size())) {
                try {
                    max_pages_ = std::stoull(args[++i]);
                } catch (...) {
                    std::cerr << "Error: Invalid value for --max-pages option.\n";
                    return false;
                }
            } else if (pid_ == -1) {
                try {
                    pid_ = std::stoi(arg);
                } catch (const std::invalid_argument&) {
                    std::cerr << "Error: Invalid PID value: " << arg << std::endl;
                    return false;
                }
            } else {
                std::cerr << "Error: Unexpected argument '" << arg << "' for mem command." << std::endl;
                return false;
            }
        }

        if (pid_ == -1) {
            std::cerr << "Error: No PID provided for mem command." << std::endl;
            return false;
        }

        return true;
    }

    int MemCommand::execute(const CommonOptions &common) {
        auto start_time = std::chrono::steady_clock::now();

        runtimexray::FindingList findings;
        size_t pages_scanned = 0;

        // ---- Scan process memory ----
        try {
            runtimexray::scan_process_for_secrets(pid_, findings, 50, max_pages_, &pages_scanned);
            Logger::log(LogLevel::Info, "Scanned " + std::to_string(pages_scanned) + " pages for PID " + std::to_string(pid_));
            // -- debug --
            Logger::log(LogLevel::Info, "Starting mem scan for PID " + std::to_string(pid_));
            auto regions = get_readable_regions(pid_);
            Logger::log(LogLevel::Info, "Found " + std::to_string(regions.size()) + " readable regions");
            for (const auto& region : regions) {
                Logger::log(LogLevel::Debug, "Region: 0x" + std::to_string(region.start) + " - 0x" + std::to_string(region.end) + " (" + region.perms + ")");
            }
            // end of debug
            runtimexray::filter_findings(findings, common.min_severity, false);
        } catch (const std::exception& e) {
            Logger::log(LogLevel::Error, std::string("Memory scan failed: ") + e.what());
            return 1;
        }
        
        auto end_time = std::chrono::steady_clock::now();
        int duration_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count()
        );

        // ---- Build lineage graph ----
        LineageGraph graph;
        graph.summary = "Memory scan for PID " + std::to_string(pid_) + " completed";

        // Process node
        Observation proc_obs;
        proc_obs.type = ObservationType::Event;
        proc_obs.syscall_name = "process";
        proc_obs.pid = pid_;
        proc_obs.tid = pid_;
        proc_obs.start_time = start_time;
        proc_obs.end_time = end_time;
        proc_obs.program_name = runtimexray::get_process_name(pid_);
        size_t proc_idx = graph.observations.size();
        graph.observations.push_back(proc_obs);
        
        // Data nodes for memory secrets
        for (const auto& f: findings) {
            if (auto* details = std::get_if<MemorySecretFindingDetails>(&f.details)) {
                Observation data_obs;
                data_obs.type = ObservationType::Data;
                data_obs.data_type = details->secret_type;
                data_obs.data_snippet = details->snippet;
                data_obs.address = details->address;
                data_obs.size = details->snippet.size();
                data_obs.pid = pid_;
                data_obs.tid = pid_;
                data_obs.start_time = start_time;
                data_obs.end_time = end_time;
                size_t data_idx = graph.observations.size();
                graph.observations.push_back(data_obs);

                // Edge: process -> data
                LineageEdge edge;
                edge.from_index = proc_idx;
                edge.to_index = data_idx;
                edge.relation = RelationType::StaticAssociated;
                edge.details = "Memory secret found";
                graph.edges.push_back(edge);
            }
        }
        
        ReportContext ctx;
        ctx.command = "mem";
        ctx.target = std::to_string(pid_);
        ctx.started_at = runtimexray::current_iso8601_utc();
        ctx.duration_ms = duration_ms;

        // ---- Build extra metadata (optional) ----
        nlohmann::json extra;
        extra["pages_scanned"] = pages_scanned;
        extra["max_pages"] = static_cast<int>(max_pages_);

        return report_findings(common, std::move(ctx), std::move(findings), std::move(graph), &extra) ? 0 : 1;
    }

    void MemCommand::print_help() const {
        std::cout << "Usage: runtimexray mem [--report FILE] [--json FILE] "
                  << "[--log-level LEVEL] [--log-file FILE] [--min-severity LEVEL] "
                  << "[--max-pages N] <pid>\n";
        std::cout << "Options:\n";
        std::cout << "  --report FILE         Write human-readable report to FILE (default: stdout)\n";
        std::cout << "  --json FILE           Write JSON report to FILE\n";
        std::cout << "  --log-level LEVEL     Set log level (error, warn, info, debug, trace)\n";
        std::cout << "  --log-file FILE       Write logs to FILE (default: stderr)\n";
        std::cout << "  --min-severity LEVEL  Minimum severity for findings (Critical, High, Medium, Low, Info)\n";
        std::cout << "  --max-pages N         Maximum number of memory pages to scan (default: 1000)\n";
        std::cout << "                        0 = skip page scanning, only check cmdline/environ\n";
        std::cout << "  --help                Show this help\n";
    }

} // namespace runtimexray