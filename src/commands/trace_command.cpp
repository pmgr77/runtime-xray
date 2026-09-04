/**
 * @file    trace_command.cpp
 * @brief   Implementation of TraceCommand for dynamic syscall tracing.
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

#include "commands/trace_command.hpp"
#include "reporter.hpp"
#include "syscall_names.hpp"
#include "itrace_backend.hpp" // declares create_ebpf_backend()
#include "tachikoma.hpp"
#include "finding.hpp"
#include "analyzer_registry.hpp"
#include "evidence.hpp"
#include "finding_filter.hpp"
#include "logger.hpp"
#include "finding_reporter.hpp"
#include "dynamic_analysis.hpp"
#include "lineage_analyzer.hpp"
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
#include <chrono>
#include <optional>

namespace {
    runtimexray::FindingList scan_child_output_for_secrets(const std::string& file_path) {
        runtimexray::FindingList results;
        std::ifstream infile(file_path);
        if (!infile) {
            return results;
        }

        std::string line;
        size_t found = 0;
        const size_t max_findings = 5;

        while (std::getline(infile, line) && found < max_findings) {
            if (!line.empty()) {
                // Create memory evidence from the output line.
                runtimexray::MemoryChunkEvidence ev{line, "child_output", 0}; // pid unknown
                auto findings = runtimexray::AnalyzerRegistry::instance().analyze_evidence(ev);

                for (const auto& f : findings) {
                    if (found >= max_findings) {
                        break;
                    }
                    results.push_back(f);
                    ++found;
                }
            }
        }
        return results;
    }

    void handle_syscall_open(
        const char *syscall_name,
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        runtimexray::FindingList& findings,
        const runtimexray::SyscallEvent& ev)
    {
        uint64_t path_addr = (std::strcmp(syscall_name, "open") == 0) ? ev.arg0 : ev.arg1;
        std::string path = backend->read_string(path_addr);
        if (!path.empty()) {
            extra_info = " path=\"" + path + "\"";
            runtimexray::FileAccessEvidence fe{path, 0, ev.pid};
            auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(fe);
            findings.insert(findings.end(), res.begin(), res.end());
        }
    }
    
    void handle_syscall_connect(
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        runtimexray::FindingList& findings,
        const runtimexray::SyscallEvent& ev) 
    {
        uint64_t sockaddr_ptr = ev.arg1;
        uint64_t addrlen = ev.arg2;
        if (sockaddr_ptr > 0 && addrlen > 0 && addrlen <= 256) {
            auto bytes = backend->read_memory(sockaddr_ptr, static_cast<size_t>(addrlen));
            auto parsed = runtimexray::parse_sockaddr(bytes);
            if (parsed.valid) {
                extra_info = " addr=" + parsed.ip + ":" + std::to_string(parsed.port);
                runtimexray::NetworkEvidence ne{parsed.ip, parsed.port, ev.pid, "outbound"};
                auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(ne);
                findings.insert(findings.end(), res.begin(), res.end());
            }                            
        }
    }

    void handle_syscall_sendto(
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        runtimexray::FindingList& findings,
        const runtimexray::SyscallEvent& ev)
    {
        // sendto: arg4 – dest_addr, arg5 – addrlen (x86_64: r8, r9)
        uint64_t sockaddr_ptr = ev.arg4;
        uint64_t addrlen = ev.arg5;
        if (sockaddr_ptr > 0 && addrlen > 0 && addrlen <= 256) {
            auto bytes = backend->read_memory(sockaddr_ptr, static_cast<size_t>(addrlen));
            auto parsed = runtimexray::parse_sockaddr(bytes);
            if (parsed.valid) {
                extra_info = " dest addr=" + parsed.ip + ":" + std::to_string(parsed.port);
                runtimexray::NetworkEvidence ne{parsed.ip, parsed.port, ev.pid, "outbound"};
                auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(ne);
                findings.insert(findings.end(), res.begin(), res.end());
            }                            
        }
    }

    void handle_syscall_write(
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        runtimexray::FindingList& findings,
        const runtimexray::SyscallEvent& ev)
    {
        uint64_t fd = ev.arg0;
        uint64_t buf_ptr = ev.arg1;
        uint64_t count = ev.arg2;
        if (buf_ptr > 0 && count > 0 && count <= 4096) {
            auto bytes = backend->read_memory(buf_ptr, static_cast<size_t>(count));
            if (!bytes.empty()) {
                std::string data_str = runtimexray::sanitize_data(bytes);
                extra_info = " fd=" + std::to_string(fd) + " data=\"" + data_str + "\"";
                runtimexray::MemoryChunkEvidence mce{data_str, "write_data", ev.pid};
                auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(mce);
                findings.insert(findings.end(), res.begin(), res.end());                                
            }
        }
    }
};

namespace runtimexray {


    
    bool TraceCommand::parse_specific_args(const std::vector<std::string> &args) {
        program_.clear();
        program_args_.clear();
        timeout_ = std::chrono::seconds(0);

        for (size_t i = 0; i < args.size(); ++i) {
            const auto &arg = args[i];
            if (arg == "-h" || arg == "--help") {
                print_help();
                return false; // signal that help was shown
            } else if (arg == "--timeout") {
                if ((i + 1) >= args.size()) {
                    std::cerr << "Error: Missing value for --timeout option." << std::endl;
                    return false;
                }
                try {
                    int seconds = std::stoi(args[++i]);
                    timeout_ = std::chrono::seconds(seconds);
                } catch (const std::invalid_argument &) {
                    std::cerr << "Error: Invalid value for --timeout option: " << args[i] << std::endl;
                    return false;
                }
            } else if (arg == "--backend") {
                if ((i + 1) >= args.size()) {
                    std::cerr << "Error: Missing value for --backend option." << std::endl;
                    return false;
                }
                backend_name_ = args[++i];
                if (backend_name_ != "ptrace" && backend_name_ != "ebpf") {
                    std::cerr << "Error: Invalid backend. Supported: ptrace, ebpf." << std::endl;
                    return false;
                }
            } else if (arg == "--follow-forks") {
               follow_forks_ = true;
            } else if (arg == "--no-follow-forks") {
                follow_forks_ = false;
            } else if (program_.empty()) {
                program_ = arg;
            } else {
                program_args_.push_back(arg);
            }
        }

        if (program_.empty()) {
            std::cerr << "Error: No program specified to trace." << std::endl;
            return false;
        }

        return true;
    }

    int TraceCommand::execute(const CommonOptions &common) {
        auto start_time = std::chrono::steady_clock::now();

        runtimexray::FindingList findings;
        std::optional<nlohmann::json> extra;
        std::string child_output;

        runtimexray::LineageAnalyzer lineage_analyzer;

        try {
            std::vector<std::string> full_args;
            full_args.reserve(1 + program_args_.size());
            full_args.push_back(program_);
            full_args.insert(full_args.end(), program_args_.begin(), program_args_.end());

            // Prepare the tracing backend
            std::unique_ptr<ITraceBackend> backend;
            if (backend_name_ == "ebpf") {
#ifdef BUILD_EBPF_BACKEND
                backend = runtimexray::create_ebpf_backend();
#else
                std::cerr << "Error: eBPF backend not built. Recompile with -DBUILD_EBPF_BACKEND=ON.\n";
                return 1;
#endif
            } else {
                backend = runtimexray::create_default_tracer_backend();
            }
            // Set backend in lineage analyzer
            lineage_analyzer.set_backend(backend.get());

            TraceConfig config;
            config.program = program_;
            config.args = full_args;
            config.timeout = timeout_;
            config.follow_forks = follow_forks_;
            config.debug = Logger::is_enabled(LogLevel::Debug);

            config.callback = [&](const runtimexray::SyscallEvent& ev) {
                // Also feed to lineage analyzer
                lineage_analyzer.on_syscall_event(ev);

                // This callback runs during the trace
                const long num = static_cast<long>(ev.syscall_number);

                if (!Logger::is_enabled(LogLevel::Debug) && 
                    !runtimexray::is_interesting_syscall(num)) {
                    return; // skip non-interesting syscalls
                }

                const char *syscall_name = runtimexray::syscall_name(static_cast<long>(ev.syscall_number));
                std::string extra_info;

                if (ev.is_entry) {
                    if (std::strcmp(syscall_name, "open") == 0 || std::strcmp(syscall_name,"openat") == 0) {
                        handle_syscall_open(syscall_name, backend, extra_info, findings, ev);
                    } else if (std::strcmp(syscall_name, "connect") == 0) {
                        handle_syscall_connect(backend, extra_info, findings, ev);
                    } else if (std::strcmp(syscall_name, "sendto") == 0) {
                        handle_syscall_sendto(backend, extra_info, findings, ev);
                    }  else if (std::strcmp(syscall_name, "write") == 0) {
                        handle_syscall_write(backend, extra_info, findings, ev);
                    }

                    // Log the syscall entry (if debug or interesting)
                    if (Logger::is_enabled(LogLevel::Debug) || runtimexray::is_interesting_syscall(num)) {
                        std::string line = "syscall " + std::to_string(ev.syscall_number) + ": " +
                                            syscall_name +
                                            " entry (pid=" + std::to_string(ev.pid) + 
                                            ", tid=" + std::to_string(ev.tid) + ") " +
                                            extra_info;
                        Logger::log(LogLevel::Debug, line);
                    }
                } else {
                    // Syscall exit – only log if debug is enabled
                    if (Logger::is_enabled(LogLevel::Debug)) {
                        std::string line = "syscall " + std::to_string(ev.syscall_number) + ": " +
                                            syscall_name +
                                            " entry (pid=" + std::to_string(ev.pid) +
                                            ", tid=" + std::to_string(ev.tid) + ") " +
                                            std::to_string(ev.return_value);
                        Logger::log(LogLevel::Debug, line);
                    }
                }
            };

            backend->trace(config);

            // ---- Child output handling (works for any backend that saves it) ----
            child_output = backend->child_output_path();

            if (!child_output.empty()) {
                auto extra_findings = scan_child_output_for_secrets(child_output);
                findings.insert(findings.end(), extra_findings.begin(), extra_findings.end());
            }

            // Build extra JSON metadata (for JSON reporter)
            extra.emplace();
            (*extra)["backend"] = backend_name_;
            (*extra)["timeout_seconds"] = static_cast<int>(timeout_.count());
            (*extra)["timed_out"] = backend->is_timed_out();
            (*extra)["child_output"] = "Child stdout/stderr saved to " + child_output;
        } catch (const std::exception& e) {
            Logger::log(LogLevel::Error, std::string("Trace failed: ") + e.what());
            return 1;
        }

        runtimexray::filter_findings(findings, common.min_severity, false);

        auto end_time = std::chrono::steady_clock::now();
        int duration_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count()
        );

        ReportContext ctx;
        ctx.command = "trace";
        ctx.target = program_;
        ctx.started_at = runtimexray::current_iso8601_utc();
        ctx.duration_ms = duration_ms;

        // After trace, produce the graph
        auto graph = lineage_analyzer.produce_graph();

        return report_findings(common, std::move(ctx), std::move(findings), std::move(graph), extra.has_value() ? &*extra : nullptr) ? 0 : 1;
    }

    void TraceCommand::print_help() const
    {
        std::cout << "Usage: runtimexray trace [--report FILE] [--json FILE] "
                  << "[--log-level LEVEL] [--log-file FILE] [--min-severity LEVEL] "
                  << "[--timeout SECONDS] [--follow-forks|--no-follow-forks] "
                  << "--backend ptrace|ebpf <program> [args...]\n";
        std::cout << "Options:\n";
        std::cout << "  --report FILE         Write human-readable report to FILE (default: stdout)\n";
        std::cout << "  --json FILE           Write JSON report to FILE\n";
        std::cout << "  --log-level LEVEL     Set log level (error, warn, info, debug, trace)\n";
        std::cout << "  --log-file FILE       Write logs to FILE (default: stderr)\n";
        std::cout << "  --min-severity LEVEL  Minimum severity for findings (Critical, High, Medium, Low, Info)\n";
        std::cout << "  --timeout SECONDS     Stop tracing after SECONDS\n";
        std::cout << "  --follow-forks        Trace child processes (default)\n";
        std::cout << "  --no-follow-forks     Do not trace child processes\n";
        std::cout << "  --backend BACKEND     Select tracing backend (ptrace or ebpf, default: ptrace)\n";
        std::cout << "  --help                Show this help\n";
    }

} // namespace runtimexray
