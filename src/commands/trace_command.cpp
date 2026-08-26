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
#ifdef BUILD_EBPF_BACKEND
#include "itrace_backend.hpp" // declares create_ebpf_backend()
#endif // BUILD_EBPF_BACKEND
#include "tachikoma.hpp"
#include "finding.hpp"
#include "analyzer_registry.hpp"
#include "evidence.hpp"
#include "finding_filter.hpp"
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
#include <chrono>

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
            TraceConfig config;
            config.program = program_;
            config.args = full_args;
            config.timeout = timeout_;
            config.callback = [&](const runtimexray::SyscallEvent& ev) {
                // This callback runs during the trace
                const long num = static_cast<long>(ev.syscall_number);

                if (!common.verbose && !runtimexray::is_interesting_syscall(num)) {
                    return; // skip non-interesting syscalls
                }

                const char *syscall_name = runtimexray::syscall_name(static_cast<long>(ev.syscall_number));
                std::string extra;

                if (ev.is_entry) {
                    if (std::strcmp(syscall_name, "open") == 0 || std::strcmp(syscall_name,"openat") == 0) {
                        uint64_t path_addr = (std::strcmp(syscall_name, "open") == 0) ? ev.arg0 : ev.arg1;
                        std::string path = backend->read_string(path_addr);
                        if (!path.empty()) {
                            extra = " path=\"" + path + "\"";
                            runtimexray::FileAccessEvidence fe{path, 0, ev.pid};
                            auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(fe);
                            findings.insert(findings.end(), res.begin(), res.end());
                        }
                    } else if (std::strcmp(syscall_name, "connect") == 0) {
                        uint64_t sockaddr_ptr = ev.arg1;
                        uint64_t addrlen = ev.arg2;
                        if (sockaddr_ptr > 0 && addrlen > 0 && addrlen <= 256) {
                            auto bytes = backend->read_memory(sockaddr_ptr, static_cast<size_t>(addrlen));
                            auto parsed = runtimexray::parse_sockaddr(bytes);
                            if (parsed.valid) {
                                extra = " addr=" + parsed.ip + ":" + std::to_string(parsed.port);
                                runtimexray::NetworkEvidence ne{parsed.ip, parsed.port, ev.pid, "outbound"};
                                auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(ne);
                                findings.insert(findings.end(), res.begin(), res.end());
                            }                            
                        }
                    } else if (std::strcmp(syscall_name, "sendto") == 0) {
                        // sendto: arg4 – dest_addr, arg5 – addrlen (x86_64: r8, r9)
                        uint64_t sockaddr_ptr = ev.arg4;
                        uint64_t addrlen = ev.arg5;
                        if (sockaddr_ptr > 0 && addrlen > 0 && addrlen <= 256) {
                            auto bytes = backend->read_memory(sockaddr_ptr, static_cast<size_t>(addrlen));
                            auto parsed = runtimexray::parse_sockaddr(bytes);
                            if (parsed.valid) {
                                extra = " dest addr=" + parsed.ip + ":" + std::to_string(parsed.port);
                                runtimexray::NetworkEvidence ne{parsed.ip, parsed.port, ev.pid, "outbound"};
                                auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(ne);
                                findings.insert(findings.end(), res.begin(), res.end());
                            }                            
                        }
                    }  else if (std::strcmp(syscall_name, "write") == 0) {
                        uint64_t fd = ev.arg0;
                        uint64_t buf_ptr = ev.arg1;
                        uint64_t count = ev.arg2;
                        if (buf_ptr > 0 && count > 0 && count <= 4096) {
                            auto bytes = backend->read_memory(buf_ptr, static_cast<size_t>(count));
                            if (!bytes.empty()) {
                                std::string data_str = runtimexray::sanitize_data(bytes);
                                extra = " fd=" + std::to_string(fd) + " data=\"" + data_str + "\"";
                                runtimexray::MemoryChunkEvidence mce{data_str, "write_data", ev.pid};
                                auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(mce);
                                findings.insert(findings.end(), res.begin(), res.end());                                
                            }
                        }
                    }

                    if (common.output_format != "json") {
                        std::cout << "syscall " << ev.syscall_number << ": "
                                << syscall_name
                                << " entry (pid=" << ev.pid << ") " 
                                << extra << '\n';
                    }
                } else {
                    if (common.output_format != "json") {
                        std::cout << "syscall " << ev.syscall_number << ": "
                                << syscall_name
                                << " exit (pid=" << ev.pid << ") = " 
                                << ev.return_value << '\n';
                    }
                }
            };

            backend->trace(config);

            // ---- Timeout handling (works for any backend) ----
            if (backend->is_timed_out() && common.output_format != "json") {
                std::cout << "\n[Trace timed out after " << timeout_.count() << " seconds]\n";
            }

            // ---- Child output handling (works for any backend that saves it) ----
            std::string child_output = backend->child_output_path();
            if (!child_output.empty()) {
                if (common.output_format != "json") {
                    std::cout << "\n[Child stdout/stderr saved to " << child_output << "]\n";
                }
                auto extra_findings = scan_child_output_for_secrets(child_output);
                findings.insert(findings.end(), extra_findings.begin(), extra_findings.end());
            }
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << '\n';
            return 1;
        }

        runtimexray::filter_findings(findings, common.min_severity, common.verbose);

        auto end_time = std::chrono::steady_clock::now();
        int duration_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count()
        );

        ReportContext ctx;
        ctx.command = "trace";
        ctx.target = program_;
        ctx.started_at = runtimexray::current_iso8601_utc();
        ctx.duration_ms = duration_ms;

        if (common.output_format == "json") {
            std::cout << Reporter::to_json(findings, ctx);
        } else {
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
            std::cout << "Trace command: " << program_ << " timeout=" << timeout_.count() << "\n";
        }

        return 0;
    }

    void TraceCommand::print_help() const
    {
        std::cout << "Usage: runtimexray trace [--verbose] [--min-severity <level>] "
                 "[--timeout <seconds>] --backend <ptrace|ebpf> <program> [args...]\n";
        std::cout << "Options:\n";
        std::cout << "  --verbose             Show all system calls, not just interesting ones.\n";
        std::cout << "  --timeout <seconds>   Stop tracing after the specified time and report findings.\n";
        std::cout << "  --min-severity <level> Minimum severity for findings (Critical, High, Medium, Low, Info). Default: Medium.\n";
        std::cout << "  --backend <ptrace|ebpf>  Select tracing backend (default: ptrace)\n";        
        std::cout << "  --help                Show this help message.\n";
    }
} // namespace runtimexray
