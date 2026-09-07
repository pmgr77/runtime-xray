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
#include "memory_scanner.hpp"
#include "finding.hpp"
#include "analyzer_registry.hpp"
#include "evidence.hpp"
#include "finding_filter.hpp"
#include "logger.hpp"
#include "finding_reporter.hpp"
#include "dynamic_analysis.hpp"
#include "lineage_analyzer.hpp"
#include "risk_assessment_registry.hpp"
#include "lineage.hpp"

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
#include <unistd.h>
#include <cstddef>

namespace {

    void handle_syscall_open(
        const char *syscall_name,
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        runtimexray::FindingList& findings,
        const runtimexray::SyscallEvent& ev)
    {
        uint64_t path_addr = (std::strcmp(syscall_name, "open") == 0) ? ev.arg0 : ev.arg1;
        std::string path = backend->read_string(ev.pid, path_addr);
        if (!path.empty()) {
            extra_info = " path=\"" + path + "\"";
            runtimexray::FileAccessEvidence fe{path, 0, ev.pid};
            auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(fe);
            for (auto& f : res) {
                f.pid = ev.pid;   // set PID
                findings.push_back(f);
            }
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
            auto bytes = backend->read_memory(ev.pid, sockaddr_ptr, static_cast<size_t>(addrlen));
            auto parsed = runtimexray::parse_sockaddr(bytes);
            if (parsed.valid) {
                extra_info = " addr=" + parsed.ip + ":" + std::to_string(parsed.port);
                runtimexray::NetworkEvidence ne{parsed.ip, parsed.port, ev.pid, "outbound"};
                auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(ne);
                for (auto& f : res) {
                    f.pid = ev.pid;   // set PID
                    findings.push_back(f);
                }
            }
        }
    }

    void handle_syscall_sendto(
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        runtimexray::FindingList& findings,
        const runtimexray::SyscallEvent& ev)
    {
        uint64_t buf_ptr = ev.arg1;
        uint64_t count   = ev.arg2;

        // Debug: log pointer and length
        runtimexray::Logger::log(runtimexray::LogLevel::Debug, "sendto: buf_ptr=0x" + std::to_string(buf_ptr) +
                ", count=" + std::to_string(count));

        if (buf_ptr > 0 && count > 0 && count <= 4096) {
            auto bytes = backend->read_memory(ev.pid, buf_ptr, static_cast<size_t>(count));
            if (!bytes.empty()) {
                if (runtimexray::Logger::is_enabled(runtimexray::LogLevel::Debug)) {
                    // Log raw hex for debugging
                    std::string hex;
                    for (size_t i = 0; i < std::min(bytes.size(), (size_t)32); ++i) {
                        char buf[4];
                        snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned char>(bytes[i]));
                        hex += buf;
                        if (i % 16 == 15) hex += " ";
                    }
                    runtimexray::Logger::log(runtimexray::LogLevel::Debug, "sendto raw bytes (hex): " + hex);
                }
                std::string data_str = runtimexray::sanitize_data(bytes);
                // Append data info to extra_info (redacted in safe log)
                extra_info += " data=\"" + data_str + "\"";
                runtimexray::MemoryChunkEvidence mce{data_str, "sendto_data", ev.pid};
                auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(mce);
                for (auto& f : res) {
                    f.pid = ev.pid;
                    findings.push_back(f);
                }
            } else {
                runtimexray::Logger::log(runtimexray::LogLevel::Debug, "sendto: read_memory returned empty");
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
            auto bytes = backend->read_memory(ev.pid, buf_ptr, static_cast<size_t>(count));
            if (!bytes.empty()) {
                std::string data_str = runtimexray::sanitize_data(bytes);
                std::string location = (fd == 1) ? "stdout" : (fd == 2) ? "stderr" : "write_data";
                extra_info = " fd=" + std::to_string(fd) + " data=\"" + data_str + "\"";
                runtimexray::MemoryChunkEvidence mce{data_str, location, ev.pid};
                auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(mce);
                for (auto& f : res) {
                    f.pid = ev.pid;   // set PID
                    findings.push_back(f);
                }
            }
        }
    }

    void handle_syscall_send(
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        runtimexray::FindingList& findings,
        const runtimexray::SyscallEvent& ev)
    {
        // send(int sockfd, const void *buf, size_t len, int flags)
        // Linux x86_64: rdi=sockfd, rsi=buf, rdx=len, r10=flags
        uint64_t buf_ptr = ev.arg1;
        uint64_t count = ev.arg2;
        if (buf_ptr > 0 && count > 0 && count <= 4096) {
            auto bytes = backend->read_memory(ev.pid, buf_ptr, static_cast<size_t>(count));
            if (!bytes.empty()) {
                std::string data_str = runtimexray::sanitize_data(bytes);
                // Optional: include sockfd in extra_info
                extra_info = " sockfd=" + std::to_string(ev.arg0) + " data=\"" + data_str + "\"";
                runtimexray::MemoryChunkEvidence mce{data_str, "send_data", ev.pid};
                auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(mce);
                for (auto& f : res) {
                    f.pid = ev.pid;   // set PID
                    findings.push_back(f);
                }
            }
        }
    }


    void handle_syscall_writev(
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        runtimexray::FindingList& findings,
        const runtimexray::SyscallEvent& ev)
    {
        // writev(int fd, const struct iovec *iov, int iovcnt)
        uint64_t fd = ev.arg0;
        uint64_t iov_ptr = ev.arg1;
        uint64_t iovcnt = ev.arg2;

        if (iov_ptr == 0 || iovcnt == 0 || iovcnt > 1024) {
            return; // sane limit
        }

        // Read the iovec array from the target process
        size_t iov_size = iovcnt * sizeof(struct iovec);
        auto iov_bytes = backend->read_memory(ev.pid, iov_ptr, iov_size);
        if (iov_bytes.empty()) {
            return;
        }

        const struct iovec* iov = reinterpret_cast<const struct iovec*>(iov_bytes.data());

        // For each iovec, read the buffer and scan for secrets
        for (uint64_t i = 0; i < iovcnt; ++i) {
            uint64_t buf_ptr = reinterpret_cast<uint64_t>(iov[i].iov_base);
            uint64_t count = static_cast<uint64_t>(iov[i].iov_len);
            if (buf_ptr == 0 || count == 0 || count > 4096) {
                continue;
            }

            auto bytes = backend->read_memory(ev.pid, buf_ptr, static_cast<size_t>(count));
            if (bytes.empty()) {
                continue;
            }

            std::string data_str = runtimexray::sanitize_data(bytes);
            // Differentiate stdout/stderr
            std::string location = (fd == 1) ? "stdout" : (fd == 2) ? "stderr" : "writev_data";
            runtimexray::MemoryChunkEvidence mce{data_str, location, ev.pid};
            auto res = runtimexray::AnalyzerRegistry::instance().analyze_evidence(mce);
            for (auto& f : res) {
                f.pid = ev.pid;
                findings.push_back(f);
            }
            // Append data to extra_info (optional)
            if (!extra_info.empty()) extra_info += " ";
            extra_info += "iov[" + std::to_string(i) + "]=" + data_str;
        }
    }
} // anonymous namespace

namespace runtimexray {

    // Helper to add data nodes from memory scan to lineage graph
    void add_data_nodes_to_graph(
        LineageGraph& graph,
        const FindingList& mem_findings,
        pid_t pid)
    {
        Logger::log(LogLevel::Debug, "add_data_nodes_to_graph: PID=" + std::to_string(pid));
        // Find the process node for this PID
        size_t proc_idx = SIZE_MAX;
        for (size_t i = 0; i < graph.observations.size(); ++i) {
            const auto& obs = graph.observations[i];
            if (obs.type == ObservationType::Event &&
                obs.syscall_name == "process" &&
                obs.pid == pid)
            {
                proc_idx = i;
                break;
            }
        }

        Logger::log(LogLevel::Debug, "add_data_nodes_to_graph: proc_idx=" + std::to_string(proc_idx));

        // If no process node exists, create one
        if (proc_idx == SIZE_MAX) {
            Logger::log(LogLevel::Debug, "add_data_nodes_to_graph: Creating new process node for PID " + std::to_string(pid));
            Observation proc_obs;
            proc_obs.type = ObservationType::Event;
            proc_obs.syscall_name = "process";
            proc_obs.pid = pid;
            proc_obs.tid = pid;
            proc_obs.start_time = std::chrono::steady_clock::now();
            proc_obs.program_name = runtimexray::get_process_name(pid);
            proc_idx = graph.observations.size();
            graph.observations.push_back(proc_obs);
        }

        for (const auto& f : mem_findings) {
            if (auto* details = std::get_if<MemorySecretFindingDetails>(&f.details)) {
                Observation data_obs;
                data_obs.type = ObservationType::Data;
                data_obs.data_type = details->location.empty() ? details->secret_type : details->location;
                data_obs.fingerprint = details->fingerprint;
                // For graph, we can redact snippet or keep raw (reporter will handle)
                data_obs.data_snippet = details->raw_snippet;
                data_obs.address = details->address;
                data_obs.size = details->raw_secret.size();
                data_obs.pid = pid;
                data_obs.tid = pid;
                data_obs.start_time = std::chrono::steady_clock::now();
                size_t data_idx = graph.observations.size();
                Logger::log(LogLevel::Debug,
                    "add_data_nodes_to_graph: Adding data node with fingerprint " +
                    details->fingerprint +
                    " for PID " + std::to_string(pid) + " at index " + std::to_string(data_idx));
                graph.observations.push_back(data_obs);

                LineageEdge edge;
                edge.from_index = proc_idx;
                edge.to_index = data_idx;
                edge.relation = RelationType::StaticAssociated;
                edge.details = "Memory secret found";
                graph.edges.push_back(edge);
            }
        }
    }

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
            } else if (arg == "--scan-memory") {
               scan_memory_ = true;
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
        std::vector<pid_t> child_pids;

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
                    } else if (std::strcmp(syscall_name, "send") == 0) {
                        handle_syscall_send(backend, extra_info, findings, ev);
                    } else if (std::strcmp(syscall_name, "writev") == 0) {
                        handle_syscall_writev(backend, extra_info, findings, ev);
                    }

                    // Log the syscall entry (if debug or interesting)
                    if (Logger::is_enabled(LogLevel::Debug) || runtimexray::is_interesting_syscall(num)) {
                        std::string safe_extra = extra_info;
                        if (extra_info.find("data=\"") != std::string::npos) {
                            safe_extra = extra_info.substr(0, extra_info.find("data=\"") + 6) + "<redacted>\"";
                        }
                        Logger::log_sensitive(
                            LogLevel::Debug,
                            "syscall " + std::to_string(ev.syscall_number) + ": " + syscall_name +
                                " entry (pid=" + std::to_string(ev.pid) + ", tid=" + std::to_string(ev.tid) + ")" + safe_extra,
                            "syscall " + std::to_string(ev.syscall_number) + ": " + syscall_name +
                                " entry (pid=" + std::to_string(ev.pid) + ", tid=" + std::to_string(ev.tid) + ")" + extra_info
                        );
                    }
                } else {
                    // Syscall exit
                    const char* name = runtimexray::syscall_name(static_cast<long>(ev.syscall_number));
                    if ((strcmp(name, "fork") == 0 || strcmp(name, "vfork") == 0 ||
                        strcmp(name, "clone") == 0) && ev.return_value > 0) {
                        pid_t child = static_cast<pid_t>(ev.return_value);
                        child_pids.push_back(child);
                        Logger::log(LogLevel::Debug, "Detected child PID " + std::to_string(child));
                    }
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

            // ---- Produce lineage graph and scan memory for secrets ----
            auto graph = lineage_analyzer.produce_graph();

            if (scan_memory_) {
                pid_t parent_pid = backend->get_pid();
                if (parent_pid > 0) {
                    FindingList parent_findings;
                    size_t pages_scanned = 0;
                    scan_process_for_secrets(parent_pid, parent_findings, 50, 1000, &pages_scanned);
                    findings.insert(findings.end(), parent_findings.begin(), parent_findings.end());
                }
                for (pid_t child : child_pids) {
                    FindingList child_findings;
                    size_t pages_scanned = 0;
                    scan_process_for_secrets(child, child_findings, 50, 1000, &pages_scanned);
                    findings.insert(findings.end(), child_findings.begin(), child_findings.end());
                }
            }

            // ---- Child output handling (works for any backend that saves it) ----
            child_output = backend->child_output_path();
            if (!child_output.empty()) {
                Logger::log(LogLevel::Debug, "Child output saved to " + child_output + " (for debugging)");
            }

            // ---- Now add ALL findings as data nodes in the graph ----
            for (const auto& f : findings) {
                if (f.pid > 0) {
                    add_data_nodes_to_graph(graph, {f}, f.pid);
                }
            }

            // Build extra JSON metadata (for JSON reporter)
            extra.emplace();
            (*extra)["backend"] = backend_name_;
            (*extra)["timeout_seconds"] = static_cast<int>(timeout_.count());
            (*extra)["timed_out"] = backend->is_timed_out();
            (*extra)["child_output"] = "Child stdout/stderr saved to " + child_output;

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

            // After filtering findings, but before reporting:
            RiskAssessmentRegistry::instance().assess_findings(findings, ctx, &graph);

            return report_findings(common,
                std::move(ctx),
                std::move(findings),
                std::move(graph),
                extra.has_value() ? &*extra : nullptr) ? 0 : 1;

        } catch (const std::exception& e) {
            Logger::log(LogLevel::Error, std::string("Trace failed: ") + e.what());
            return 1;
        }
        // No code after catch – the function always returns from inside try or catch.
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
        std::cout << "  --show-secrets         Show raw secret values in reports (default: hidden)\n";
        std::cout << "  --timeout SECONDS     Stop tracing after SECONDS\n";
        std::cout << "  --follow-forks        Trace child processes (default)\n";
        std::cout << "  --no-follow-forks     Do not trace child processes\n";
        std::cout << "  --backend BACKEND     Select tracing backend (ptrace or ebpf, default: ptrace)\n";
        std::cout << "  --help                Show this help\n";
    }

} // namespace runtimexray
