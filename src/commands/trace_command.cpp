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
#include "memory_scan_coordinator.hpp"
#include "finding.hpp"
#include "finding_filter.hpp"
#include "logger.hpp"
#include "finding_reporter.hpp"
#include "dynamic_analysis.hpp"
#include "lineage_analyzer.hpp"
#include "lineage.hpp"
#include "detection_engine.hpp"
#include "detection_rule_registry.hpp"
#include "secret_extractor.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <sys/uio.h>
#include <utility>
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
#include <set>
#include <stdexcept>

namespace {

    // Prefer bytes captured in-kernel by the backend. Fall back to reading
    // target memory only when the backend did not capture (ptrace path).
    std::string get_path_bytes(
        const std::unique_ptr<runtimexray::ITraceBackend>& backend,
        const runtimexray::SyscallEvent& ev,
        uint64_t addr)
    {
        if (!ev.captured_path.empty())
            return ev.captured_path;
        return backend->read_string(ev.pid, addr);
    }

    std::vector<std::byte> get_sockaddr_bytes(
        const std::unique_ptr<runtimexray::ITraceBackend>& backend,
        const runtimexray::SyscallEvent& ev,
        uint64_t addr, size_t len)
    {
        if (!ev.captured_sockaddr.empty()) {
            // The kernel side already truncated to its capture limit. Trust
            // that; a caller asking for `len` bytes still gets at most what
            // was captured.
            return ev.captured_sockaddr;
        }
        return backend->read_memory(ev.pid, addr, len);
    }

    std::vector<std::byte> get_buffer_bytes(
        const std::unique_ptr<runtimexray::ITraceBackend>& backend,
        const runtimexray::SyscallEvent& ev,
        uint64_t addr, size_t len)
    {
        if (!ev.captured_payload.empty()) {
            // The kernel side already truncated to its capture limit. Trust
            // that; a caller asking for `len` bytes still gets at most what
            // was captured.
            return ev.captured_payload;
        }
        return backend->read_memory(ev.pid, addr, len);
    }

    void append_data_observations_to_graph(
        runtimexray::LineageGraph& graph,
        std::vector<runtimexray::Observation>& observations)
    {
        for (auto& data_obs : observations) {
            size_t context_index = SIZE_MAX;

            //
            // Resolve the execution context that existed when the scanner
            // observation was produced.
            //
            for (size_t i = 0;
                i < graph.observations.size();
                ++i) {

                const auto& candidate =
                    graph.observations[i];

                if (candidate.process_instance_id == 0) {
                    continue;
                }

                if (candidate.pid != data_obs.pid &&
                    candidate.tgid != data_obs.pid) {
                    continue;
                }

                if (candidate.start_time >
                    data_obs.start_time) {
                    continue;
                }

                if (context_index == SIZE_MAX ||
                    candidate.start_time >
                        graph.observations[context_index].start_time ||
                    (candidate.start_time ==
                        graph.observations[context_index].start_time &&
                    candidate.seq >
                        graph.observations[context_index].seq)) {

                    context_index = i;
                }
            }

            size_t process_index = SIZE_MAX;

            if (context_index != SIZE_MAX) {
                const auto& context =
                    graph.observations[context_index];

                data_obs.process_instance_id =
                    context.process_instance_id;

                data_obs.exec_generation =
                    context.exec_generation;

                data_obs.tgid =
                    context.tgid > 0
                        ? context.tgid
                        : context.pid;

                //
                // Find the process node belonging to the resolved process instance.
                //
                for (size_t i = graph.observations.size();
                    i-- > 0;) {

                    const auto& candidate =
                        graph.observations[i];

                    if (candidate.type == runtimexray::ObservationType::Event &&
                        candidate.syscall_name == "process" &&
                        candidate.process_instance_id == data_obs.process_instance_id) {

                        process_index = i;
                        break;
                    }
                }
            }

            //
            // Scanner may observe a process that was not represented by the
            // trace graph. Create a standalone process identity in that case.
            //
            if (process_index == SIZE_MAX) {
                uint64_t next_instance_id = 1;

                for (const auto& existing :
                    graph.observations) {

                    if (existing.process_instance_id >=
                        next_instance_id) {

                        next_instance_id =
                            existing.process_instance_id + 1;
                    }
                }

                runtimexray::Observation process;

                process.type = runtimexray::ObservationType::Event;

                process.syscall_name = "process";

                process.pid = data_obs.pid;

                process.tid = data_obs.pid;

                process.tgid = data_obs.pid;

                process.process_instance_id = next_instance_id;

                process.exec_generation = 0;

                process.start_time = data_obs.start_time;

                process.end_time = data_obs.end_time;

                process.program_name = runtimexray::get_process_name(data_obs.pid);

                process_index = runtimexray::append_observation(graph, std::move(process));

                data_obs.process_instance_id = next_instance_id;

                data_obs.exec_generation = 0;

                data_obs.tgid = data_obs.pid;
            }

            size_t source_event_index = SIZE_MAX;

            if (data_obs.source_event_seq != 0) {
                for (size_t i = 0; i < graph.observations.size(); ++i) {
                    const auto& candidate = graph.observations[i];

                    if (candidate.seq == data_obs.source_event_seq &&
                        candidate.type == runtimexray::ObservationType::Event &&
                        candidate.process_instance_id == data_obs.process_instance_id &&
                        candidate.exec_generation == data_obs.exec_generation) {

                        source_event_index = i;

                        data_obs.resource_id = candidate.resource_id;
                        data_obs.resource_type = candidate.resource_type;
                        data_obs.resource_role = candidate.resource_role;

                        // Preserve the exact file or endpoint associated with
                        // the source syscall, when known.
                        if (!candidate.source.empty()) {
                            data_obs.source = candidate.source;
                        }

                        break;
                    }
                }
            }

            const size_t data_index = runtimexray::append_observation(graph, std::move(data_obs));

            runtimexray::LineageEdge edge;

            edge.from_index = process_index;

            edge.to_index = data_index;

            edge.relation = runtimexray::RelationType::ObservedIn;

            const auto zero_time = std::chrono::steady_clock::time_point{};

            const auto& process_obs = graph.observations[process_index];

            const auto& stored_data_obs = graph.observations[data_index];

            if (process_obs.start_time != zero_time &&
                stored_data_obs.start_time != zero_time) {

                edge.time_delta =
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        stored_data_obs.start_time -
                        process_obs.start_time);
            }

            edge.details = "Sensitive data observed in process";

            graph.edges.push_back(std::move(edge));

            if (source_event_index != SIZE_MAX) {
                runtimexray::LineageEdge evidence_edge;

                evidence_edge.from_index = source_event_index;
                evidence_edge.to_index = data_index;
                evidence_edge.relation = runtimexray::RelationType::ObservedAt;

                evidence_edge.details = "Secret extracted from the syscall's captured buffer";

                graph.edges.push_back(std::move(evidence_edge));
            }
        }
    }

    // Capture the path on syscall entry and expose it to the caller so the
    // observation can be stamped for later fd -> path resolution. Findings
    // are NOT emitted here: at entry the syscall has not returned, so we
    // cannot yet distinguish a successful open from an ENOENT/EACCES probe.
    void handle_syscall_open_entry(
        const char *syscall_name,
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        const runtimexray::SyscallEvent& ev,
        std::string& resolved_path)
    {
        uint64_t path_addr = (std::strcmp(syscall_name, "open") == 0) ? ev.arg0 : ev.arg1;
        std::string path = get_path_bytes(backend, ev, path_addr);
        if (!path.empty()) {
            resolved_path = path;
            extra_info = " path=\"" + path + "\"";
        }
    }

    void handle_syscall_connect(
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        const runtimexray::SyscallEvent& ev,
        std::string& resolved_endpoint)
    {
        const uint64_t sockaddr_ptr = ev.arg1;

        const uint64_t addrlen = ev.arg2;

        if (sockaddr_ptr == 0 ||  addrlen == 0 || addrlen > 256) {
            return;
        }

        const auto bytes =
            get_sockaddr_bytes(
                backend,
                ev,
                sockaddr_ptr,
                static_cast<size_t>(addrlen));

        const auto parsed = runtimexray::parse_sockaddr(bytes);

        if (!parsed.valid) {
            return;
        }

        resolved_endpoint =  parsed.ip + ":" + std::to_string(parsed.port);

        extra_info = " addr=" + resolved_endpoint;
    }

    void handle_syscall_sendto(
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        const runtimexray::SyscallEvent& ev,
        std::string& detected_fingerprint,
        std::vector<runtimexray::Observation>& secret_observations)
    {
        const uint64_t buf_ptr =
            ev.arg1;

        const uint64_t count =
            ev.arg2;

        if (buf_ptr == 0 ||
            count == 0 ||
            count > 4096) {
            return;
        }

        const auto bytes =
            get_buffer_bytes(
                backend,
                ev,
                buf_ptr,
                static_cast<size_t>(count));

        if (bytes.empty()) {
            return;
        }

        const std::string raw(
            reinterpret_cast<const char*>(
                bytes.data()),
            bytes.size());

        const std::string data_str =
            runtimexray::sanitize_data(bytes);

        extra_info =
            " sockfd=" +
            std::to_string(ev.arg0) +
            " data=\"" +
            data_str +
            "\"";

        auto extracted =
            runtimexray::extract_secret_observations(
                raw,
                "sendto_data",
                ev.pid,
                static_cast<uintptr_t>(buf_ptr));

        if (!extracted.empty()) {
            detected_fingerprint =
                extracted.front().fingerprint;

            for (auto& observation : extracted) {
                secret_observations.push_back(
                    std::move(observation));
            }
        }
    }

    void handle_syscall_write(
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        const runtimexray::SyscallEvent& ev,
        std::string& detected_fingerprint,
        std::vector<runtimexray::Observation>& secret_observations)
    {
        const uint64_t fd =
            ev.arg0;

        const uint64_t buf_ptr =
            ev.arg1;

        const uint64_t count =
            ev.arg2;

        if (buf_ptr == 0 ||
            count == 0 ||
            count > 4096) {
            return;
        }

        const auto bytes =
            get_buffer_bytes(
                backend,
                ev,
                buf_ptr,
                static_cast<size_t>(count));

        if (bytes.empty()) {
            return;
        }

        const std::string raw(
            reinterpret_cast<const char*>(
                bytes.data()),
            bytes.size());

        const std::string data_str =
            runtimexray::sanitize_data(bytes);

        extra_info =
            " fd=" +
            std::to_string(fd) +
            " data=\"" +
            data_str +
            "\"";

        const std::string location =
            (fd == 1)
                ? "stdout"
                : (fd == 2)
                    ? "stderr"
                    : "write_data";

        auto extracted =
            runtimexray::extract_secret_observations(
                raw,
                location,
                ev.pid,
                static_cast<uintptr_t>(buf_ptr));

        if (!extracted.empty()) {
            detected_fingerprint =
                extracted.front().fingerprint;

            for (auto& observation : extracted) {
                secret_observations.push_back(
                    std::move(observation));
            }
        }
    }

    void handle_syscall_writev(
        std::unique_ptr<runtimexray::ITraceBackend>& backend,
        std::string& extra_info,
        const runtimexray::SyscallEvent& ev,
        std::string& detected_fingerprint,
        std::vector<runtimexray::Observation>& secret_observations)
    {
        const uint64_t fd =
            ev.arg0;

        const uint64_t iov_ptr =
            ev.arg1;

        const uint64_t iovcnt =
            ev.arg2;

        if (iov_ptr == 0 ||
            iovcnt == 0 ||
            iovcnt > 1024) {
            return;
        }

        const size_t iov_size =
            iovcnt * sizeof(struct iovec);

        const auto iov_bytes =
            backend->read_memory(
            ev.pid,
            iov_ptr,
            iov_size);

        if (iov_bytes.size() < iov_size) {
            return;
        }

        const auto* iov =
            reinterpret_cast<const struct iovec*>(
                iov_bytes.data());

        for (uint64_t i = 0;
            i < iovcnt;
            ++i) {

            const uint64_t buf_ptr =
                reinterpret_cast<uint64_t>(
                    iov[i].iov_base);

            const uint64_t count =
                static_cast<uint64_t>(
                    iov[i].iov_len);

            if (buf_ptr == 0 ||
                count == 0 ||
                count > 4096) {
                continue;
            }

            const auto bytes =
                backend->read_memory(
                    ev.pid,
                    buf_ptr,
                    static_cast<size_t>(count));

            if (bytes.empty()) {
                continue;
            }

            const std::string raw(
                reinterpret_cast<const char*>(
                    bytes.data()),
                bytes.size());

            const std::string data_str =
                runtimexray::sanitize_data(bytes);

            const std::string location =
                (fd == 1)
                    ? "stdout"
                    : (fd == 2)
                        ? "stderr"
                        : "writev_data";

            auto extracted =
                runtimexray::extract_secret_observations(
                    raw,
                    location,
                    ev.pid,
                    static_cast<uintptr_t>(buf_ptr));

            if (!extracted.empty()) {
                if (detected_fingerprint.empty()) {
                    detected_fingerprint =
                        extracted.front().fingerprint;
                }

                for (auto& observation : extracted) {
                    secret_observations.push_back(
                        std::move(observation));
                }
            }

            if (!extra_info.empty()) {
                extra_info += " ";
            }

            extra_info +=
                "iov[" +
                std::to_string(i) +
                "]=" +
                data_str;
        }
    }
} // anonymous namespace

/**
 * @brief Manages memory inspection during one trace session.
 *
 * This class adapts semantic runtime observations to the
 * MemoryScanCoordinator and the existing memory scanner.
 *
 * Responsibilities:
 *
 * - Resolve the current process-image identity.
 * - Capture initial process context once per executable image.
 * - Request bounded memory scans for semantic runtime signals.
 * - Execute authorized scans.
 * - Report actual page usage to the coordinator.
 *
 * It does not:
 *
 * - Classify individual syscalls.
 * - Decide whether a payload contains sensitive information.
 * - Create causal relationships in the lineage graph.
 * - Implement memory-region selection or secret extraction.
 *
 * @note This helper belongs to the trace command rather than
 *       the public memory-scanning API.
 *
 * @note Calls must be serialized. The underlying coordinator
 *       is not thread-safe.
 */
class TraceMemoryScanSession {
public:
    /**
     * @brief Construct a memory-scanning session.
     *
     * @param enabled Whether memory inspection is enabled.
     * @param analyzer Source of active process-image identities.
     * @param observations Destination for detected secrets.
     */
    TraceMemoryScanSession(
    bool enabled,
    const runtimexray::LineageAnalyzer& analyzer,
    std::vector<runtimexray::Observation>& observations,
    runtimexray::MemoryReadBackend memory_reader_backend)
    : enabled_(enabled),
      analyzer_(analyzer),
      observations_(observations),
      memory_reader_backend_(memory_reader_backend),
      coordinator_(make_trace_scan_policy())
    {
    }

    /**
     * @brief Capture argv and environment on first image observation.
     *
     * The command line and environment are inspected once for
     * each observed process executable image.
     *
     * This operation does not consume memory-page budget:
     * it uses the existing /proc cmdline and environ readers.
     *
     * A successful exec creates a new generation, allowing
     * the new executable image to be inspected independently.
     *
     * @param ev Event that may identify a newly observed image.
     */
    void capture_initial_context(const runtimexray::SyscallEvent& ev)
    {
        if (!enabled_ ||
            ev.type != runtimexray::TraceEventType::Syscall ||
            !ev.is_entry) {
            return;
        }

        const auto target = resolve_target(ev);

        if (!target.has_value()) {
            return;
        }

        // Each executable image is inspected only once.
        //
        // The key includes both process lifetime and
        // executable generation, unlike a raw PID.
        if (!startup_scanned_images_.insert(target->image).second) {
            return;
        }

        constexpr size_t kMaxInitialObservations = 50;

        const size_t before = observations_.size();

        runtimexray::scan_cmdline_for_secrets(
            target->tgid,
            observations_,
            kMaxInitialObservations);

        const size_t produced = observations_.size() - before;

        if (produced < kMaxInitialObservations) {
            runtimexray::scan_environ_for_secrets(
                target->tgid,
                observations_,
                kMaxInitialObservations - produced);
        }

        runtimexray::Logger::log(
            runtimexray::LogLevel::Info,
            "Initial process context inspection: TGID=" +
                std::to_string(target->tgid) +
            " instance=" +
                std::to_string(target->image.process_instance_id) +
            " generation=" +
                std::to_string(target->image.exec_generation) +
            " observations=" +
                std::to_string(observations_.size() - before));

        // Stage C: inspect process memory when a new executable image
        // is first observed.
        //
        // This includes:
        // - the initial traced process;
        // - new process instances created through fork/clone;
        // - new executable generations following successful exec.
        //
        // startup_scanned_images_ guarantees this path is entered only
        // once per process image, even for multithreaded applications.
        //
        // No originating syscall event is attached: this inspection
        // is a process-image checkpoint, not proof that the current
        // syscall caused any discovered secret to appear.
        request_scan(
            ev,
            runtimexray::MemoryScanReason::InitialInspection,
            std::nullopt);
    }

    /**
     * @brief Request and perform a semantically triggered memory scan.
     *
     * The caller provides an already-classified semantic reason.
     * This method does not examine syscall names or payloads.
     *
     * The coordinator decides whether a new scan is authorized
     * and determines its page and observation limits.
     *
     * Each authorized scan is accounted for independently,
     * allowing different semantic reasons to request memory
     * inspection at different moments in one process image.
     *
     * @param ev Event identifying the target process.
     * @param reason Semantic reason for scanning.
     * @param event_seq Optional originating lineage event sequence.
     */
    void request_scan(
        const runtimexray::SyscallEvent& ev,
        runtimexray::MemoryScanReason reason,
        std::optional<uint64_t> event_seq)
    {
        if (!enabled_) {
            return;
        }

        const auto target = resolve_target(ev);

        if (!target.has_value()) {
            return;
        }

        const runtimexray::MemoryScanRequest request{
            target->image,
            reason,
            event_seq.value_or(0)
        };

        const auto permit = coordinator_.request_scan(request);

        if (!permit.has_value()) {
            return;
        }

        const size_t before = observations_.size();

        size_t pages_scanned = 0;

        // Inspect process memory only.
        //
        // Initial argv/environment inspection is performed
        // separately by capture_initial_context().
        //
        // The memory scanner is responsible for honoring
        // the resource limits supplied by the permit.
        runtimexray::scan_memory_for_secrets(
            target->tgid,
            observations_,
            memory_reader_backend_,
            permit->max_observations,
            permit->max_pages,
            &pages_scanned);

        // Complete accounting even when no readable memory
        // pages were found. An authorized attempt consumes
        // one scan opportunity.
        //
        // A completion failure indicates an internal contract
        // violation and must not be silently ignored.
        if (!coordinator_.complete_scan(*permit, pages_scanned)) {
            throw std::logic_error("Memory scan coordinator rejected completion");
        }

        runtimexray::Logger::log(
            runtimexray::LogLevel::Info,
            "Runtime memory scan: TGID=" +
                std::to_string(target->tgid) +
            " instance=" +
                std::to_string(target->image.process_instance_id) +
            " generation=" +
                std::to_string(target->image.exec_generation) +
            " reason=" +
                std::string(reason_name(reason)) +
            " pages=" +
                std::to_string(pages_scanned) +
            " observations=" +
                std::to_string(observations_.size() - before));
    }

private:
    /**
     * @brief Configure memory scan budgets for traced process images.
     *
     * Stage C introduces InitialInspection in addition to the existing
     * SensitiveDataDiscovery and DataBoundaryCrossing scans.
     *
     * Each reason may request up to 1000 pages. The trace session must
     * therefore have enough aggregate page budget for three independent
     * scans of the same executable image.
     *
     * This policy is specific to trace sessions. It does not change
     * the generic MemoryScanCoordinator default policy.
     *
     * @return Memory scan policy for a trace session.
     */
    static runtimexray::MemoryScanPolicy make_trace_scan_policy()
    {
        runtimexray::MemoryScanPolicy policy;

        policy.max_pages_per_process_image =
            policy.max_scans_per_process_image *
            policy.max_pages_per_scan;

        return policy;
    }

    /**
     * @brief Resolved runtime process target.
     *
     * The TGID identifies the Linux address space to inspect.
     * The process-image key identifies the budget owner.
     */
    struct ScanTarget {
        pid_t tgid = -1;
        runtimexray::ProcessImageKey image;
    };

    /**
     * @brief Resolve an event to an active process executable image.
     *
     * Uses LineageAnalyzer as the single source of truth
     * for process lifetimes and exec generations.
     *
     * @param ev Runtime event identifying the target.
     * @return Resolved target, or std::nullopt if unavailable.
     */
    std::optional<ScanTarget> resolve_target(const runtimexray::SyscallEvent& ev) const
    {
        // Runtime memory requests currently originate from
        // syscall observations. Semantic lifecycle signals
        // can be supported here in a later integration step.
        if (ev.type != runtimexray::TraceEventType::Syscall) {
            return std::nullopt;
        }

        // A backend may report a worker TID in ev.pid.
        // Memory is shared by threads of the same TGID.
        const pid_t tgid = (ev.tgid > 0) ? ev.tgid : ev.pid;

        if (tgid <= 0) {
            return std::nullopt;
        }

        const auto image = analyzer_.active_process_image(tgid);

        if (!image.has_value()) {
            return std::nullopt;
        }

        return ScanTarget{tgid, *image};
    }

    /**
     * @brief Convert a semantic scan reason to a diagnostic name.
     *
     * Used for logging only. It does not influence policy
     * decisions or scan priority.
     *
     * @param reason Semantic scan reason.
     * @return Human-readable constant string.
     */
    static const char* reason_name(runtimexray::MemoryScanReason reason) noexcept
    {
        using runtimexray::MemoryScanReason;

        switch (reason) {
            case MemoryScanReason::InitialInspection:
                return "InitialInspection";

            case MemoryScanReason::SensitiveDataDiscovery:
                return "SensitiveDataDiscovery";

            case MemoryScanReason::MemoryStateChange:
                return "MemoryStateChange";

            case MemoryScanReason::DataBoundaryCrossing:
                return "DataBoundaryCrossing";

            case MemoryScanReason::ExplicitRequest:
                return "ExplicitRequest";
        }

        return "Unknown";
    }

    bool enabled_ = false;

    const runtimexray::LineageAnalyzer& analyzer_;

    std::vector<runtimexray::Observation>& observations_;

    runtimexray::MemoryReadBackend memory_reader_backend_;

    // Independent semantic scan accounting and page budgets.
    runtimexray::MemoryScanCoordinator coordinator_;

    // Initial context inspection is tracked by process image,
    // not by PID, so exec transitions and PID reuse are handled.
    std::set<runtimexray::ProcessImageKey> startup_scanned_images_;
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

        std::vector<Observation> secret_observations;

        std::optional<nlohmann::json> extra;
        std::string child_output;

        runtimexray::LineageAnalyzer lineage_analyzer;
        lineage_analyzer.set_initial_program(program_);

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
            config.memory_reader = common.memory_reader;

            // Own runtime memory scan policy and accounting for this trace.
            // The session uses LineageAnalyzer for process-image identity.
            TraceMemoryScanSession memory_scans(
                scan_memory_,
                lineage_analyzer,
                secret_observations,
                common.memory_reader);

            config.callback = [&](const runtimexray::SyscallEvent& ev) {
                // Feed the analyzer first. It creates the entry observation and later
                // updates the same observation on exit. All set_* calls below depend
                // on this having already run for the current event.
                lineage_analyzer.on_syscall_event(ev);

                // Capture initial process context before the application
                // has an opportunity to overwrite argv or environment.
                memory_scans.capture_initial_context(ev);

                //
                // Semantic trace events are consumed by the lineage analyzer.
                // They must not fall through into syscall-specific processing.
                //
                if (ev.type != TraceEventType::Syscall) {
                    return;
                }

                // This callback runs during the trace
                const long num = static_cast<long>(ev.syscall_number);

                if (!Logger::is_enabled(LogLevel::Debug) &&
                    !runtimexray::is_interesting_syscall(num)) {
                    return; // skip non-interesting syscalls
                }

                const char *syscall_name = runtimexray::syscall_name(static_cast<long>(ev.syscall_number));
                std::string extra_info;

                // =======================================================================
                // Syscall entry
                // =======================================================================
                if (ev.is_entry) {
                    // ----- Outbound: buffer is valid on entry -----
                    //
                    // If sensitive data is recognized in the syscall payload, stamp the
                    // syscall Observation with the exact-value fingerprint for later
                    // graph-based correlation.
                    const size_t outbound_before = secret_observations.size();
                    std::string payload_fingerprint;

                    if (std::strcmp(syscall_name, "write") == 0) {
                        handle_syscall_write(
                            backend,
                            extra_info,
                            ev,
                            payload_fingerprint,
                            secret_observations);
                    } else if (std::strcmp(syscall_name, "writev") == 0) {
                        handle_syscall_writev(
                            backend,
                            extra_info,
                            ev,
                            payload_fingerprint,
                            secret_observations);
                    } else if (std::strcmp(syscall_name, "sendto") == 0) {
                        handle_syscall_sendto(
                            backend,
                            extra_info,
                            ev,
                            payload_fingerprint,
                            secret_observations);
                    }

                    if (const auto event_seq = lineage_analyzer.pending_event_seq(ev.pid, ev.tid)) {
                        for (size_t i = outbound_before; i < secret_observations.size(); ++i) {
                            secret_observations[i].source_event_seq = *event_seq;
                        }
                    }

                    if (!payload_fingerprint.empty()) {
                        lineage_analyzer.set_pending_event_fingerprint(
                            ev.pid,
                            ev.tid,
                            payload_fingerprint);
                    }

                    // Convert the observed outbound boundary into a semantic
                    // memory inspection request. Scan policy belongs to the
                    // coordinator, not to this syscall handler.
                    if (std::strcmp(syscall_name, "sendto") == 0 ||
                        !payload_fingerprint.empty()) {

                        memory_scans.request_scan(
                            ev,
                            MemoryScanReason::DataBoundaryCrossing,
                            lineage_analyzer.pending_event_seq(ev.pid, ev.tid));
                    }

                    std::string resolved;

                    if (std::strcmp(syscall_name, "open") == 0 ||
                        std::strcmp(syscall_name, "openat") == 0) {

                        handle_syscall_open_entry(
                            syscall_name,
                            backend,
                            extra_info,
                            ev,
                            resolved);

                        if (!resolved.empty()) {
                            lineage_analyzer.set_pending_event_source(
                                ev.pid,
                                ev.tid,
                                resolved);
                        }

                    } else if (std::strcmp(syscall_name, "connect") == 0) {

                        handle_syscall_connect(
                            backend,
                            extra_info,
                            ev,
                            resolved);

                        if (!resolved.empty()) {
                            lineage_analyzer.set_pending_event_source(
                                ev.pid,
                                ev.tid,
                                resolved);
                        }
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
                                " entry (pid=" + std::to_string(ev.pid) +
                                ", tid=" + std::to_string(ev.tid) + ")" + safe_extra,
                            "syscall " + std::to_string(ev.syscall_number) + ": " + syscall_name +
                                " entry (pid=" + std::to_string(ev.pid) +
                                ", tid=" + std::to_string(ev.tid) + ")" + extra_info
                        );
                    }
                    return;
                }

                // =======================================================================
                // Syscall exit
                // =======================================================================
                const char* name = runtimexray::syscall_name(static_cast<long>(ev.syscall_number));

                // Existing child tracking.
                if ((strcmp(name, "fork") == 0 || strcmp(name, "vfork") == 0 ||
                    strcmp(name, "clone") == 0) && ev.return_value > 0) {
                    pid_t child = static_cast<pid_t>(ev.return_value);
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

                // ----- Inbound: userspace buffer is only valid on exit -----
                // read(fd, buf, count) and recvfrom(sockfd, buf, len, ...) both put the
                // received bytes in arg1 and return the valid byte count.
                if ((strcmp(name, "read") == 0 || strcmp(name, "recvfrom") == 0)
                    && ev.return_value > 0)
                {
                    std::vector<std::byte> bytes;
                    size_t actual  = static_cast<size_t>(ev.return_value);

                    if (!ev.captured_payload.empty()) {
                        // eBPF: bytes were captured in-kernel at syscall exit.
                        bytes = ev.captured_payload;
                    } else {
                        // ptrace: read from target memory
                        uint64_t buf_ptr = ev.arg1;
                        if (buf_ptr != 0 && actual > 0 && actual <= 65536) {
                            bytes = backend->read_memory(ev.pid, buf_ptr, actual);
                        }
                    }

                    if (!bytes.empty()) {
                        // Detection runs on raw bytes, sanitize_data is only for logging.
                        std::string raw(reinterpret_cast<const char*>(bytes.data()), bytes.size());
                        std::string printable = runtimexray::sanitize_data(bytes);
                        std::string location = (std::strcmp(name, "read") == 0) ? "read" : "recvfrom";

                        auto extracted =
                            extract_secret_observations(
                                raw,
                                location,
                                ev.pid,
                                static_cast<uintptr_t>(ev.arg1));

                        const bool sensitive_payload = !extracted.empty();
                        if (sensitive_payload) {
                            //
                            // Fingerprint on the syscall Event means the sensitive value was
                            // observed in this syscall payload.
                            //
                            lineage_analyzer.set_last_exit_fingerprint(
                                ev.pid,
                                ev.tid,
                                extracted.front().fingerprint);

                            const auto event_seq = lineage_analyzer.last_exit_event_seq(ev.pid, ev.tid);

                            for (auto& observation : extracted) {
                                if (event_seq) {
                                    observation.source_event_seq = *event_seq;
                                }
                                secret_observations.push_back(std::move(observation));
                            }
                        }

                        // Sensitive data was observed in an inbound buffer.
                        // Its discovery may justify inspecting the current
                        // process memory independently of earlier scans.
                        if (sensitive_payload) {
                            memory_scans.request_scan(
                                ev,
                                MemoryScanReason::SensitiveDataDiscovery,
                                lineage_analyzer.last_exit_event_seq(ev.pid, ev.tid));
                        }

                        Logger::log_sensitive(
                            LogLevel::Debug,
                            std::string("read exit pid=") + std::to_string(ev.pid) +
                                " fd=" + std::to_string(ev.arg0) +
                                " n="  + std::to_string(actual) + " <redacted>",
                            std::string("read exit pid=") + std::to_string(ev.pid) +
                                " fd=" + std::to_string(ev.arg0) +
                                " n="  + std::to_string(actual) +
                                " data=\"" + printable + "\"");
                    }
                }

                // Existing exit logging.
                if (Logger::is_enabled(LogLevel::Debug)) {
                    std::string line = "syscall " + std::to_string(ev.syscall_number) + ": " +
                                    syscall_name +
                                    " exit (pid=" + std::to_string(ev.pid) +
                                    ", tid=" + std::to_string(ev.tid) + ") " +
                                    std::to_string(ev.return_value);
                    Logger::log(LogLevel::Debug, line);
                }
            };

            backend->trace(config);

            // ---- Produce completed lineage graph ----
            auto graph = lineage_analyzer.produce_graph();

            // ---- Child output handling ----
            child_output = backend->child_output_path();

            if (!child_output.empty()) {
                Logger::log(
                    LogLevel::Debug,
                    "Child output saved to " +
                        child_output +
                        " (for debugging)");
            }

            //
            // Memory scanner produced Observations, not Findings.
            //
            // Attach those observations to the completed lineage graph before any
            // security detection is executed.
            //
            append_data_observations_to_graph(
                graph,
                secret_observations);

            //
            // Security detection starts only after the complete evidence graph exists.
            //
            DetectionEngine detection_engine(DetectionRuleRegistry::instance());

            FindingList findings = detection_engine.detect(graph);

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
                  << "[--memory-reader proc|vmread] "
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
        std::cout << "  --scan-memory         Scan process memory for secrets\n";
        std::cout << "  --memory-reader READER  Select memory reader (proc or vmread, default: proc)\n";
        std::cout << "  --backend BACKEND     Select tracing backend (ptrace or ebpf, default: ptrace)\n";
        std::cout << "  --help                Show this help\n";
    }

} // namespace runtimexray
