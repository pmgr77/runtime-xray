/**
 * @file    process_lineage_analyzer.cpp
 * @brief   Builds a lineage graph from syscall events.
 *
 * @author  Peter Magram
 * @date    2026-08-31
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

#include "lineage_analyzer.hpp"
#include "syscall_names.hpp"
#include "logger.hpp"
#include <cstring>
#include <chrono>
#include <linux/sched.h>

namespace runtimexray {

LineageAnalyzer::LineageAnalyzer() {
    // Reserve some space to avoid frequent reallocations
    observations_.reserve(1024);
    edges_.reserve(2048);
}

size_t LineageAnalyzer::add_observation(const Observation& obs) {
    Observation stored = obs;
    stored.seq = next_seq_++;
    observations_.push_back(std::move(stored));
    return observations_.size() - 1;
}

void LineageAnalyzer::add_edge(size_t from, size_t to,
                                      RelationType rel,
                                      const std::string& details) {
    LineageEdge edge;
    edge.from_index = from;
    edge.to_index = to;
    edge.relation = rel;
    // Compute time delta if both observations have start_time
    if (from < observations_.size() && to < observations_.size()) {
        auto dt = observations_[to].start_time - observations_[from].start_time;
        edge.time_delta = std::chrono::duration_cast<std::chrono::microseconds>(dt);
    } else {
        edge.time_delta = std::chrono::microseconds(0);
    }
    edge.details = details;
    edges_.push_back(edge);
}

size_t LineageAnalyzer::ensure_process(pid_t pid, pid_t tid, pid_t tgid,
                                              const std::string& program) {

    // Process nodes represent Linux thread groups, not individual tasks.
    // ptrace's pid may actually be a worker TID, while tgid identifies
    // the process whose address space/resources the thread belongs to.
    const pid_t process_id = (tgid > 0) ? tgid : pid;

    auto it = process_node_map_.find(process_id);
    if (it != process_node_map_.end()) {
        // Optionally update program name if it was empty
        if (!program.empty() && observations_[it->second].program_name.empty()) {
            observations_[it->second].program_name = program;
        }
        return it->second;
    }

    Observation obs;
    // We'll use Event for process nodes too, but distinguish by syscall_name == "process"
    obs.type = ObservationType::Event;
    obs.pid = process_id;
    obs.tid = tid;
    obs.tgid = process_id;
    obs.program_name = program;
    obs.syscall_name = "process"; // marker
    obs.is_entry = true;
    // For process nodes, we'll use end_time when process exits
    size_t idx = add_observation(obs);
    process_node_map_[process_id] = idx;
    return idx;
}

void LineageAnalyzer::on_syscall_event(const SyscallEvent& ev) {
    Logger::log(LogLevel::Debug,
                "on_syscall_event: pid=" + std::to_string(ev.pid) +
                " tid=" + std::to_string(ev.tid) +
                " tgid=" + std::to_string(ev.tgid) +
                " syscall=" + std::to_string(ev.syscall_number) +
                " entry=" + std::to_string(ev.is_entry));

    pid_t pid = ev.pid;
    // We need to pass tid from SyscallEvent; we'll need to extend it
    pid_t tid = ev.tid;
    pid_t tgid = ev.tgid;

    // Ensure process node exists
    size_t proc_idx = ensure_process(pid, tid, tgid);

    if (ev.is_entry) {
        // Create syscall entry observation
        Observation obs;
        obs.type = ObservationType::Event;
        obs.pid = pid;
        obs.tid = tid;
        obs.tgid = tgid;
        obs.start_time = std::chrono::steady_clock::now();
        obs.syscall_name = syscall_name(static_cast<long>(ev.syscall_number));
        obs.arg0 = ev.arg0;
        obs.arg1 = ev.arg1;
        obs.arg2 = ev.arg2;
        obs.arg3 = ev.arg3;
        obs.arg4 = ev.arg4;
        obs.arg5 = ev.arg5;
        obs.is_entry = true;

        size_t sys_idx = add_observation(obs);

        // Calls edge: process -> syscall
        add_edge(proc_idx, sys_idx, RelationType::Calls);

        // Chronological edge: previous syscall in this thread -> this syscall
        auto& thread_map = thread_last_syscall_[pid];
        auto it = thread_map.find(tid);
        if (it != thread_map.end()) {
            add_edge(it->second, sys_idx, RelationType::Chronological);
        }
        thread_map[tid] = sys_idx;

        // Store pending entry for exit pairing
        pending_entry_[pid][tid] = sys_idx;

        // If this is an execve entry, capture the program name immediately.
        if (obs.syscall_name == "execve") {
            handle_execve_entry(ev);
        }
    } else {
        // Syscall exit
        auto& pending_map = pending_entry_[pid];
        auto it = pending_map.find(tid);
        if (it != pending_map.end()) {
            size_t sys_idx = it->second;
            // Update observation with end time and return value
            auto end_time = std::chrono::steady_clock::now();
            observations_[sys_idx].end_time = end_time;
            observations_[sys_idx].duration = std::chrono::duration_cast<std::chrono::microseconds>(
                end_time - observations_[sys_idx].start_time);
            observations_[sys_idx].return_value = ev.return_value;
            observations_[sys_idx].is_entry = false;

            // Remember the observation we just updated on exit, so a caller can
            // stamp it with a fingerprint after on_syscall_event() returns.
            last_exit_index_[pid][tid] = sys_idx;

            // Remove from pending
            pending_map.erase(it);
            if (pending_map.empty()) {
                pending_entry_.erase(pid);
            }

            // Special handling for fork/clone
            const char* name = syscall_name(static_cast<long>(ev.syscall_number));
            if (strcmp(name, "fork") == 0 ||
                strcmp(name, "vfork") == 0 ||
                strcmp(name, "clone") == 0 ||
                strcmp(name, "clone3") == 0)
            {
                // Copy the information we need before calling the handler.
                // handle_fork_exit() may create a process node, which can grow
                // observations_ and invalidate references into the vector.
                const std::string fork_syscall =
                    observations_[sys_idx].syscall_name;
                const uint64_t clone_flags =
                    observations_[sys_idx].arg0;
                handle_fork_exit(ev, fork_syscall, clone_flags);
            } else if (strcmp(name, "execve") == 0) {
                handle_execve_exit(ev);
            } else if (strcmp(name, "exit_group") == 0 || strcmp(name, "exit") == 0) {
                handle_exit_group(ev);
            }
        }
    }
}

void LineageAnalyzer::set_pending_event_source(pid_t pid, pid_t tid,
                                               const std::string& source) {
    auto pit = pending_entry_.find(pid);
    if (pit == pending_entry_.end())
        return;
    auto tit = pit->second.find(tid);
    if (tit == pit->second.end())
        return;
    if (tit->second < observations_.size()) {
        observations_[tit->second].source = source;
    }
}

void LineageAnalyzer::set_pending_event_fingerprint(pid_t pid, pid_t tid,
                                                    const std::string& fingerprint) {
    auto pit = pending_entry_.find(pid);
    if (pit == pending_entry_.end())
        return;
    auto tit = pit->second.find(tid);
    if (tit == pit->second.end())
        return;
    if (tit->second < observations_.size()) {
        observations_[tit->second].fingerprint = fingerprint;
    }
}

void LineageAnalyzer::set_last_exit_fingerprint(pid_t pid, pid_t tid,
                                                const std::string& fingerprint) {
    auto pit = last_exit_index_.find(pid);
    if (pit == last_exit_index_.end())
        return;
    auto tit = pit->second.find(tid);
    if (tit == pit->second.end())
        return;
    if (tit->second < observations_.size()) {
        observations_[tit->second].fingerprint = fingerprint;
    }
}

void LineageAnalyzer::handle_fork_exit(
    const SyscallEvent& ev,
    std::string syscall_name,
    uint64_t clone_flags) {

    const pid_t child_tid = static_cast<pid_t>(ev.return_value);
    if (child_tid <= 0) {
        return; // fork failed
    }

    const pid_t parent_tgid =
        (ev.tgid > 0) ? ev.tgid : ev.pid;

    //
    // clone(flags, ...)
    //
    // Unlike clone3(), clone() passes the flags directly as arg0,
    // so we can reliably identify CLONE_THREAD here.
    //
    if (syscall_name == "clone") {
        if ((clone_flags & CLONE_THREAD) != 0) {
            Logger::log(
                LogLevel::Debug,
                "lineage: clone created thread tid=" +
                std::to_string(child_tid) +
                " in tgid=" +
                std::to_string(parent_tgid));
            return;
        }
    }

    //
    // clone3(&clone_args, sizeof(clone_args))
    //
    // arg0 is a userspace pointer to struct clone_args, NOT the flags.
    // We intentionally do not classify this child here yet.
    //
    // The child's own syscall events already carry its authoritative
    // TGID, so ensure_process() will still group threads correctly:
    //
    //     child TGID == parent TGID  -> same process node
    //     child TGID != parent TGID  -> separate process node
    //
    // What is temporarily missing is only the parent->child causality
    // edge for process-creating clone3(). We will fix that when we add
    // explicit process-instance/lifecycle tracking.
    //
    if (syscall_name == "clone3") {
        Logger::log(
            LogLevel::Debug,
            "lineage: clone3 child tid=" +
            std::to_string(child_tid) +
            " classification deferred to child TGID");
        return;
    }

    //
    // fork(), vfork(), or clone() without CLONE_THREAD:
    // the returned child TID is the leader of a new thread group.
    //
    const pid_t child_tgid = child_tid;

    size_t child_idx = ensure_process(child_tgid, child_tid, child_tgid);

    // Causality edge: parent process -> child process
    auto parent_it = process_node_map_.find(parent_tgid);
    if (parent_it == process_node_map_.end()) {
        Logger::log(
            LogLevel::Debug,
            "lineage: parent process node missing for tgid=" +
            std::to_string(parent_tgid));
        return;
    }

    add_edge(
        parent_it->second,
        child_idx,
        RelationType::Causality,
        syscall_name + " created child process");
}

void LineageAnalyzer::handle_execve_entry(const SyscallEvent& ev) {
    if (!backend_) {
        Logger::log(LogLevel::Debug, "No backend set for LineageAnalyzer; cannot read execve path.");
        return;
    }
    uint64_t path_addr = ev.arg0;
    std::string path = backend_->read_string(ev.tid, path_addr);
    if (path.empty()) {
        Logger::log(LogLevel::Debug, "handle_execve_entry: read_string returned empty for address 0x" + std::to_string(path_addr));
        return;
    }
    Logger::log(LogLevel::Debug, "handle_execve_entry: path = " + path);
    const pid_t process_id = (ev.tgid > 0) ? ev.tgid : ev.pid;
    auto it = process_node_map_.find(process_id);
    if (it != process_node_map_.end()) {
        observations_[it->second].program_name = path;
        Logger::log(LogLevel::Debug,
            "Updated process node with program name (from execve entry): " + path);
    } else {
        Logger::log(LogLevel::Debug,
            "Process node not found for TGID " + std::to_string(process_id) +
            " (tid=" + std::to_string(ev.tid) + ")");
    }
}

void LineageAnalyzer::handle_execve_exit(const SyscallEvent& ev) {
    // Execve succeeded if return_value == 0
    if (ev.return_value != 0) {
        Logger::log(LogLevel::Debug, "execve failed, return=" + std::to_string(ev.return_value));
        return;
    }
    if (!backend_) {
        Logger::log(LogLevel::Debug, "No backend set for LineageAnalyzer; cannot read execve path.");
        return;
    }

    // arg0 is the path pointer
    uint64_t path_addr = ev.arg0;
    std::string path = backend_->read_string(ev.tid, path_addr);
    if (path.empty()) {
        Logger::log(LogLevel::Debug, "handle_execve_exit: read_string returned empty for address 0x" + std::to_string(path_addr));
    } else {
        Logger::log(LogLevel::Debug, "handle_execve_exit: path = " + path);
        // Update the process node's program name
        const pid_t process_id = (ev.tgid > 0) ? ev.tgid : ev.pid;
        auto it = process_node_map_.find(process_id);
        if (it != process_node_map_.end()) {
            observations_[it->second].program_name = path;
            Logger::log(LogLevel::Debug,
                "Updated process node with program name (from execve exit): " + path);
        } else {
            Logger::log(LogLevel::Debug,
                "Process node not found for TGID " + std::to_string(process_id) +
                " (tid=" + std::to_string(ev.tid) + ")");
        }
    }
    // Note: Execve exit may not always be delivered; we rely on the entry handler for the program name.
    // The exit handler is kept as a fallback for debugging.
}

void LineageAnalyzer::handle_exit_group(const SyscallEvent& ev) {
    const pid_t process_id = (ev.tgid > 0) ? ev.tgid : ev.pid;
    auto it = process_node_map_.find(process_id);
    if (it != process_node_map_.end()) {
        observations_[it->second].end_time = std::chrono::steady_clock::now();
        // Duration is not set for process nodes; we could compute it if we had start.
    }
}

LineageGraph LineageAnalyzer::produce_graph() const {
    LineageGraph graph;
    graph.summary = "Process lineage with " + std::to_string(observations_.size()) + " observations and " +
                    std::to_string(edges_.size()) + " edges";
    graph.observations = observations_;
    graph.edges = edges_;
    return graph;
}

} // namespace runtimexray
