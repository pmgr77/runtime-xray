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

std::optional<size_t>
LineageAnalyzer::find_active_process_node(pid_t tgid) const {
    auto active_it = active_process_by_tgid_.find(tgid);
    if (active_it == active_process_by_tgid_.end()) {
        return std::nullopt;
    }

    auto node_it = process_node_by_instance_.find(active_it->second);
    if (node_it == process_node_by_instance_.end()) {
        return std::nullopt;
    }

    return node_it->second;
}

size_t LineageAnalyzer::ensure_process(pid_t pid, pid_t tid, pid_t tgid,
                                              const std::string& program) {

    // Process nodes represent Linux thread groups, not individual tasks.
    // ptrace's pid may actually be a worker TID, while tgid identifies
    // the process whose address space/resources the thread belongs to.
    const pid_t process_id = (tgid > 0) ? tgid : pid;

    //
    // Is this TGID already an active RuntimeXRay process instance?
    //
    if (auto existing = find_active_process_node(process_id)) {
        Observation& process_obs = observations_[*existing];

        if (!program.empty() &&
            process_obs.program_name.empty()) {
            process_obs.program_name = program;
        }

        // Every syscall tells us that this TID is currently part
        // of this process instance.
        active_tids_by_instance_[process_obs.process_instance_id].insert(tid);

        return *existing;
    }

    //
    // New lifetime of this TGID.
    //
    // Linux may reuse TGIDs, but RuntimeXRay never reuses instance IDs.
    //
    const uint64_t instance_id = next_process_instance_id_++;

    std::string process_program = program;
    if (!initial_program_assigned_) {
        if (process_program.empty()) {
            process_program = initial_program_;
        }
        initial_program_assigned_ = true;
    }
    
    Observation obs;
    // We'll use Event for process nodes too, but distinguish by syscall_name == "process"
    obs.type = ObservationType::Event;
    obs.pid = process_id;
    obs.tid = tid;
    obs.tgid = process_id;
    obs.process_instance_id = instance_id;
    obs.exec_generation = 0;
    obs.program_name = process_program;
    obs.syscall_name = "process"; // marker
    obs.is_entry = true;    
    // For process nodes, we'll use end_time when process exits
    size_t idx = add_observation(obs);

    active_process_by_tgid_[process_id] = instance_id;
    process_node_by_instance_[instance_id] = idx;
    active_tids_by_instance_[instance_id].insert(tid);
    exec_generation_by_instance_[instance_id] = 0;

    Logger::log(
        LogLevel::Debug,
        "lineage: created process instance=" +
        std::to_string(instance_id) +
        " tgid=" +
        std::to_string(process_id));

    return idx;
}

void LineageAnalyzer::on_syscall_event(const SyscallEvent& ev)
{
    // Handle TraceEventType::Exec
    // This must happen before normal syscall handling.
    if (ev.type == TraceEventType::Exec) {
        handle_exec_success(ev);
        return;
    }

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
    const uint64_t process_instance_id = observations_[proc_idx].process_instance_id;
    // stamp every syscall with current generation
    uint64_t exec_generation = 0;
    auto generation_it = exec_generation_by_instance_.find(process_instance_id);
    if (generation_it != exec_generation_by_instance_.end()) {
        exec_generation = generation_it->second;
    }

    if (ev.is_entry) {
        // Create syscall entry observation
        Observation obs;
        obs.type = ObservationType::Event;
        obs.pid = pid;
        obs.tid = tid;
        obs.tgid = tgid;
        obs.process_instance_id = process_instance_id;
        obs.exec_generation = exec_generation;
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
        if (is_exec_syscall(static_cast<long>(ev.syscall_number))) {
            handle_execve_entry(ev);
        }

        if (obs.syscall_name == "exit") {
            handle_thread_exit(ev);
        }

        if (obs.syscall_name == "exit_group") {
            handle_exit_group(ev);
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
            } else if (is_exec_syscall(static_cast<long>(ev.syscall_number))) {
                handle_execve_exit(ev);
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

std::optional<uint64_t> LineageAnalyzer::pending_event_seq(pid_t pid, pid_t tid) const
{
    auto pid_it = pending_entry_.find(pid);
    if (pid_it == pending_entry_.end()) {
        return std::nullopt;
    }

    auto tid_it = pid_it->second.find(tid);
    if (tid_it == pid_it->second.end()) {
        return std::nullopt;
    }

    const size_t index = tid_it->second;
    if (index >= observations_.size()) {
        return std::nullopt;
    }

    const uint64_t seq = observations_[index].seq;
    if (seq == 0) {
        return std::nullopt;
    }

    return seq;
}

std::optional<uint64_t> LineageAnalyzer::last_exit_event_seq(pid_t pid, pid_t tid) const
{
    auto pid_it = last_exit_index_.find(pid);
    if (pid_it == last_exit_index_.end()) {
        return std::nullopt;
    }

    auto tid_it = pid_it->second.find(tid);
    if (tid_it == pid_it->second.end()) {
        return std::nullopt;
    }

    const size_t index = tid_it->second;
    if (index >= observations_.size()) {
        return std::nullopt;
    }

    const uint64_t seq = observations_[index].seq;
    if (seq == 0) {
        return std::nullopt;
    }

    return seq;
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

    
    auto parent_idx = find_active_process_node(parent_tgid);
    if (!parent_idx.has_value()) {
        Logger::log(
            LogLevel::Debug,
            "lineage: active parent process node missing for tgid=" +
            std::to_string(parent_tgid));

        return;
    }

    // Causality edge: parent process -> child process
    add_edge(
        *parent_idx,
        child_idx,
        RelationType::Causality,
        syscall_name + " created child process");
}

void LineageAnalyzer::handle_execve_entry(const SyscallEvent& ev) {
    std::string path = ev.captured_path;
    //
    // ptrace does not have kernel-captured path bytes, so fall back
    // to reading target memory while the process is stopped.
    //
    if (path.empty()) {
        if (!backend_) {
            Logger::log(
                LogLevel::Debug,
                "No backend set for LineageAnalyzer; cannot read exec path.");
            return;
        }

        const uint64_t path_addr = is_execveat_syscall(static_cast<long>(ev.syscall_number)) ? ev.arg1 : ev.arg0;

        path = backend_->read_string(ev.tid, path_addr);
    }

    if (path.empty()) {
        Logger::log(
            LogLevel::Debug,
            "lineage: exec path is empty for tid=" +
            std::to_string(ev.tid));
        return;
    }

    pending_exec_path_by_tid_[ev.tid] = path;

    //
    // The exec syscall observation records the requested executable.
    // The process node itself spans all exec generations and therefore
    // must not be renamed on every exec.
    //
    auto pid_it = pending_entry_.find(ev.pid);
    if (pid_it != pending_entry_.end()) {
        auto tid_it = pid_it->second.find(ev.tid);
        if (tid_it != pid_it->second.end() &&
            tid_it->second < observations_.size()) {
            observations_[tid_it->second].program_name = path;
        }
    }

    Logger::log(
        LogLevel::Debug,
        "lineage: pending exec path tid=" +
        std::to_string(ev.tid) +
        " path=" +
        path);
}

void LineageAnalyzer::handle_execve_exit(const SyscallEvent& ev) {
    //
    // A failed exec returns normally to the old image.
    // Therefore the pending target must be discarded and the current
    // exec generation remains unchanged.
    //
    if (ev.return_value < 0) {
        pending_exec_path_by_tid_.erase(ev.tid);

        Logger::log(
            LogLevel::Debug,
            "lineage: execve failed tid=" +
            std::to_string(ev.tid) +
            " return=" +
            std::to_string(ev.return_value));

        return;
    }

    //
    // Successful exec is handled by TraceEventType::Exec.
    //
    // Do not update program_name or exec_generation here.
}

void LineageAnalyzer::handle_exec_success(const SyscallEvent& ev)
{
    const pid_t tgid = (ev.tgid > 0) ? ev.tgid : ev.pid;

    auto process_idx = find_active_process_node(tgid);
    if (!process_idx.has_value()) {
        Logger::log(
            LogLevel::Debug,
            "lineage: exec success but no active process for tgid=" +
            std::to_string(tgid));
        return;
    }

    Observation& process_obs = observations_[*process_idx];
    const uint64_t instance_id = process_obs.process_instance_id;
    uint64_t& generation = exec_generation_by_instance_[instance_id];
    ++generation;

    // Support an interesting case:
    // worker TID 1002 calls exec
    //    ↓
    // Linux de-threads
    //    ↓
    // post-exec task becomes TID 1000
    // The pending path is under 1002, but exec event arrives as 1000.
    auto path_it = pending_exec_path_by_tid_.find(ev.tid);
    if (path_it == pending_exec_path_by_tid_.end() && ev.former_tid > 0) {
        path_it = pending_exec_path_by_tid_.find(ev.former_tid);
    }

    // erase path during successful exec
    if (path_it != pending_exec_path_by_tid_.end()) {
        Logger::log(
            LogLevel::Debug,
            "lineage: erase pending path, exec generation=" +
            std::to_string(generation) +
            " program=" +
            path_it->second);
        pending_exec_path_by_tid_.erase(path_it);
    }

    //
    // Successful exec destroys all other threads in the process.
    //
    // The exec'ing task is the only surviving thread in the new image.
    //
    auto& tids = active_tids_by_instance_[instance_id];
    tids.clear();
    tids.insert(ev.tid);

    Logger::log(
        LogLevel::Debug,
        "lineage: process_instance=" +
        std::to_string(instance_id) +
        " successful exec -> generation=" +
        std::to_string(generation) +
        " tgid=" +
        std::to_string(tgid) +
        " tid=" +
        std::to_string(ev.tid));
}

void LineageAnalyzer::handle_thread_exit(const SyscallEvent& ev)
{
    const pid_t tgid = (ev.tgid > 0) ? ev.tgid : ev.pid;

    auto process_idx = find_active_process_node(tgid);
    if (!process_idx.has_value()) {
        return;
    }

    Observation& process_obs = observations_[*process_idx];
    const uint64_t instance_id = process_obs.process_instance_id;

    auto tids_it = active_tids_by_instance_.find(instance_id);
    if (tids_it == active_tids_by_instance_.end()) {
        return;
    }

    // exit() terminates only the calling thread.
    tids_it->second.erase(ev.tid);

    Logger::log(
        LogLevel::Debug,
        "lineage: thread tid=" +
        std::to_string(ev.tid) +
        " exited process_instance=" +
        std::to_string(instance_id) +
        " remaining_threads=" +
        std::to_string(tids_it->second.size()));

    //
    // Other threads still belong to this process.
    //
    if (!tids_it->second.empty()) {
        return;
    }

    //
    // This was the last observed thread.
    //
    process_obs.end_time = std::chrono::steady_clock::now();

    active_process_by_tgid_.erase(tgid);
    active_tids_by_instance_.erase(instance_id);

    Logger::log(
        LogLevel::Debug,
        "lineage: process instance=" +
        std::to_string(instance_id) +
        " tgid=" +
        std::to_string(tgid) +
        " ended after last thread exit");
}

void LineageAnalyzer::handle_exit_group(const SyscallEvent& ev) {
    const pid_t tgid = (ev.tgid > 0) ? ev.tgid : ev.pid;

    auto process_idx = find_active_process_node(tgid);
    if (!process_idx.has_value()) {
        return;
    }

    Observation& process_obs = observations_[*process_idx];
    process_obs.end_time = std::chrono::steady_clock::now();

    const uint64_t instance_id = process_obs.process_instance_id;

    Logger::log(LogLevel::Debug,
        "lineage: process instance=" +
        std::to_string(instance_id) +
        " tgid=" + std::to_string(tgid) + " ended via exit_group");

    //
    // This TGID is no longer active.
    //
    // If Linux later reuses the same TGID, ensure_process() will allocate
    // a completely new RuntimeXRay process_instance_id.
    //
    active_process_by_tgid_.erase(tgid);
    active_tids_by_instance_.erase(instance_id);
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
