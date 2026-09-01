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

namespace runtimexray {

LineageAnalyzer::LineageAnalyzer() {
    // Reserve some space to avoid frequent reallocations
    observations_.reserve(1024);
    edges_.reserve(2048);
}

size_t LineageAnalyzer::add_observation(const Observation& obs) {
    observations_.push_back(obs);
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

size_t LineageAnalyzer::ensure_process(pid_t pid, pid_t tid,
                                              const std::string& program) {
    auto it = process_node_map_.find(pid);
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
    obs.pid = pid;
    obs.tid = tid;
    obs.program_name = program;
    obs.syscall_name = "process"; // marker
    obs.is_entry = true;
    // For process nodes, we'll use end_time when process exits
    size_t idx = add_observation(obs);
    process_node_map_[pid] = idx;
    return idx; 
}

void LineageAnalyzer::on_syscall_event(const SyscallEvent& ev) {
    Logger::log(LogLevel::Debug, "on_syscall_event: pid=" + std::to_string(ev.pid) +
                 " syscall=" + std::to_string(ev.syscall_number) +
                 " entry=" + std::to_string(ev.is_entry));
    
    pid_t pid = ev.pid;
    // We need to pass tid from SyscallEvent; we'll need to extend it
    pid_t tid = ev.tid;

    // Ensure process node exists
    size_t proc_idx = ensure_process(pid, tid);

    if (ev.is_entry) {
        // Create syscall entry observation
        Observation obs;
        obs.type = ObservationType::Event;
        obs.pid = pid;
        obs.tid = tid;
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

            // Remove from pending
            pending_map.erase(it);
            if (pending_map.empty()) {
                pending_entry_.erase(pid);
            }

            // Special handling for fork/clone
            const char* name = syscall_name(static_cast<long>(ev.syscall_number));
            if (strcmp(name, "fork") == 0 ||
                strcmp(name, "vfork") == 0 ||
                strcmp(name, "clone") == 0) 
            {
                handle_fork_exit(ev);
            } else if (strcmp(name, "execve") == 0) {
                handle_execve_exit(ev);
            } else if (strcmp(name, "exit_group") == 0 || strcmp(name, "exit") == 0) {
                handle_exit_group(ev);
            }
        }
    }
}

void LineageAnalyzer::handle_fork_exit(const SyscallEvent& ev) {
    pid_t child_pid = static_cast<pid_t>(ev.return_value);
    if (child_pid <= 0) return; // fork failed

    // Create child process node
    pid_t parent_pid = ev.pid;
    size_t child_idx = ensure_process(child_pid, child_pid); // tid = pid for process

    // Causality edge: parent process -> child process
    size_t parent_idx = process_node_map_[parent_pid];
    add_edge(parent_idx, child_idx, RelationType::Causality, "fork created child");
}

void LineageAnalyzer::handle_execve_entry(const SyscallEvent& ev) {
    if (!backend_) {
        Logger::log(LogLevel::Debug, "No backend set for LineageAnalyzer; cannot read execve path.");
        return;
    }
    uint64_t path_addr = ev.arg0;
    std::string path = backend_->read_string(path_addr);
    if (path.empty()) {
        Logger::log(LogLevel::Debug, "handle_execve_entry: read_string returned empty for address 0x" + std::to_string(path_addr));
        return;
    }
    Logger::log(LogLevel::Debug, "handle_execve_entry: path = " + path);
    auto it = process_node_map_.find(ev.pid);
    if (it != process_node_map_.end()) {
        observations_[it->second].program_name = path;
        Logger::log(LogLevel::Debug, "Updated process node with program name (from execve entry): " + path);
    } else {
        Logger::log(LogLevel::Debug, "Process node not found for PID " + std::to_string(ev.pid));
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
    std::string path = backend_->read_string(path_addr);
    if (path.empty()) {
        Logger::log(LogLevel::Debug, "handle_execve_exit: read_string returned empty for address 0x" + std::to_string(path_addr));
    } else {
        Logger::log(LogLevel::Debug, "handle_execve_exit: path = " + path);
        // Update the process node's program name
        auto it = process_node_map_.find(ev.pid);
        if (it != process_node_map_.end()) {
            observations_[it->second].program_name = path;
            Logger::log(LogLevel::Debug, "Updated process node with program name");
        } else {
            Logger::log(LogLevel::Debug, "Process node not found for PID " + std::to_string(ev.pid));
        }
    }
    // Note: Execve exit may not always be delivered; we rely on the entry handler for the program name.
    // The exit handler is kept as a fallback for debugging.    
}

void LineageAnalyzer::handle_exit_group(const SyscallEvent& ev) {
    pid_t pid = ev.pid;
    auto it = process_node_map_.find(pid);
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
