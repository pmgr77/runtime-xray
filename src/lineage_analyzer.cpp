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
#include "inherited_fd_discovery.hpp"
#include "syscall_names.hpp"
#include "logger.hpp"
#include <cstring>
#include <chrono>
#include <fcntl.h>
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
    const auto zero_time = std::chrono::steady_clock::time_point{};
    if (from < observations_.size() &&
        to < observations_.size() &&
        observations_[from].start_time != zero_time &&
        observations_[to].start_time != zero_time) {

        const auto dt = observations_[to].start_time - observations_[from].start_time;

        edge.time_delta = std::chrono::duration_cast<std::chrono::microseconds>(dt);
    } else {
        edge.time_delta = std::chrono::microseconds{0};
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

/**
 * @brief Resolve the executable-image identity of an active process.
 *
 * Uses the active TGID-to-instance mapping maintained by
 * LineageAnalyzer and the corresponding exec generation.
 *
 * Does not create, modify, or reactivate process state.
 *
 * @param tgid Linux thread-group ID of the process.
 * @return Current process-image identity, or std::nullopt
 *         if the process is unknown or no longer active.
 */
std::optional<ProcessImageKey>
LineageAnalyzer::active_process_image(pid_t tgid) const
{
    // Resolve the currently active process instance.
    const auto process_it = active_process_by_tgid_.find(tgid);

    if (process_it == active_process_by_tgid_.end()) {
        return std::nullopt;
    }

    const uint64_t instance_id = process_it->second;

    if (instance_id == 0) {
        return std::nullopt;
    }

    // Retrieve the current executable-image generation.
    // find() does not insert missing entries.
    const auto generation_it = exec_generation_by_instance_.find(instance_id);

    if (generation_it == exec_generation_by_instance_.end()) {
        return std::nullopt;
    }

    return ProcessImageKey{
        instance_id,
        generation_it->second
    };
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

        if (!program.empty() && process_obs.program_name.empty()) {
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
    //
    // Process lifetime begins when RuntimeXRay first observes this process
    // instance. end_time is filled when the process exits.
    //
    obs.start_time = std::chrono::steady_clock::now();
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
    if (ev.type == TraceEventType::TaskCreate) {
        handle_task_create(ev);
        return;
    }

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
        // Register previously unknown FDs before stamping this syscall.
        // This includes inherited stdin and other pre-existing descriptors.
        discover_initial_fd_bindings((tgid > 0) ? tgid : pid,  process_instance_id);

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
        stamp_fd_resource(obs);

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

            //
            // A pipe read may complete before RuntimeXRay processes the exit of the
            // write that supplied its bytes.
            //
            // read-side fingerprinting already attempts to create DataFlow immediately.
            // When the corresponding write exit arrives later, retry completed matching
            // reads so DataFlow construction does not depend on syscall-exit delivery
            // order.
            //
            if ((std::strcmp(name, "write") == 0 || std::strcmp(name, "writev") == 0) &&
                !observations_[sys_idx].fingerprint.empty()) {

                reconcile_pipe_dataflow_from_write(sys_idx);
            }

            if ((strcmp(name, "pipe") == 0 || strcmp(name, "pipe2") == 0) &&
                ev.return_value == 0) {
                handle_pipe_exit(ev, sys_idx);
            }

            if (std::strcmp(name, "dup") == 0 ||
                std::strcmp(name, "dup2") == 0 ||
                std::strcmp(name, "dup3") == 0) {
                handle_dup_exit(ev, sys_idx);
            }

            if (std::strcmp(name, "fcntl") == 0) {
                handle_fcntl_exit(ev, sys_idx);
            }

            if (std::strcmp(name, "close") == 0) {
                handle_close_exit(ev, sys_idx);
            }

            if (std::strcmp(name, "open") == 0 ||
                std::strcmp(name, "openat") == 0) {
                handle_open_exit(ev, sys_idx);
            }

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
        link_pipe_dataflow(tit->second);
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

void LineageAnalyzer::handle_task_create(const SyscallEvent& ev) {
    if (ev.parent_tid <= 0 || ev.parent_tgid <= 0 ||
        ev.child_tid <= 0 || ev.child_tgid <= 0) {
        return;
    }

    auto parent_idx = find_active_process_node(ev.parent_tgid);
    if (!parent_idx.has_value()) {
        Logger::log(
            LogLevel::Debug,
            "lineage: TaskCreate parent process missing tgid=" +
            std::to_string(ev.parent_tgid));
        return;
    }

    //
    // New task belongs to the existing process/thread group.
    //
    if (ev.child_tgid == ev.parent_tgid) {
        const uint64_t instance_id = observations_[*parent_idx].process_instance_id;

        active_tids_by_instance_[instance_id].insert(ev.child_tid);

        Logger::log(
            LogLevel::Debug,
            "lineage: TaskCreate registered thread tid=" +
            std::to_string(ev.child_tid) +
            " process_instance=" +
            std::to_string(instance_id));

        return;
    }

    //
    // New process.
    //
    const size_t child_idx = ensure_process(ev.child_tgid, ev.child_tid, ev.child_tgid);

    const uint64_t parent_instance_id = observations_[*parent_idx].process_instance_id;

    const uint64_t child_instance_id = observations_[child_idx].process_instance_id;

    // Remember that this child process was already created through the early
    // TaskCreate path. The corresponding parent fork/clone syscall may return
    // much later (notably with CLONE_VFORK), after the child has already exited.
    task_create_parent_instance_by_child_tid_[ev.child_tid] = parent_instance_id;

    //
    // This may also be encountered later through the fork/clone syscall
    // exit. Initialize exactly once so the late parent syscall exit cannot
    // overwrite close()/dup()/exec() changes already made by the child.
    //
    const bool first_initialization = fd_inheritance_initialized_instances_.insert(child_instance_id).second;
    if (!first_initialization) {
        return;
    }

    auto parent_bindings = fd_bindings_by_instance_.find(parent_instance_id);

    //
    // Always create a child FD-map entry, even if the parent currently has
    // no tracked resources. Presence of this entry represents completed
    // inheritance.
    //
    auto& child_bindings = fd_bindings_by_instance_[child_instance_id];

    // The child may already have executed syscalls before TaskCreate
    // was delivered. Never overwrite bindings discovered or modified
    // during that observation period.
    if (fd_discovery_initialized_instances_.count(child_instance_id) != 0) {
        // Child was observed before TaskCreate.
        // Preserve its FD table and reconcile only matching identities.
        reconcile_child_fd_bindings(parent_instance_id, child_instance_id);
    } else {
        // Normal ordering: child has not performed FD discovery yet
        if (parent_bindings != fd_bindings_by_instance_.end()) {
            child_bindings = parent_bindings->second;
        } else {
            child_bindings.clear();
        }
    }

    add_edge(*parent_idx, child_idx, RelationType::Causality, "kernel task creation");

    Logger::log(
        LogLevel::Debug,
        "lineage: TaskCreate inherited FD bindings parent_instance=" +
        std::to_string(parent_instance_id) +
        " child_instance=" +
        std::to_string(child_instance_id));
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
            //
            // The new task belongs to the parent's existing Linux thread group.
            //
            // Register it immediately rather than waiting for the child's first
            // syscall. Otherwise the thread-group leader may exit first, causing
            // handle_thread_exit() to incorrectly conclude that the whole process
            // instance has ended.
            //
            auto parent_idx = find_active_process_node(parent_tgid);
            if (!parent_idx.has_value()) {
                Logger::log(
                    LogLevel::Debug,
                    "lineage: clone created thread but active parent process "
                    "node is missing for tgid=" +
                    std::to_string(parent_tgid));
                return;
            }
            const uint64_t instance_id = observations_[*parent_idx].process_instance_id;
            active_tids_by_instance_[instance_id].insert(child_tid);
            Logger::log(
                LogLevel::Debug,
                "lineage: clone created thread tid=" +
                std::to_string(child_tid) +
                " in tgid=" +
                std::to_string(parent_tgid) +
                " process_instance=" +
                std::to_string(instance_id));
            return;
        }
    }

    //
    // TaskCreate may have already created and initialized this child.
    //
    // This is especially important for CLONE_VFORK: the child may exec or exit
    // before the parent's clone syscall returns. In that case the child is no
    // longer active here, but we must not create a second process instance.
    //
    auto parent_idx = find_active_process_node(parent_tgid);
    if (!parent_idx.has_value()) {
        Logger::log(
            LogLevel::Debug,
            "lineage: active parent process node missing for tgid=" +
            std::to_string(parent_tgid));
        return;
    }

    const uint64_t parent_instance_id = observations_[*parent_idx].process_instance_id;

    auto task_create_it = task_create_parent_instance_by_child_tid_.find(child_tid);

    if (task_create_it != task_create_parent_instance_by_child_tid_.end() &&
        task_create_it->second == parent_instance_id) {

        task_create_parent_instance_by_child_tid_.erase(task_create_it);

        Logger::log(
            LogLevel::Debug,
            "lineage: fork exit matched earlier TaskCreate child_tid=" +
            std::to_string(child_tid));

        return;
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

    const uint64_t child_instance_id = observations_[child_idx].process_instance_id;

    const bool first_initialization = fd_inheritance_initialized_instances_.insert(child_instance_id).second;

    if (first_initialization) {
        if (fd_discovery_initialized_instances_.count(child_instance_id) != 0) {
            reconcile_child_fd_bindings(parent_instance_id, child_instance_id);
        } else {
            auto bindings_it = fd_bindings_by_instance_.find(parent_instance_id);
            auto& child_bindings = fd_bindings_by_instance_[child_instance_id];
            if (bindings_it != fd_bindings_by_instance_.end()) {
                child_bindings = bindings_it->second;
            } else {
                child_bindings.clear();
            }
        }

        // Causality edge: parent process -> child process.
        // TaskCreate normally creates this earlier. This is the fallback for
        // backends that do not yet emit TaskCreate.
        add_edge(
            *parent_idx,
            child_idx,
            RelationType::Causality,
            syscall_name + " created child process");
    }
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

    //
    // Successful exec closes every descriptor marked FD_CLOEXEC.
    //
    // Remove those bindings before processing events from the new executable
    // image so a later reuse of the same fd number cannot inherit stale
    // RuntimeXRay resource metadata.
    //
    auto bindings_it = fd_bindings_by_instance_.find(instance_id);

    if (bindings_it != fd_bindings_by_instance_.end()) {
        auto& bindings = bindings_it->second;

        for (auto it = bindings.begin(); it != bindings.end(); ) {
            if (it->second.cloexec) {
                it = bindings.erase(it);
            } else {
                ++it;
            }
        }
    }

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
    fd_bindings_by_instance_.erase(instance_id);
    fd_discovery_initialized_instances_.erase(instance_id);
    initial_fd_bindings_by_instance_.erase(instance_id);

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
    fd_bindings_by_instance_.erase(instance_id);
    fd_discovery_initialized_instances_.erase(instance_id);
    initial_fd_bindings_by_instance_.erase(instance_id);
}

LineageGraph LineageAnalyzer::produce_graph() const {
    LineageGraph graph;
    graph.summary = "Process lineage with " +
                    std::to_string(observations_.size()) +
                    " observations and " +
                    std::to_string(edges_.size()) +
                    " edges";
    graph.observations = observations_;
    graph.edges = edges_;
    return graph;
}

/**
 * @brief Discover FD bindings existing before their creation was observed.
 *
 * Only the ptrace backend is supported here: the target is stopped
 * while its syscall entry is being processed.
 *
 * Existing bindings take precedence over /proc discovery.
 * Each unknown descriptor receives a new local resource identity.
 * No causality or DataFlow edges are created.
 */
void LineageAnalyzer::discover_initial_fd_bindings(pid_t tgid, uint64_t instance_id)
{
    if (tgid <= 0 || instance_id == 0 ||
        !backend_ || backend_->name() != "ptrace") {
        return;
    }

    // Attempt discovery once per process instance.
    if (!fd_discovery_initialized_instances_.insert(instance_id).second) {
        return;
    }

    const auto discovered = discover_preexisting_fds(tgid);

    auto& bindings = fd_bindings_by_instance_[instance_id];
    auto& initial_bindings = initial_fd_bindings_by_instance_[instance_id];

    size_t added = 0;

    for (const auto& descriptor : discovered) {
        if (descriptor.fd < 0 || bindings.find(descriptor.fd) != bindings.end()) {
            continue;
        }

        FdResourceBinding binding;
        binding.resource_id = next_resource_id_++;
        binding.type = descriptor.type;
        binding.role = descriptor.role;
        binding.cloexec = descriptor.cloexec;
        binding.kernel_object_key = descriptor.kernel_object_key;

        // Preserve the descriptor identity discovered at process inspection.
        // Subsequent close(), dup(), and open() operations must not change
        // this historical snapshot.
        initial_bindings.emplace(descriptor.fd, binding);

        bindings.emplace(descriptor.fd, std::move(binding));
        ++added;
    }

    Logger::log(
        LogLevel::Debug,
        "lineage: initial FD discovery instance=" +
        std::to_string(instance_id) +
        " tgid=" + std::to_string(tgid) +
        " discovered=" + std::to_string(discovered.size()) +
        " added=" + std::to_string(added));
}

/**
 * @brief Replace an independently discovered resource identity.
 *
 * Resource IDs are unique within one RuntimeXRay analysis.
 *
 * Updates current FD bindings and already recorded observations.
 * Does not create new DataFlow edges.
 */
void LineageAnalyzer::remap_resource_identity(uint64_t old_resource_id, uint64_t new_resource_id)
{
    if (old_resource_id == 0 ||
        new_resource_id == 0 ||
        old_resource_id == new_resource_id) {
        return;
    }

    // Update all live FD bindings referring to the old identity.
    for (auto& instance_entry : fd_bindings_by_instance_) {
        for (auto& fd_entry : instance_entry.second) {
            FdResourceBinding& binding = fd_entry.second;

            if (binding.resource_id == old_resource_id) {
                binding.resource_id = new_resource_id;
            }
        }
    }

    // Update historical discovery snapshots as well.
    //
    // The snapshot preserves descriptor identity and kernel-object
    // metadata, but its RuntimeXRay-local resource ID may be
    // canonicalized after a late parent-child reconciliation.
    for (auto& instance_entry : initial_fd_bindings_by_instance_) {
        for (auto& fd_entry : instance_entry.second) {
            FdResourceBinding& binding = fd_entry.second;

            if (binding.resource_id == old_resource_id) {
                binding.resource_id = new_resource_id;
            }
        }
    }

    // Update observations already recorded before TaskCreate.
    for (Observation& obs : observations_) {
        if (obs.resource_id == old_resource_id) {
            obs.resource_id = new_resource_id;
        }
    }

    // Keep existing DataFlow edge descriptions consistent.
    const std::string old_details =
        "exact fingerprint observed across pipe resource_id=" +
        std::to_string(old_resource_id);

    const std::string new_details =
        "exact fingerprint observed across pipe resource_id=" +
        std::to_string(new_resource_id);

    for (LineageEdge& edge : edges_) {
        if (edge.relation == RelationType::DataFlow &&
            edge.details == old_details) {
            edge.details = new_details;
        }
    }

    Logger::log(
        LogLevel::Debug,
        "lineage: remapped resource identity old=" +
        std::to_string(old_resource_id) +
        " new=" +
        std::to_string(new_resource_id));
}

/**
 * @brief Reconcile independently discovered inherited FD identities.
 *
 * Uses initial discovery snapshots rather than current FD tables.
 *
 * This allows historical observations to be reconciled even when
 * the child has already closed or replaced its inherited descriptor.
 *
 * Reconciliation requires:
 *   - Confirmed parent-child process relationship.
 *   - Matching FD numbers at initial discovery.
 *   - Matching non-empty kernel-object keys.
 *   - Matching supported resource types and descriptor roles.
 *
 * Current FD tables are never overwritten with parent bindings.
 * No DataFlow edges are created.
 */
void LineageAnalyzer::reconcile_child_fd_bindings(uint64_t parent_instance_id, uint64_t child_instance_id)
{
    const auto parent_it = initial_fd_bindings_by_instance_.find(parent_instance_id);

    const auto child_it = initial_fd_bindings_by_instance_.find(child_instance_id);

    if (parent_it == initial_fd_bindings_by_instance_.end() ||
        child_it == initial_fd_bindings_by_instance_.end()) {
        return;
    }

    for (const auto& child_entry : child_it->second) {
        const int fd = child_entry.first;
        const FdResourceBinding& child_binding = child_entry.second;

        const auto parent_fd_it = parent_it->second.find(fd);

        if (parent_fd_it == parent_it->second.end()) {
            continue;
        }

        const FdResourceBinding& parent_binding = parent_fd_it->second;

        if (child_binding.resource_id == 0 ||
            parent_binding.resource_id == 0 ||
            child_binding.kernel_object_key.empty() ||
            parent_binding.kernel_object_key.empty()) {
            continue;
        }

        // Currently supported kernel-object identities.
        if (child_binding.type != "pipe" &&
            child_binding.type != "socket") {
            continue;
        }

        if (child_binding.type != parent_binding.type ||
            child_binding.role != parent_binding.role ||
            child_binding.kernel_object_key !=
                parent_binding.kernel_object_key) {
            continue;
        }

        if (child_binding.resource_id == parent_binding.resource_id) {
            continue;
        }

        Logger::log(
            LogLevel::Debug,
            "lineage: reconciling inherited FD=" +
            std::to_string(fd) +
            " parent_instance=" +
            std::to_string(parent_instance_id) +
            " child_instance=" +
            std::to_string(child_instance_id) +
            " old_resource=" +
            std::to_string(child_binding.resource_id) +
            " new_resource=" +
            std::to_string(parent_binding.resource_id));

        remap_resource_identity(child_binding.resource_id, parent_binding.resource_id);
    }
}

void LineageAnalyzer::stamp_fd_resource(Observation& obs) const {
    if (obs.process_instance_id == 0) {
        return;
    }

    const bool has_fd_arg =
        obs.syscall_name == "read" ||
        obs.syscall_name == "write" ||
        obs.syscall_name == "writev" ||
        obs.syscall_name == "recvfrom" ||
        obs.syscall_name == "sendto" ||
        obs.syscall_name == "close" ||
        obs.syscall_name == "dup" ||
        obs.syscall_name == "dup2" ||
        obs.syscall_name == "dup3";

    if (!has_fd_arg) {
        return;
    }

    const auto process_it = fd_bindings_by_instance_.find(obs.process_instance_id);
    if (process_it == fd_bindings_by_instance_.end()) {
        return;
    }

    const int fd = static_cast<int>(obs.arg0);
    const auto fd_it = process_it->second.find(fd);
    if (fd_it == process_it->second.end()) {
        return;
    }

    obs.resource_id = fd_it->second.resource_id;
    obs.resource_type = fd_it->second.type;
    obs.resource_role = fd_it->second.role;
    if (obs.source.empty()) {
        obs.source = fd_it->second.source;
    }
}

void LineageAnalyzer::handle_pipe_exit(const SyscallEvent& ev, size_t syscall_index) {

    if (ev.return_value != 0) {
        return;
    }
    if (syscall_index >= observations_.size()) {
        return;
    }
    Observation& pipe_obs = observations_[syscall_index];
    const uint64_t pipefd_addr = pipe_obs.arg0;
    if (pipefd_addr == 0) {
        return;
    }

    int fds[2] = {-1, -1};
    if (ev.has_captured_pipe_fds) {
        fds[0] = ev.captured_pipe_fd0;
        fds[1] = ev.captured_pipe_fd1;
    } else {
        if (!backend_) {
            return;
        }
        const auto bytes = backend_->read_memory(ev.pid, pipefd_addr, sizeof(int) * 2);
        if (bytes.size() != sizeof(int) * 2) {
            Logger::log(
                LogLevel::Debug,
                "lineage: failed to read pipefd array from pid=" +
                std::to_string(ev.pid) +
                " addr=0x" + std::to_string(pipefd_addr));
            return;
        }
        std::memcpy(fds, bytes.data(), sizeof(fds));
    }

    if (fds[0] < 0 || fds[1] < 0) {
        Logger::log(
            LogLevel::Debug,
            "lineage: invalid pipefd values from pid=" +
            std::to_string(ev.pid) +
            " addr=0x" + std::to_string(pipefd_addr));
        return;
    }

    const uint64_t resource_id = next_resource_id_++;

    const bool cloexec =
        pipe_obs.syscall_name == "pipe2" &&
        (pipe_obs.arg1 & O_CLOEXEC) != 0;

    auto& fd_map = fd_bindings_by_instance_[pipe_obs.process_instance_id];
    fd_map[fds[0]] = {resource_id, "pipe", "read", cloexec, "", ""};
    fd_map[fds[1]] = {resource_id, "pipe", "write", cloexec, "", ""};
    pipe_obs.resource_id = resource_id;
    pipe_obs.resource_type = "pipe";
    Logger::log(
        LogLevel::Debug,
        "lineage: pipe resource=" +
        std::to_string(resource_id) +
        " read_fd=" +
        std::to_string(fds[0]) +
        " write_fd=" +
        std::to_string(fds[1]) +
        " process_instance=" +
        std::to_string(pipe_obs.process_instance_id));
}

void LineageAnalyzer::handle_close_exit(const SyscallEvent& ev, size_t syscall_index) {

    if (ev.return_value != 0 || syscall_index >= observations_.size()) {
        return;
    }

    const Observation& close_obs = observations_[syscall_index];

    auto process_it = fd_bindings_by_instance_.find(close_obs.process_instance_id);
    if (process_it == fd_bindings_by_instance_.end()) {
        return;
    }

    const int fd = static_cast<int>(close_obs.arg0);
    process_it->second.erase(fd);
}

void LineageAnalyzer::handle_dup_exit(const SyscallEvent& ev, size_t syscall_index)
{
    if (ev.return_value < 0 || syscall_index >= observations_.size()) {
        return;
    }

    const Observation& dup_obs = observations_[syscall_index];

    const int oldfd = static_cast<int>(dup_obs.arg0);
    const int newfd = static_cast<int>(dup_obs.return_value);

    auto instance_it = fd_bindings_by_instance_.find(dup_obs.process_instance_id);
    if (instance_it == fd_bindings_by_instance_.end()) {
        return;
    }

    auto& bindings = instance_it->second;

    //
    // dup2(oldfd, oldfd) is a successful no-op.
    // It must not change FD_CLOEXEC.
    //
    if (dup_obs.syscall_name == "dup2" && oldfd == newfd) {
        return;
    }

    auto source_it = bindings.find(oldfd);
    if (source_it == bindings.end()) {
        //
        // A successful dup2()/dup3() replaces newfd even when oldfd is
        // not one of the resources RuntimeXRay currently tracks.
        //
        bindings.erase(newfd);
        return;
    }

    FdResourceBinding new_binding = source_it->second;

    //
    // Linux descriptor semantics:
    //
    // dup()  -> new descriptor has FD_CLOEXEC cleared
    // dup2() -> new descriptor has FD_CLOEXEC cleared
    // dup3() -> O_CLOEXEC controls FD_CLOEXEC on the new descriptor
    //
    new_binding.cloexec = false;

    if (dup_obs.syscall_name == "dup3") {
        new_binding.cloexec =
            (dup_obs.arg2 & O_CLOEXEC) != 0;
    }

    bindings[newfd] = std::move(new_binding);
}

void LineageAnalyzer::handle_fcntl_exit(const SyscallEvent& ev, size_t syscall_index)
{
    if (ev.return_value < 0 || syscall_index >= observations_.size()) {
        return;
    }

    const Observation& fcntl_obs = observations_[syscall_index];

    const int fd = static_cast<int>(fcntl_obs.arg0);
    const int cmd = static_cast<int>(fcntl_obs.arg1);

    auto instance_it = fd_bindings_by_instance_.find(fcntl_obs.process_instance_id);
    if (instance_it == fd_bindings_by_instance_.end()) {
        return;
    }

    auto& bindings = instance_it->second;

    //
    // fcntl(fd, F_DUPFD, ...)
    // fcntl(fd, F_DUPFD_CLOEXEC, ...)
    //
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        const int newfd = static_cast<int>(ev.return_value);

        auto source_it = bindings.find(fd);
        if (source_it == bindings.end()) {
            bindings.erase(newfd);
            return;
        }

        FdResourceBinding new_binding = source_it->second;

        new_binding.cloexec =
            (cmd == F_DUPFD_CLOEXEC);

        bindings[newfd] = std::move(new_binding);
        return;
    }

    //
    // fcntl(fd, F_SETFD, flags)
    //
    if (cmd == F_SETFD) {
        auto binding_it = bindings.find(fd);
        if (binding_it == bindings.end()) {
            return;
        }

        const int flags = static_cast<int>(fcntl_obs.arg2);

        binding_it->second.cloexec =
            (flags & FD_CLOEXEC) != 0;
    }
}

void LineageAnalyzer::handle_open_exit(const SyscallEvent& ev, size_t syscall_index)
{
    if (ev.return_value < 0 || syscall_index >= observations_.size()) {
        return;
    }

    const Observation& open_obs = observations_[syscall_index];

    const int fd = static_cast<int>(ev.return_value);

    uint64_t flags = 0;

    if (open_obs.syscall_name == "open") {
        flags = open_obs.arg1;
    } else if (open_obs.syscall_name == "openat") {
        flags = open_obs.arg2;
    } else {
        return;
    }

    std::string role;

    switch (flags & O_ACCMODE) {
        case O_RDONLY:
            role = "read";
            break;

        case O_WRONLY:
            role = "write";
            break;

        case O_RDWR:
            role = "readwrite";
            break;

        default:
            role = "unknown";
            break;
    }

    FdResourceBinding binding;
    binding.resource_id = next_resource_id_++;
    binding.type = "file";
    binding.role = std::move(role);
    binding.cloexec = (flags & O_CLOEXEC) != 0;
    binding.source = open_obs.source;

    fd_bindings_by_instance_[open_obs.process_instance_id][fd] = std::move(binding);
}

void LineageAnalyzer::link_pipe_dataflow(size_t read_index)
{
    if (read_index >= observations_.size()) {
        return;
    }

    const Observation& read_obs = observations_[read_index];
    if (read_obs.type != ObservationType::Event ||
        read_obs.syscall_name != "read" ||
        read_obs.return_value <= 0 ||
        read_obs.resource_id == 0 ||
        read_obs.resource_type != "pipe" ||
        read_obs.resource_role != "read" ||
        read_obs.fingerprint.empty()) {
        return;
    }

    std::optional<size_t> best_write;
    for (size_t i = 0; i < observations_.size(); ++i) {
        if (i == read_index) {
            continue;
        }

        const Observation& write_obs = observations_[i];
        if (write_obs.type != ObservationType::Event) {
            continue;
        }

        if (write_obs.syscall_name != "write" &&
            write_obs.syscall_name != "writev") {
            continue;
        }

        if (write_obs.return_value <= 0) {
            continue;
        }

        if (write_obs.resource_id != read_obs.resource_id ||
            write_obs.resource_type != "pipe" ||
            write_obs.resource_role != "write") {
            continue;
        }

        if (write_obs.fingerprint != read_obs.fingerprint) {
            continue;
        }

        /*
        * Observation order is not causal order.
        *
        * A blocking read may begin before the supplying write, and the reader may
        * return before the writer itself leaves the write() syscall.
        *
        * The necessary temporal condition is only that the write had already begun
        * by the time the read completed. The actual byte transfer may happen at any
        * point during the write syscall.
        */
        if (write_obs.start_time > read_obs.end_time) {
            continue;
        }

        /*
        * If multiple matching writes exist, prefer the most recently started write
        * that could have supplied this read.
        *
        * Exact byte-stream accounting is not available yet, so this remains a
        * best-supported match among same-resource, same-fingerprint writes.
        */
        if (!best_write.has_value() ||
            observations_[*best_write].start_time < write_obs.start_time) {
            best_write = i;
        }
    }

    if (!best_write.has_value()) {
        return;
    }

    //
    // Linking can be attempted from both sides:
    //
    //   read exit  -> matching completed write
    //   write exit -> already completed matching read
    //
    // Never emit the same proof edge twice.
    //
    for (const LineageEdge& edge : edges_) {
        if (edge.relation == RelationType::DataFlow &&
            edge.from_index == *best_write &&
            edge.to_index == read_index) {
            return;
        }
    }

    add_edge(
        *best_write,
        read_index,
        RelationType::DataFlow,
        "exact fingerprint observed across pipe resource_id=" +
            std::to_string(read_obs.resource_id));
}

void LineageAnalyzer::reconcile_pipe_dataflow_from_write(size_t write_index)
{
    if (write_index >= observations_.size()) {
        return;
    }

    const Observation& write_obs = observations_[write_index];

    if (write_obs.type != ObservationType::Event ||
        (write_obs.syscall_name != "write" &&
         write_obs.syscall_name != "writev") ||
        write_obs.return_value <= 0 ||
        write_obs.resource_id == 0 ||
        write_obs.resource_type != "pipe" ||
        write_obs.resource_role != "write" ||
        write_obs.fingerprint.empty()) {
        return;
    }

    //
    // The write has now completed. A matching read may already have completed
    // earlier from RuntimeXRay's event-delivery perspective and therefore
    // failed to find this write during its original linking attempt.
    //
    // Retry only reads that could possibly belong to this exact transfer.
    //
    for (size_t i = 0; i < observations_.size(); ++i) {

        if (i == write_index) {
            continue;
        }

        const Observation& read_obs = observations_[i];

        if (read_obs.type != ObservationType::Event ||
            read_obs.syscall_name != "read" ||
            read_obs.return_value <= 0 ||
            read_obs.resource_id != write_obs.resource_id ||
            read_obs.resource_type != "pipe" ||
            read_obs.resource_role != "read" ||
            read_obs.fingerprint != write_obs.fingerprint) {
            continue;
        }

        //
        // link_pipe_dataflow() remains the single place that selects the best
        // supplying write and creates the actual DataFlow edge.
        //
        link_pipe_dataflow(i);
    }
}

} // namespace runtimexray
