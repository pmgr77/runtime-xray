/**
 * @file    lineage_analyzer.hpp
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

#ifndef LINEAGE_ANALYZER_HPP
#define LINEAGE_ANALYZER_HPP

#include "lineage.hpp"
#include "tachikoma.hpp"
#include "itrace_backend.hpp"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <optional>

namespace runtimexray {

class LineageAnalyzer {
public:
    LineageAnalyzer();

    void set_backend(const ITraceBackend* backend) { backend_ = backend; }

    void set_initial_program(const std::string& program) { initial_program_ = program; }

    /** Call for each syscall event (entry and exit). */
    void on_syscall_event(const SyscallEvent& ev);

    /** After tracing, produce the lineage graph. */
    LineageGraph produce_graph() const;

    // Attach a resolved string (path or "ip:port") to the in-flight syscall
    // observation for (pid, tid). Called on syscall entry, after
    // on_syscall_event() has created the entry observation.
    void set_pending_event_source(pid_t pid, pid_t tid, const std::string& source);

    // Attach a fingerprint to the in-flight syscall observation for (pid, tid).
    // Called on syscall entry for send-family calls whose buffer contained a
    // detected secret.
    void set_pending_event_fingerprint(pid_t pid, pid_t tid, const std::string& fingerprint);

    // Attach a fingerprint to the observation that was just updated by the
    // most recent syscall exit for (pid, tid). Called on syscall exit for
    // read-family calls whose userspace buffer contained a detected secret.
    void set_last_exit_fingerprint(pid_t pid, pid_t tid, const std::string& fingerprint);

    // syscall currently at entry
    std::optional<uint64_t> pending_event_seq(pid_t pid, pid_t tid) const;

    // syscall just completed
    std::optional<uint64_t> last_exit_event_seq(pid_t pid, pid_t tid) const;

private:
    const ITraceBackend* backend_ = nullptr;

    std::string initial_program_;
    bool initial_program_assigned_ = false;

    struct FdResourceBinding {
        uint64_t resource_id = 0;
        std::string type;
        std::string role;
        bool cloexec = false;
        std::string source;
    };

    // RuntimeXRay-local resource allocator.
    // 0 means "unassigned".
    uint64_t next_resource_id_ = 1;

    // process_instance_id -> fd -> resource
    std::unordered_map<uint64_t, std::unordered_map<int, FdResourceBinding>> fd_bindings_by_instance_;

    // Process instances whose initial FD table has already been inherited
    // from their parent.
    //
    // Needed because TaskCreate may initialize the child before the
    // fork/clone syscall exit is observed. The later syscall exit must not
    // overwrite FD changes already made by the child.
    std::unordered_set<uint64_t> fd_inheritance_initialized_instances_;

    std::unordered_map<pid_t, uint64_t> task_create_parent_instance_by_child_tid_;

    void stamp_fd_resource(Observation& obs) const;

    void handle_pipe_exit(const SyscallEvent& ev, size_t syscall_index);

    void handle_close_exit(const SyscallEvent& ev, size_t syscall_index);

    void handle_dup_exit(const SyscallEvent& ev, size_t syscall_index);

    void handle_fcntl_exit(const SyscallEvent& ev, size_t syscall_index);

    void handle_open_exit(const SyscallEvent& ev, size_t syscall_index);

    void link_pipe_dataflow(size_t read_index);

    void reconcile_pipe_dataflow_from_write(size_t write_index);
    
    // Graph storage
    std::vector<Observation> observations_;
    std::vector<LineageEdge> edges_;

    // Monotonic observation sequence.
    // 0 is reserved for "unassigned".
    uint64_t next_seq_ = 1;

    // RuntimeXRay process instance allocator.
    // 0 is reserved for "unassigned".
    uint64_t next_process_instance_id_ = 1;

    // Active Linux TGID -> RuntimeXRay process instance.
    //
    // A TGID may be reused by Linux after a process exits, so TGID itself
    // must not be the permanent identity of a process in the lineage graph.
    std::unordered_map<pid_t, uint64_t> active_process_by_tgid_;

    // RuntimeXRay process instance -> process observation index.
    std::unordered_map<uint64_t, size_t> process_node_by_instance_;

    // RuntimeXRay process instance -> current executable-image generation.
    //
    // A process begins at generation 0.
    // Every successful exec advances it by one.
    std::unordered_map<uint64_t, uint64_t> exec_generation_by_instance_;

    // RuntimeXRay process instance -> currently observed live TIDs.
    //
    // This lets us distinguish:
    //   one worker thread calling exit()
    // from:
    //   the last thread in a process calling exit().
    std::unordered_map<uint64_t, std::unordered_set<pid_t>> active_tids_by_instance_;

    // Pending exec target path by TID.
    //
    // Captured at execve entry and committed only after a successful
    // exec boundary.
    std::unordered_map<pid_t, std::string> pending_exec_path_by_tid_;

    // For chronological edges: (PID, TID) -> index of last syscall observation
    std::unordered_map<pid_t, std::unordered_map<pid_t, size_t>> thread_last_syscall_;

    // Pending syscall entry: (PID, TID) -> index of entry observation
    std::unordered_map<pid_t, std::unordered_map<pid_t, size_t>> pending_entry_;

    // Index of the observation most recently updated by a syscall exit, keyed
    // by (pid, tid). Used by set_last_exit_fingerprint().
    std::unordered_map<pid_t, std::unordered_map<pid_t, size_t>> last_exit_index_;

    // Helper:
    std::optional<size_t> find_active_process_node(pid_t tgid) const;

    // Helper: get or create process node
    size_t ensure_process(pid_t pid, pid_t tid, pid_t tgid, const std::string& program = "");

    // Helper: add observation and return index
    size_t add_observation(const Observation &obs);

    // Helper: add edge
    void add_edge(size_t from, size_t to, RelationType rel, const std::string& details = "");

    void handle_task_create(const SyscallEvent& ev);
    // Specific handlers
    void handle_fork_exit(const SyscallEvent& ev, std::string syscall_name, uint64_t clone_flags);

    void handle_execve_entry(const SyscallEvent& ev);
    void handle_execve_exit(const SyscallEvent& ev);
    void handle_exec_success(const SyscallEvent& ev);

    void handle_thread_exit(const SyscallEvent& ev);
    void handle_exit_group(const SyscallEvent& ev);
};

} // namespace runtimexray

#endif // LINEAGE_ANALYZER_HPP