
/**
 * @file    lineage_analyzer.hpp
 * @brief   Builds a lineage graph from syscall events.
 *
 * Tracks process lifetimes, executable-image generations,
 * syscall observations, and resource relationships.
 *
 * Exposes read-only access to active process-image identities
 * for components that maintain process-scoped runtime state.
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
#include "process_image_key.hpp"
#include "tachikoma.hpp"
#include "itrace_backend.hpp"

#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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

    /**
     * @brief Get the identity of an active process executable image.
     *
     * Resolves a Linux thread-group ID to its currently active
     * RuntimeXRay process instance and executable-image generation.
     *
     * The process instance is allocated by LineageAnalyzer when
     * the process is first observed. Its exec generation advances
     * after each successfully observed exec transition.
     *
     * This method is read-only:
     *
     * - It does not create a process observation.
     * - It does not allocate a process-instance ID.
     * - It does not modify executable-image generations.
     * - It does not reactivate terminated processes.
     *
     * A process that is unknown or no longer active has no
     * available process-image identity.
     *
     * @param tgid Linux thread-group ID of the target process.
     * @return Current process-image identity, or std::nullopt
     *         if the process is not known to be active.
     *
     * @note Call after on_syscall_event() has processed the
     *       relevant runtime event so the returned identity
     *       reflects the latest observed process state.
     */
    std::optional<ProcessImageKey> active_process_image(pid_t tgid) const;

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
        // Identity of the underlying Linux kernel object, when known.
        //
        // Examples:
        //   pipe:[123456]
        //   socket:[789012]
        //
        // This is separate from RuntimeXRay's resource_id.
        //
        // A matching key alone does not establish data flow or
        // prove that two observations occurred on the same
        // descriptor lifetime.
        //
        // Empty when identity is unavailable or unsupported.
        std::string kernel_object_key;
    };

    // RuntimeXRay-local resource allocator.
    // 0 means "unassigned".
    uint64_t next_resource_id_ = 1;

    // process_instance_id -> fd -> resource
    std::unordered_map<uint64_t, std::unordered_map<int, FdResourceBinding>> fd_bindings_by_instance_;

    /**
     * @brief Initial FD discovery snapshot for each process instance.
     *
     * Unlike fd_bindings_by_instance_, this snapshot is immutable
     * during normal FD operations.
     *
     * It records the resource identity observed when a process
     * instance was first inspected through /proc.
     *
     * The snapshot survives close(), dup(), and FD-number reuse.
     * It allows a late TaskCreate notification to reconcile
     * historical observations without modifying the child's
     * current FD table.
     *
     * Key:
     *   process_instance_id -> fd -> initial binding
     *
     * This is not a complete FD lifetime history. It only preserves
     * identities established during initial discovery.
     *
     * Entries are removed when the process instance terminates.
     */
    std::unordered_map<uint64_t, std::unordered_map<int, FdResourceBinding>> initial_fd_bindings_by_instance_;

    // Process instances whose initial FD table has already been inherited
    // from their parent.
    //
    // Needed because TaskCreate may initialize the child before the
    // fork/clone syscall exit is observed. The later syscall exit must not
    // overwrite FD changes already made by the child.
    std::unordered_set<uint64_t> fd_inheritance_initialized_instances_;

    // Process instances whose pre-existing FD snapshot has been inspected.
    //
    // Discovery is attempted once, on the first observed syscall entry.
    // A discovered descriptor must never replace an existing binding
    // established through observed open/pipe/dup or fork inheritance.
    //
    // This is separate from fd_inheritance_initialized_instances_:
    // inheritance and /proc discovery are different operations.
    std::unordered_set<uint64_t> fd_discovery_initialized_instances_;

    std::unordered_map<pid_t, uint64_t> task_create_parent_instance_by_child_tid_;

    /**
     * @brief Register previously unknown descriptors for a process instance.
     *
     * Inspects /proc/<tgid>/fd and creates RuntimeXRay-local resource
     * identities for descriptors not already present in the FD map.
     *
     * Does not overwrite observed or inherited resource identities.
     * Does not construct DataFlow or causality edges.
     *
     * @param tgid Linux thread-group ID.
     * @param instance_id RuntimeXRay process-instance identity.
     */
    void discover_initial_fd_bindings(pid_t tgid, uint64_t instance_id);

    /**
     * @brief Reconcile FD identities after late child discovery.
     *
     * TaskCreate may arrive after the child has already been observed.
     * In that case, the child may have independently discovered FDs
     * inherited from its parent and allocated different resource IDs.
     *
     * Reconciliation requires matching kernel-object identities.
     * Unknown or conflicting identities must remain independent.
     *
     * Existing child FD changes must not be overwritten.
     *
     * @param parent_instance_id Parent process-instance identity.
     * @param child_instance_id Child process-instance identity.
     */
    void reconcile_child_fd_bindings(uint64_t parent_instance_id, uint64_t child_instance_id);

    /**
     * @brief Replace one resource identity with another.
     *
     * Updates current FD bindings and existing observations so the
     * lineage graph remains consistent after reconciliation.
     *
     * This function does not create DataFlow edges.
     *
     * @param old_resource_id Resource identity being replaced.
     * @param new_resource_id Canonical resource identity.
     */
    void remap_resource_identity(uint64_t old_resource_id, uint64_t new_resource_id);

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
