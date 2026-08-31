/**
 * @file    lineage_analyzer.hpp
 * @brief   Builds a lineage graph from syscall events.
 *
 * @author  Peter Magram
 * @date    2026-08-31
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

#ifndef LINEAGE_ANALYZER_HPP
#define LINEAGE_ANALYZER_HPP

#include "lineage.hpp"
#include "tachikoma.hpp"
#include "itrace_backend.hpp"
#include <unordered_map>
#include <vector>

namespace runtimexray {

class LineageAnalyzer {
public:
    LineageAnalyzer();

    void set_backend(const ITraceBackend* backend) { backend_ = backend; }

    /** Call for each syscall event (entry and exit). */
    void on_syscall_event(const SyscallEvent& ev);

    /** After tracing, produce the lineage graph. */
    LineageGraph produce_graph() const;

private:
    const ITraceBackend* backend_ = nullptr;

    // Graph storage
    std::vector<Observation> observations_;
    std::vector<LineageEdge> edges_;

    // Process node map: PID -> index in observations_
    std::unordered_map<pid_t, size_t> process_node_map_;
    
    // For chronological edges: (PID, TID) -> index of last syscall observation
    std::unordered_map<pid_t, std::unordered_map<pid_t, size_t>> thread_last_syscall_;

    // Pending syscall entry: (PID, TID) -> index of entry observation
    std::unordered_map<pid_t, std::unordered_map<pid_t, size_t>> pending_entry_;

    // Helper: get or create process node
    size_t ensure_process(pid_t pid, pid_t tid, const std::string& program = "");

    // Helper: add observation and return index
    size_t add_observation(const Observation &obs);

    // Helper: add edge
    void add_edge(size_t from, size_t to, RelationType rel, const std::string& details = "");

    // Specific handlers
    void handle_fork_exit(const SyscallEvent& ev);
    void handle_execve_exit(const SyscallEvent& ev);
    void handle_exit_group(const SyscallEvent& ev);    
};

} // namespace runtimexray

#endif // LINEAGE_ANALYZER_HPP