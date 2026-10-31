/**
 * @file    test_lineage_fd_discovery_order.cpp
 * @brief   Tests FD identity when TaskCreate arrives late.
 *
 * @author  Peter Magram
 * @date    2026-10-31
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

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

using namespace runtimexray;

void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/**
 * @brief Minimal backend identifying itself as ptrace.
 *
 * No tracing is performed. The real parent and stopped child
 * remain alive while LineageAnalyzer inspects their /proc FDs.
 */
class TestBackend final : public ITraceBackend {
public:
    std::string name() const override { return "ptrace"; }

    pid_t get_pid() const override { return ::getpid(); }

    bool supports_attach() const override { return false; }

    bool supports_function_tracing() const override { return false; }

    bool is_timed_out() const override { return false; }

    std::string child_output_path() const override { return {}; }

    std::string read_string(pid_t, uint64_t, size_t) const override
    {
        return {};
    }

    std::vector<std::byte> read_memory(pid_t, uint64_t, size_t) const override
    {
        return {};
    }

    int trace(const TraceConfig&) override { return -1; }
};

/**
 * @brief Own both pipe descriptors.
 */
class PipeGuard {
public:
    PipeGuard()
    {
        if (::pipe(fds_) != 0) {
            throw std::runtime_error("pipe() failed");
        }
    }

    ~PipeGuard()
    {
        ::close(fds_[0]);
        ::close(fds_[1]);
    }

    PipeGuard(const PipeGuard&) = delete;
    PipeGuard& operator=(const PipeGuard&) = delete;

    int reader() const { return fds_[0]; }
    int writer() const { return fds_[1]; }

private:
    int fds_[2] = {-1, -1};
};

/**
 * @brief Terminate and reap the test child.
 */
class ChildGuard {
public:
    explicit ChildGuard(pid_t pid) : pid_(pid) {}

    ~ChildGuard()
    {
        if (pid_ <= 0) {
            return;
        }

        ::kill(pid_, SIGKILL);

        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 &&
               errno == EINTR) {
        }
    }

    ChildGuard(const ChildGuard&) = delete;
    ChildGuard& operator=(const ChildGuard&) = delete;

private:
    pid_t pid_;
};

/**
 * @brief Wait until the child is stopped.
 */
void wait_for_stopped_child(pid_t child)
{
    int status = 0;
    pid_t result;

    do {
        result = ::waitpid(child, &status, WUNTRACED);
    } while (result < 0 && errno == EINTR);

    require(result == child, "waitpid() failed");
    require(WIFSTOPPED(status), "child is not stopped");
}

/**
 * @brief Build a synthetic read syscall entry.
 */
SyscallEvent make_read(pid_t tgid, int fd)
{
    SyscallEvent ev{};

    ev.type = TraceEventType::Syscall;
    ev.pid = tgid;
    ev.tid = tgid;
    ev.tgid = tgid;
    ev.syscall_number = SYS_read;
    ev.arg0 = static_cast<unsigned long long>(fd);
    ev.is_entry = true;

    return ev;
}

/**
 * @brief Build a synthetic kernel task-creation notification.
 */
SyscallEvent make_task_create(pid_t parent, pid_t child)
{
    SyscallEvent ev{};

    ev.type = TraceEventType::TaskCreate;
    ev.pid = parent;
    ev.tid = parent;
    ev.tgid = parent;
    ev.parent_tid = parent;
    ev.parent_tgid = parent;
    ev.child_tid = child;
    ev.child_tgid = child;

    return ev;
}

/**
 * @brief Find the read observation for one process.
 */
const Observation* find_read(const LineageGraph& graph, pid_t tgid, int fd)
{
    for (const auto& obs : graph.observations) {
        if (obs.type == ObservationType::Event &&
            obs.syscall_name == "read" &&
            obs.tgid == tgid &&
            obs.arg0 == static_cast<uint64_t>(fd)) {
            return &obs;
        }
    }

    return nullptr;
}

struct ResourcePair {
    uint64_t parent = 0;
    uint64_t child = 0;
};

/**
 * @brief Run one controlled event ordering.
 *
 * The pipe is a real inherited Linux resource.
 * Only the ordering of observations is simulated.
 */
ResourcePair run_ordering(pid_t parent, pid_t child, int fd, bool late_task_create)
{
    TestBackend backend;
    LineageAnalyzer analyzer;

    analyzer.set_backend(&backend);

    // Parent discovers the existing pipe first.
    analyzer.on_syscall_event(make_read(parent, fd));

    if (!late_task_create) {
        analyzer.on_syscall_event(make_task_create(parent, child));
    }

    // Child observes the same kernel pipe.
    analyzer.on_syscall_event(make_read(child, fd));

    if (late_task_create) {
        analyzer.on_syscall_event(make_task_create(parent, child));
    }

    const auto graph = analyzer.produce_graph();

    const Observation* parent_read = find_read(graph, parent, fd);

    const Observation* child_read = find_read(graph, child, fd);

    require(parent_read != nullptr, "parent read missing");
    require(child_read != nullptr, "child read missing");

    require(
        parent_read->process_instance_id != child_read->process_instance_id,
        "parent and child share process instance");

    require(
        parent_read->resource_type == "pipe" && child_read->resource_type == "pipe",
        "pipe resource type missing");

    require(
        parent_read->resource_role == "read" && child_read->resource_role == "read",
        "pipe read role missing");

    require(
        parent_read->resource_id != 0 && child_read->resource_id != 0,
        "resource identity missing");

    return {
        parent_read->resource_id, child_read->resource_id
    };
}

/**
 * @brief Verify that late TaskCreate does not merge different pipes.
 *
 * The child replaces its inherited read FD with the read end
 * of another pipe before its first observed syscall.
 *
 * Both processes use the same FD number, but they refer to
 * different kernel objects and must retain different resource IDs.
 */
void test_fd_replacement_no_false_merge()
{
    PipeGuard original_pipe;
    PipeGuard replacement_pipe;

    const pid_t parent = ::getpid();
    const pid_t child = ::fork();

    require(child >= 0, "fork() failed");

    if (child == 0) {
        // Replace the inherited FD with an independent pipe.
        if (::dup2(replacement_pipe.reader(), original_pipe.reader()) != original_pipe.reader()) {
            ::_exit(1);
        }

        // The original FD number now refers to replacement_pipe.
        ::close(replacement_pipe.reader());

        if (::raise(SIGSTOP) != 0) {
            ::_exit(1);
        }

        ::_exit(0);
    }

    ChildGuard child_guard(child);
    wait_for_stopped_child(child);

    // Parent's FD still refers to original_pipe.
    // Child's same-numbered FD refers to replacement_pipe.
    const auto resources = run_ordering(parent, child, original_pipe.reader(), true);

    std::cout
        << "Replacement: parent resource=" << resources.parent
        << " child resource=" << resources.child
        << '\n';

    require(
        resources.parent != resources.child,
        "late TaskCreate incorrectly merged independent pipes"
    );

    std::cout << "PASS: FD replacement preserves independent identities\n";
}


/**
 * @brief Verify historical FD identity after replacement and late TaskCreate.
 *
 * The child first uses an inherited pipe, then closes its read FD
 * and reuses the same number for a different pipe.
 *
 * TaskCreate is delivered only after both child observations.
 *
 * Expected:
 *   - Historical child read matches the parent's original pipe.
 *   - Later child read belongs to the replacement pipe.
 *   - The two child reads have different resource identities.
 */
void test_fd_replacement_after_first_observation()
{
    PipeGuard original_pipe;
    PipeGuard replacement_pipe;

    const pid_t parent = ::getpid();
    const pid_t child = ::fork();

    require(child >= 0, "fork() failed");

    if (child == 0) {
        // Stop before modifying the inherited FD table.
        if (::raise(SIGSTOP) != 0) {
            ::_exit(1);
        }

        if (::close(original_pipe.reader()) != 0) {
            ::_exit(2);
        }

        if (::dup2(
                replacement_pipe.reader(),
                original_pipe.reader()) != original_pipe.reader()) {
            ::_exit(3);
        }

        // Stop again with the replacement FD installed.
        if (::raise(SIGSTOP) != 0) {
            ::_exit(4);
        }

        ::_exit(0);
    }

    ChildGuard child_guard(child);
    wait_for_stopped_child(child);

    TestBackend backend;
    LineageAnalyzer analyzer;
    analyzer.set_backend(&backend);

    const int fd = original_pipe.reader();

    // The parent and child initially refer to the same pipe.
    analyzer.on_syscall_event(make_read(parent, fd));
    analyzer.on_syscall_event(make_read(child, fd));

    // Allow the real child to close and replace its FD.
    require(
        ::kill(child, SIGCONT) == 0,
        "SIGCONT failed"
    );

    wait_for_stopped_child(child);

    // Deliver the child's successful close() events.
    auto close_entry = make_read(child, fd);
    close_entry.syscall_number = SYS_close;

    analyzer.on_syscall_event(close_entry);

    auto close_exit = close_entry;
    close_exit.is_entry = false;
    close_exit.return_value = 0;

    analyzer.on_syscall_event(close_exit);

    // On AArch64 Linux, dup2() is implemented through dup3().
    // Model the successful replacement with the native dup3 event.
    auto dup_entry = make_read(child, replacement_pipe.reader());
    dup_entry.syscall_number = SYS_dup3;
    dup_entry.arg1 = static_cast<unsigned long long>(fd);
    dup_entry.arg2 = 0;

    analyzer.on_syscall_event(dup_entry);

    auto dup_exit = dup_entry;
    dup_exit.is_entry = false;
    dup_exit.return_value = fd;

    analyzer.on_syscall_event(dup_exit);

    // The same FD number now refers to the replacement pipe.
    analyzer.on_syscall_event(make_read(child, fd));

    // Parent-child relationship is delivered last.
    analyzer.on_syscall_event(make_task_create(parent, child));

    const auto graph = analyzer.produce_graph();

    const Observation* parent_read = find_read(graph, parent, fd);

    std::vector<const Observation*> child_reads;

    for (const auto& obs : graph.observations) {
        if (obs.type == ObservationType::Event &&
            obs.syscall_name == "read" &&
            obs.tgid == child &&
            obs.arg0 == static_cast<uint64_t>(fd)) {
            child_reads.push_back(&obs);
        }
    }

    require(parent_read != nullptr, "parent read missing");
    require(child_reads.size() == 2, "expected two child reads");

    const uint64_t parent_original = parent_read->resource_id;
    const uint64_t child_original = child_reads[0]->resource_id;
    const uint64_t child_replacement = child_reads[1]->resource_id;

    require(
        parent_original != 0 &&
        child_original != 0 &&
        child_replacement != 0,
        "resource identity missing"
    );

    std::cout
        << "Historical: parent original=" << parent_original
        << " child original=" << child_original
        << " child replacement=" << child_replacement
        << '\n';

    require(
        child_original != child_replacement,
        "two FD lifetimes incorrectly share resource identity"
    );

    require(
        child_replacement != parent_original,
        "replacement pipe incorrectly merged with original pipe"
    );

    std::cout << "PASS: replacement retains independent identity\n";

    require(
        child_original == parent_original,
        "historical inherited pipe was not reconciled"
    );

    std::cout << "PASS: historical inherited identity reconciled\n";
}

/**
 * @brief Exercise normal and reordered TaskCreate delivery.
 */
void test_fd_discovery_order()
{
    PipeGuard pipe;

    const pid_t parent = ::getpid();
    const pid_t child = ::fork();

    require(child >= 0, "fork() failed");

    if (child == 0) {
        ::raise(SIGSTOP);
        ::_exit(0);
    }

    ChildGuard child_guard(child);
    wait_for_stopped_child(child);

    const int fd = pipe.reader();

    // Baseline: TaskCreate arrives before child's first syscall.
    const auto normal = run_ordering(parent, child, fd, false);

    std::cout
        << "Normal: parent resource=" << normal.parent
        << " child resource=" << normal.child
        << '\n';

    require(
        normal.parent == normal.child,
        "normal TaskCreate lost inherited resource identity");

    std::cout << "PASS: normal TaskCreate ordering\n";

    // Regression: child is observed before TaskCreate arrives.
    const auto late = run_ordering(parent, child, fd, true);

    std::cout
        << "Late: parent resource=" << late.parent
        << " child resource=" << late.child
        << '\n';

    require(
        late.parent == late.child,
        "late TaskCreate lost inherited resource identity");

    std::cout << "PASS: late TaskCreate ordering\n";
}


/**
 * @brief Verify cross-process DataFlow through a pre-existing pipe.
 *
 * The pipe is created before the analyzer observes either process.
 * Parent writes through one endpoint; child reads through the other.
 *
 * Both endpoints must share one RuntimeXRay resource identity.
 * Matching fingerprint evidence must produce a DataFlow edge.
 */
void test_preexisting_pipe_cross_process_dataflow()
{
    PipeGuard pipe;

    const pid_t parent = ::getpid();
    const pid_t child = ::fork();

    require(child >= 0, "fork() failed");

    if (child == 0) {
        if (::raise(SIGSTOP) != 0) {
            ::_exit(1);
        }

        ::_exit(0);
    }

    ChildGuard child_guard(child);
    wait_for_stopped_child(child);

    TestBackend backend;
    LineageAnalyzer analyzer;
    analyzer.set_backend(&backend);

    const std::string fingerprint = "test-pipe-fingerprint";

    // Parent writes to a pipe that existed before tracing.
    auto write_entry = make_read(parent, pipe.writer());
    write_entry.syscall_number = SYS_write;

    analyzer.on_syscall_event(write_entry);

    analyzer.set_pending_event_fingerprint(parent, parent, fingerprint);

    auto write_exit = write_entry;
    write_exit.is_entry = false;
    write_exit.return_value = 1;

    analyzer.on_syscall_event(write_exit);

    // The child inherits both endpoints.
    analyzer.on_syscall_event(make_task_create(parent, child));

    // Child reads from the same underlying pipe.
    auto read_entry = make_read(child, pipe.reader());

    analyzer.on_syscall_event(read_entry);

    auto read_exit = read_entry;
    read_exit.is_entry = false;
    read_exit.return_value = 1;

    analyzer.on_syscall_event(read_exit);

    analyzer.set_last_exit_fingerprint(child, child, fingerprint);

    const auto graph = analyzer.produce_graph();

    const Observation* parent_write = nullptr;
    const Observation* child_read = nullptr;

    for (const auto& obs : graph.observations) {
        if (obs.type != ObservationType::Event) {
            continue;
        }

        if (obs.tgid == parent &&
            obs.syscall_name == "write" &&
            obs.arg0 == static_cast<uint64_t>(pipe.writer())) {
            parent_write = &obs;
        }

        if (obs.tgid == child &&
            obs.syscall_name == "read" &&
            obs.arg0 == static_cast<uint64_t>(pipe.reader())) {
            child_read = &obs;
        }
    }

    require(parent_write != nullptr, "parent write missing");
    require(child_read != nullptr, "child read missing");

    require(
        parent_write->resource_id != 0 &&
        child_read->resource_id != 0,
        "pipe resource identity missing"
    );

    std::cout
        << "Pre-existing pipe: parent write resource="
        << parent_write->resource_id
        << " child read resource="
        << child_read->resource_id
        << '\n';

    require(
        parent_write->resource_id == child_read->resource_id,
        "pre-existing pipe endpoints have different resource IDs"
    );

    bool dataflow_found = false;

    for (const auto& edge : graph.edges) {
        if (edge.relation != RelationType::DataFlow) {
            continue;
        }

        if (edge.from_index >= graph.observations.size() ||
            edge.to_index >= graph.observations.size()) {
            continue;
        }

        const auto& source = graph.observations[edge.from_index];
        const auto& destination = graph.observations[edge.to_index];

        if (source.seq == parent_write->seq &&
            destination.seq == child_read->seq) {
            dataflow_found = true;
            break;
        }
    }

    require(
        dataflow_found,
        "missing cross-process pipe DataFlow edge"
    );

    std::cout
        << "PASS: pre-existing pipe cross-process DataFlow\n";
}

/**
 * @brief Verify DataFlow reconstruction after late TaskCreate.
 *
 * Parent write and child read finish before TaskCreate arrives.
 * Their independently discovered resource IDs initially differ.
 *
 * Late reconciliation must recover the matching pipe identity
 * and establish the previously missing DataFlow edge.
 */
void test_late_task_create_restores_dataflow()
{
    PipeGuard pipe;

    const pid_t parent = ::getpid();
    const pid_t child = ::fork();

    require(child >= 0, "fork() failed");

    if (child == 0) {
        if (::raise(SIGSTOP) != 0) {
            ::_exit(1);
        }
        ::_exit(0);
    }

    ChildGuard child_guard(child);
    wait_for_stopped_child(child);

    TestBackend backend;
    LineageAnalyzer analyzer;
    analyzer.set_backend(&backend);

    const std::string fingerprint = "late-pipe-dataflow-test";

    // Parent writes before the child relationship is reported.
    auto write_entry = make_read(parent, pipe.writer());
    write_entry.syscall_number = SYS_write;

    analyzer.on_syscall_event(write_entry);
    analyzer.set_pending_event_fingerprint(parent, parent, fingerprint);

    auto write_exit = write_entry;
    write_exit.is_entry = false;
    write_exit.return_value = 1;

    analyzer.on_syscall_event(write_exit);

    // Child independently discovers the same kernel pipe.
    auto read_entry = make_read(child, pipe.reader());

    analyzer.on_syscall_event(read_entry);

    auto read_exit = read_entry;
    read_exit.is_entry = false;
    read_exit.return_value = 1;

    analyzer.on_syscall_event(read_exit);
    analyzer.set_last_exit_fingerprint(child, child, fingerprint);

    const auto before = analyzer.produce_graph();

    uint64_t write_resource = 0;
    uint64_t read_resource = 0;
    uint64_t write_seq = 0;
    uint64_t read_seq = 0;

    for (const auto& obs : before.observations) {
        if (obs.tgid == parent &&
            obs.syscall_name == "write" &&
            obs.arg0 == static_cast<uint64_t>(pipe.writer())) {
            write_resource = obs.resource_id;
            write_seq = obs.seq;
        }

        if (obs.tgid == child &&
            obs.syscall_name == "read" &&
            obs.arg0 == static_cast<uint64_t>(pipe.reader())) {
            read_resource = obs.resource_id;
            read_seq = obs.seq;
        }
    }

    require(write_resource != 0, "parent write resource missing");
    require(read_resource != 0, "child read resource missing");

    require(
        write_resource != read_resource,
        "test did not reproduce independent FD discovery"
    );

    // No DataFlow should exist before resource reconciliation.
    for (const auto& edge : before.edges) {
        require(
            !(edge.relation == RelationType::DataFlow &&
              before.observations[edge.from_index].seq == write_seq &&
              before.observations[edge.to_index].seq == read_seq),
            "premature DataFlow before resource reconciliation"
        );
    }

    // The parent-child relationship arrives after both syscalls.
    analyzer.on_syscall_event(make_task_create(parent, child));

    const auto after = analyzer.produce_graph();

    uint64_t reconciled_read_resource = 0;
    bool dataflow_found = false;

    for (const auto& obs : after.observations) {
        if (obs.seq == read_seq) {
            reconciled_read_resource = obs.resource_id;
        }
    }

    for (const auto& edge : after.edges) {
        if (edge.relation != RelationType::DataFlow) {
            continue;
        }

        if (after.observations[edge.from_index].seq == write_seq &&
            after.observations[edge.to_index].seq == read_seq) {
            dataflow_found = true;
        }
    }

    std::cout
        << "Late DataFlow: write resource=" << write_resource
        << " original read resource=" << read_resource
        << " reconciled read resource=" << reconciled_read_resource
        << '\n';

    require(
        reconciled_read_resource == write_resource,
        "late TaskCreate failed to reconcile pipe identity"
    );

    std::cout << "PASS: late pipe identity reconciliation\n";

    require(
        dataflow_found,
        "late TaskCreate did not reconstruct missing DataFlow"
    );

    std::cout << "PASS: late TaskCreate restores DataFlow\n";
}

} // anonymous namespace

int main()
{
    try {
        test_fd_discovery_order();
        test_fd_replacement_no_false_merge();
        test_fd_replacement_after_first_observation();
        test_preexisting_pipe_cross_process_dataflow();
        test_late_task_create_restores_dataflow();

        std::cout << "PASS: lineage FD discovery ordering tests\n";

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
