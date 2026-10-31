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

} // anonymous namespace

int main()
{
    try {
        test_fd_discovery_order();
        test_fd_replacement_no_false_merge();
        test_fd_replacement_after_first_observation();

        std::cout << "PASS: lineage FD discovery ordering tests\n";

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
