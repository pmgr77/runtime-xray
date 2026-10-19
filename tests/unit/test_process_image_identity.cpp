
/**
 * @file    test_process_image_identity.cpp
 * @brief   Tests active process-image identity and lifecycle tracking.
 *
 * Verifies that LineageAnalyzer exposes stable process identities
 * without modifying its internal state.
 *
 * The tests cover:
 *
 * - Unknown processes.
 * - Initial process registration.
 * - Repeated observations of the same process.
 * - Independent process instances.
 * - Failed and successful exec transitions.
 * - Multiple threads sharing one process image.
 * - Process termination and simulated PID reuse.
 *
 * Synthetic trace events are used instead of launching processes.
 * No ptrace privileges or external applications are required.
 *
 * @author  Peter Magram
 * @date    2026-10-19
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
#include "process_image_key.hpp"

#include <sys/syscall.h>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using runtimexray::LineageAnalyzer;
using runtimexray::ProcessImageKey;
using runtimexray::SyscallEvent;
using runtimexray::TraceEventType;

/**
 * @brief Assert a required test condition.
 *
 * Unlike assert(), this check remains active in Release builds.
 *
 * @param condition Condition expected to be true.
 * @param message Failure description.
 */
void require(
    bool condition,
    const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/**
 * @brief Create a synthetic syscall event.
 *
 * By default, the thread ID is the same as the process TGID.
 * A different TID can be supplied to simulate a worker thread.
 *
 * @param tgid Linux thread-group ID.
 * @param tid Linux task ID.
 * @param syscall_number Native syscall number.
 * @param is_entry Whether the event represents syscall entry.
 * @return Initialized synthetic syscall event.
 */
SyscallEvent make_syscall(
    pid_t tgid,
    pid_t tid,
    unsigned long long syscall_number,
    bool is_entry = true)
{
    SyscallEvent event{};

    event.type = TraceEventType::Syscall;
    event.pid = tid;
    event.tid = tid;
    event.tgid = tgid;
    event.syscall_number = syscall_number;
    event.is_entry = is_entry;

    return event;
}

/**
 * @brief Create a synthetic successful exec notification.
 *
 * This models the semantic Exec event delivered by the tracer
 * after the executable image has been replaced successfully.
 *
 * @param tgid Linux thread-group ID.
 * @return Initialized exec event.
 */
SyscallEvent make_exec_event(pid_t tgid)
{
    SyscallEvent event{};

    event.type = TraceEventType::Exec;
    event.pid = tgid;
    event.tid = tgid;
    event.tgid = tgid;

    return event;
}

/**
 * @brief Register a process using its first observed syscall.
 *
 * @param analyzer Analyzer receiving the event.
 * @param tgid Linux thread-group ID.
 */
void observe_process(
    LineageAnalyzer& analyzer,
    pid_t tgid)
{
    analyzer.on_syscall_event(
        make_syscall(tgid, tgid, SYS_getpid));
}

/**
 * @brief Verify that identity lookup does not create processes.
 */
void test_unknown_process()
{
    LineageAnalyzer analyzer;

    require(
        !analyzer.active_process_image(1001).has_value(),
        "Unknown process unexpectedly has an identity");

    require(
        !analyzer.active_process_image(0).has_value(),
        "Invalid TGID unexpectedly has an identity");

    const auto graph = analyzer.produce_graph();

    require(
        graph.observations.empty(),
        "Identity lookup unexpectedly created observations");
}

/**
 * @brief Verify stable identity across repeated syscall events.
 */
void test_stable_process_identity()
{
    LineageAnalyzer analyzer;

    constexpr pid_t kTgid = 2001;

    observe_process(analyzer, kTgid);

    const auto first = analyzer.active_process_image(kTgid);

    require(
        first.has_value(),
        "Observed process has no identity");

    require(
        first->is_valid(),
        "Observed process has an invalid identity");

    require(
        first->exec_generation == 0,
        "Initial executable generation is not zero");

    analyzer.on_syscall_event(
        make_syscall(kTgid, kTgid, SYS_getpid));

    const auto second = analyzer.active_process_image(kTgid);

    require(
        second.has_value() && *second == *first,
        "Process identity changed without an exec");
}

/**
 * @brief Verify independent identities for different processes.
 */
void test_independent_processes()
{
    LineageAnalyzer analyzer;

    observe_process(analyzer, 3001);
    observe_process(analyzer, 3002);

    const auto first = analyzer.active_process_image(3001);
    const auto second = analyzer.active_process_image(3002);

    require(
        first.has_value() && second.has_value(),
        "One or more process identities are missing");

    require(
        first->process_instance_id != second->process_instance_id,
        "Different processes share a process-instance ID");

    require(
        first->exec_generation == 0 &&
        second->exec_generation == 0,
        "New process has an unexpected exec generation");
}

/**
 * @brief Verify that failed exec does not advance generation.
 *
 * A failed exec returns to the original executable image.
 * Only a successful Exec notification advances generation.
 */
void test_failed_exec()
{
    LineageAnalyzer analyzer;

    constexpr pid_t kTgid = 4001;

    observe_process(analyzer, kTgid);

    const auto before = analyzer.active_process_image(kTgid);

    auto entry = make_syscall(
        kTgid,
        kTgid,
        SYS_execve);

    entry.captured_path = "/nonexistent/program";

    analyzer.on_syscall_event(entry);

    auto exit = make_syscall(
        kTgid,
        kTgid,
        SYS_execve,
        false);

    exit.return_value = -2;

    analyzer.on_syscall_event(exit);

    const auto after = analyzer.active_process_image(kTgid);

    require(
        before.has_value() &&
        after.has_value() &&
        *before == *after,
        "Failed exec unexpectedly changed process image");
}

/**
 * @brief Verify generation changes after successful exec.
 *
 * A successful exec changes the executable image while
 * preserving the RuntimeXRay process-instance identity.
 */
void test_successful_exec()
{
    LineageAnalyzer analyzer;

    constexpr pid_t kTgid = 5001;

    observe_process(analyzer, kTgid);

    const auto before = analyzer.active_process_image(kTgid);

    analyzer.on_syscall_event(make_exec_event(kTgid));

    const auto after = analyzer.active_process_image(kTgid);

    require(
        before.has_value() && after.has_value(),
        "Process disappeared during exec transition");

    require(
        before->process_instance_id == after->process_instance_id,
        "Successful exec changed the process-instance ID");

    require(
        after->exec_generation == before->exec_generation + 1,
        "Successful exec did not advance the generation");

    analyzer.on_syscall_event(make_exec_event(kTgid));

    const auto third = analyzer.active_process_image(kTgid);

    require(
        third.has_value() &&
        third->exec_generation == after->exec_generation + 1,
        "Second successful exec did not advance generation");
}

/**
 * @brief Verify that threads share their process-image identity.
 *
 * A worker thread does not create another executable image.
 * Exiting one worker thread must not terminate the process
 * while its main thread remains active.
 */
void test_shared_thread_identity()
{
    LineageAnalyzer analyzer;

    constexpr pid_t kTgid = 6001;
    constexpr pid_t kWorkerTid = 6002;

    observe_process(analyzer, kTgid);

    const auto before = analyzer.active_process_image(kTgid);

    analyzer.on_syscall_event(
        make_syscall(kTgid, kWorkerTid, SYS_getpid));

    const auto with_worker = analyzer.active_process_image(kTgid);

    require(
        before.has_value() &&
        with_worker.has_value() &&
        *before == *with_worker,
        "Worker thread changed process identity");

    analyzer.on_syscall_event(
        make_syscall(kTgid, kWorkerTid, SYS_exit));

    const auto after_worker_exit =
        analyzer.active_process_image(kTgid);

    require(
        after_worker_exit.has_value() &&
        *after_worker_exit == *before,
        "Worker thread exit incorrectly terminated process");
}

/**
 * @brief Verify termination and simulated Linux PID reuse.
 *
 * After exit_group, the original identity must no longer
 * be accessible. A newly observed lifetime of the same
 * TGID must receive a different process-instance ID.
 */
void test_termination_and_pid_reuse()
{
    LineageAnalyzer analyzer;

    constexpr pid_t kTgid = 7001;

    observe_process(analyzer, kTgid);

    const auto original = analyzer.active_process_image(kTgid);

    require(
        original.has_value(),
        "Original process identity is missing");

    analyzer.on_syscall_event(
        make_syscall(kTgid, kTgid, SYS_exit_group));

    require(
        !analyzer.active_process_image(kTgid).has_value(),
        "Terminated process still appears active");

    // Simulate Linux assigning the same TGID to a new process.
    observe_process(analyzer, kTgid);

    const auto replacement = analyzer.active_process_image(kTgid);

    require(
        replacement.has_value(),
        "Reused TGID did not receive an identity");

    require(
        replacement->process_instance_id !=
            original->process_instance_id,
        "PID reuse incorrectly reused process-instance ID");

    require(
        replacement->exec_generation == 0,
        "New process lifetime did not start at generation zero");
}

} // anonymous namespace

/**
 * @brief Execute all process-image identity regression tests.
 *
 * @return Zero if all tests pass; one otherwise.
 */
int main()
{
    try {
        test_unknown_process();
        test_stable_process_identity();
        test_independent_processes();
        test_failed_exec();
        test_successful_exec();
        test_shared_thread_identity();
        test_termination_and_pid_reuse();

        std::cout
            << "PASS: process image identity tests\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr
            << "FAIL: " << e.what() << '\n';

        return 1;
    }
}
