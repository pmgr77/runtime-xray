
/**
 * @file    test_memory_scan_coordinator.cpp
 * @brief   Unit tests for policy-driven memory scan coordination.
 *
 * Verifies semantic scan limits, process-image isolation,
 * page reservations, unused-budget refunds, and validation
 * of scan completion permits.
 *
 * Tests run without ptrace, process memory access, or external
 * applications. They validate scan authorization and accounting
 * independently from the memory scanning implementation.
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

#include "memory_scan_coordinator.hpp"

#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

namespace {

using runtimexray::MemoryScanCoordinator;
using runtimexray::MemoryScanPermit;
using runtimexray::MemoryScanPolicy;
using runtimexray::MemoryScanReason;
using runtimexray::MemoryScanRequest;
using runtimexray::ProcessImageKey;

/**
 * @brief Fail a test when a required condition is false.
 *
 * Unlike assert(), this check remains enabled in Release builds.
 *
 * @param condition Condition that must be true.
 * @param message Description of the failed expectation.
 */
void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/**
 * @brief Extract an authorized scan permit from a result.
 *
 * @param result Result returned by request_scan().
 * @param message Description used if authorization failed.
 * @return The authorized scan permit.
 */
MemoryScanPermit require_permit(const std::optional<MemoryScanPermit>& result, const std::string& message)
{
    require(result.has_value(), message);

    require(result->reservation_id != 0, "Coordinator issued an invalid reservation ID");

    require(result->max_pages > 0, "Coordinator issued a zero-page scan permit");

    require(result->max_observations > 0, "Coordinator issued a zero-observation scan permit");

    return *result;
}

/**
 * @brief Create a small policy with predictable test limits.
 *
 * The deliberately small budgets make boundary conditions
 * easy to verify without allocating or scanning memory.
 *
 * @return A policy suitable for unit tests.
 */
MemoryScanPolicy make_test_policy()
{
    MemoryScanPolicy policy;

    policy.max_scans_per_reason = 1;
    policy.max_scans_per_process_image = 3;
    policy.max_pages_per_scan = 100;
    policy.max_pages_per_process_image = 200;
    policy.max_observations_per_scan = 10;

    return policy;
}

/**
 * @brief Verify that scan reasons are independent.
 *
 * A repeated request for one reason must not consume or
 * disable another reason's scan opportunity.
 *
 * The overall scan-count limit must still be enforced.
 */
void test_independent_reasons()
{
    MemoryScanCoordinator coordinator(make_test_policy());

    const ProcessImageKey image{42, 0};

    const MemoryScanRequest discovery{
        image,
        MemoryScanReason::SensitiveDataDiscovery,
        1001
    };

    const auto first = require_permit(
        coordinator.request_scan(discovery),
        "Sensitive data discovery scan was rejected");

    require(
        first.reason == MemoryScanReason::SensitiveDataDiscovery,
        "Permit contains the wrong reason");

    require(
        first.related_event_seq == 1001,
        "Permit lost the originating event sequence");

    // Per-reason limits must reject another discovery scan.
    require(
        !coordinator.request_scan(discovery).has_value(),
        "Repeated discovery scan exceeded per-reason limit");

    const auto second = require_permit(
        coordinator.request_scan({
            image,
            MemoryScanReason::DataBoundaryCrossing,
            1002
        }),
        "Boundary crossing scan was incorrectly rejected");

    // Both previous permits reserved 100 pages.
    // Completing one frees unused pages but does not
    // restore its scan-count allowance.
    require(
        coordinator.complete_scan(first, 20),
        "Failed to complete discovery scan");

    const auto third = require_permit(
        coordinator.request_scan({
            image,
            MemoryScanReason::MemoryStateChange,
            1003
        }),
        "Memory state change scan was incorrectly rejected");

    // Three scans have now been authorized for this image.
    require(
        !coordinator.request_scan({
            image,
            MemoryScanReason::ExplicitRequest,
            1004
        }).has_value(),
        "Aggregate scan-count limit was not enforced");

    require(
        coordinator.complete_scan(second, 80),
        "Failed to complete boundary crossing scan");

    require(
        coordinator.complete_scan(third, 50),
        "Failed to complete memory state change scan");
}

/**
 * @brief Verify that outstanding reservations share one budget.
 *
 * Two simultaneous permits must not each receive the entire
 * remaining process-image page budget.
 *
 * Completing a scan refunds unused pages so later requests
 * can use them.
 */
void test_reservation_and_refund()
{
    MemoryScanPolicy policy;

    policy.max_scans_per_reason = 1;
    policy.max_scans_per_process_image = 4;
    policy.max_pages_per_scan = 6;
    policy.max_pages_per_process_image = 8;
    policy.max_observations_per_scan = 5;

    MemoryScanCoordinator coordinator(policy);

    const ProcessImageKey image{10, 0};

    const auto first = require_permit(
        coordinator.request_scan({
            image,
            MemoryScanReason::SensitiveDataDiscovery,
            1
        }),
        "First reservation failed");

    require(
        first.max_pages == 6,
        "First reservation received the wrong page budget");

    const auto second = require_permit(
        coordinator.request_scan({
            image,
            MemoryScanReason::DataBoundaryCrossing,
            2
        }),
        "Second reservation failed");

    require(
        second.max_pages == 2,
        "Second reservation exceeded the remaining budget");

    // The full eight-page budget is now reserved.
    require(
        !coordinator.request_scan({
            image,
            MemoryScanReason::MemoryStateChange,
            3
        }).has_value(),
        "Coordinator overcommitted outstanding reservations");

    // The first scan used only three of its six pages.
    // Exactly three pages must become available again.
    require(
        coordinator.complete_scan(first, 3),
        "Failed to complete first reservation");

    const auto third = require_permit(
        coordinator.request_scan({
            image,
            MemoryScanReason::MemoryStateChange,
            3
        }),
        "Unused pages were not refunded");

    require(
        third.max_pages == 3,
        "Incorrect page budget after refund");

    require(
        coordinator.complete_scan(second, 1),
        "Failed to complete second reservation");

    require(
        coordinator.complete_scan(third, 3),
        "Failed to complete third reservation");

    // Actual usage is now 3 + 1 + 3 = 7 pages.
    // One page remains for a fourth permitted scan.
    const auto fourth = require_permit(
        coordinator.request_scan({
            image,
            MemoryScanReason::ExplicitRequest,
            4
        }),
        "Remaining page was not available");

    require(
        fourth.max_pages == 1,
        "Incorrect final remaining page budget");

    require(
        coordinator.complete_scan(fourth, 1),
        "Failed to complete fourth reservation");

    // The full budget has now been consumed.
    require(
        !coordinator.request_scan({
            image,
            MemoryScanReason::InitialInspection,
            5
        }).has_value(),
        "Exhausted process-image budget was exceeded");
}

/**
 * @brief Verify independence of process instances and exec generations.
 *
 * One process image exhausting its budget must not prevent
 * another process or a later exec generation from scanning.
 */
void test_process_image_isolation()
{
    MemoryScanPolicy policy = make_test_policy();

    policy.max_scans_per_process_image = 1;

    MemoryScanCoordinator coordinator(policy);

    const ProcessImageKey original{42, 0};
    const ProcessImageKey after_exec{42, 1};
    const ProcessImageKey another_process{43, 0};

    const auto first = require_permit(
        coordinator.request_scan({
            original,
            MemoryScanReason::SensitiveDataDiscovery,
            10
        }),
        "Original process image was rejected");

    require(
        !coordinator.request_scan({
            original,
            MemoryScanReason::DataBoundaryCrossing,
            11
        }).has_value(),
        "Original image exceeded its scan-count limit");

    const auto second = require_permit(
        coordinator.request_scan({
            after_exec,
            MemoryScanReason::SensitiveDataDiscovery,
            12
        }),
        "Exec generation did not receive an independent budget");

    const auto third = require_permit(
        coordinator.request_scan({
            another_process,
            MemoryScanReason::SensitiveDataDiscovery,
            13
        }),
        "Different process instance did not receive a budget");

    require(
        first.reservation_id != second.reservation_id &&
        first.reservation_id != third.reservation_id &&
        second.reservation_id != third.reservation_id,
        "Reservation IDs are not unique");

    require(
        coordinator.complete_scan(first, 10),
        "Failed to complete original-image scan");

    require(
        coordinator.complete_scan(second, 10),
        "Failed to complete post-exec scan");

    require(
        coordinator.complete_scan(third, 10),
        "Failed to complete different-process scan");
}

/**
 * @brief Verify validation of reservation completion.
 *
 * Unknown, modified, duplicated, and over-budget permits
 * must not alter coordinator accounting.
 *
 * A failed completion must leave the original reservation
 * available for a subsequent valid completion.
 */
void test_invalid_completion()
{
    MemoryScanCoordinator coordinator(make_test_policy());

    const auto original = require_permit(
        coordinator.request_scan({
            {100, 2},
            MemoryScanReason::SensitiveDataDiscovery,
            1234
        }),
        "Failed to create reservation");

    MemoryScanPermit changed = original;

    changed.max_pages += 1;

    require(
        !coordinator.complete_scan(changed, 10),
        "Modified page budget was accepted");

    changed = original;
    changed.related_event_seq += 1;

    require(
        !coordinator.complete_scan(changed, 10),
        "Modified event reference was accepted");

    changed = original;
    changed.reason = MemoryScanReason::ExplicitRequest;

    require(
        !coordinator.complete_scan(changed, 10),
        "Modified scan reason was accepted");

    changed = original;
    changed.image.exec_generation += 1;

    require(
        !coordinator.complete_scan(changed, 10),
        "Modified process identity was accepted");

    changed = original;
    changed.reservation_id += 1000;

    require(
        !coordinator.complete_scan(changed, 10),
        "Unknown reservation ID was accepted");

    require(
        !coordinator.complete_scan(
            original,
            original.max_pages + 1),
        "Scan exceeded its authorized page budget");

    // Invalid completion attempts must not destroy
    // the original outstanding reservation.
    require(
        coordinator.complete_scan(original, 10),
        "Original permit became invalid after rejected attempts");

    require(
        !coordinator.complete_scan(original, 10),
        "Duplicate completion was accepted");
}

/**
 * @brief Verify that a zero-page scan still consumes a scan count.
 *
 * A failed or inaccessible memory scan may attempt zero pages.
 * Its unused page budget is refunded, but its scan opportunity
 * must not be restored automatically.
 */
void test_zero_page_completion()
{
    MemoryScanCoordinator coordinator(make_test_policy());

    const ProcessImageKey image{55, 0};

    const MemoryScanRequest request{
        image,
        MemoryScanReason::InitialInspection,
        0
    };

    const auto first = require_permit(
        coordinator.request_scan(request),
        "Initial inspection was rejected");

    require(
        coordinator.complete_scan(first, 0),
        "Zero-page scan completion was rejected");

    require(
        !coordinator.request_scan(request).has_value(),
        "Zero-page scan incorrectly restored its scan count");

    const auto second = require_permit(
        coordinator.request_scan({
            image,
            MemoryScanReason::SensitiveDataDiscovery,
            20
        }),
        "Another reason could not use refunded pages");

    require(
        second.max_pages == make_test_policy().max_pages_per_scan,
        "Zero-page scan did not refund its entire page budget");

    require(
        coordinator.complete_scan(second, 10),
        "Failed to complete subsequent scan");
}

/**
 * @brief Verify rejection of an invalid process-image identity.
 */
void test_invalid_process_identity()
{
    MemoryScanCoordinator coordinator(make_test_policy());

    require(
        !coordinator.request_scan({
            {0, 0},
            MemoryScanReason::InitialInspection,
            0
        }).has_value(),
        "Unassigned process-instance ID was accepted");
}

/**
 * @brief Verify that zero-valued policy limits disable scans.
 *
 * Each resource limit is checked independently so the test
 * catches accidental omission of any policy constraint.
 */
void test_disabled_limits()
{
    const MemoryScanRequest request{
        {1, 0},
        MemoryScanReason::SensitiveDataDiscovery,
        1
    };

    {
        auto policy = make_test_policy();
        policy.max_scans_per_reason = 0;

        MemoryScanCoordinator coordinator(policy);

        require(
            !coordinator.request_scan(request).has_value(),
            "Zero per-reason limit was ignored");
    }

    {
        auto policy = make_test_policy();
        policy.max_scans_per_process_image = 0;

        MemoryScanCoordinator coordinator(policy);

        require(
            !coordinator.request_scan(request).has_value(),
            "Zero total scan limit was ignored");
    }

    {
        auto policy = make_test_policy();
        policy.max_pages_per_scan = 0;

        MemoryScanCoordinator coordinator(policy);

        require(
            !coordinator.request_scan(request).has_value(),
            "Zero per-scan page budget was ignored");
    }

    {
        auto policy = make_test_policy();
        policy.max_pages_per_process_image = 0;

        MemoryScanCoordinator coordinator(policy);

        require(
            !coordinator.request_scan(request).has_value(),
            "Zero total page budget was ignored");
    }

    {
        auto policy = make_test_policy();
        policy.max_observations_per_scan = 0;

        MemoryScanCoordinator coordinator(policy);

        require(
            !coordinator.request_scan(request).has_value(),
            "Zero observation limit was ignored");
    }
}

} // anonymous namespace

/**
 * @brief Execute all MemoryScanCoordinator regression tests.
 *
 * @return 0 when all tests pass, 1 when any test fails.
 */
int main()
{
    try {
        test_independent_reasons();
        test_reservation_and_refund();
        test_process_image_isolation();
        test_invalid_completion();
        test_zero_page_completion();
        test_invalid_process_identity();
        test_disabled_limits();

        std::cout
            << "PASS: all MemoryScanCoordinator tests\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr
            << "FAIL: " << e.what() << '\n';

        return 1;
    }
}
