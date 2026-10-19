
/**
 * @file    memory_scan_coordinator.hpp
 * @brief   Defines policy-driven coordination of runtime memory scans.
 *
 * The coordinator decides whether a memory scan is permitted and
 * assigns bounded resources to each scan request.
 *
 * Scan requests are expressed in terms of semantic runtime events,
 * rather than specific system calls or tracing backends.
 *
 * Process-image identity is provided by the shared ProcessImageKey
 * type, independently of the coordinator.
 *
 * The coordinator does not inspect process memory, extract secrets,
 * or create lineage observations.
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

#ifndef RUNTIMEXRAY_MEMORY_SCAN_COORDINATOR_HPP
#define RUNTIMEXRAY_MEMORY_SCAN_COORDINATOR_HPP

#include "process_image_key.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>

namespace runtimexray {

/**
 * @brief Semantic reasons for requesting process memory inspection.
 *
 * Values describe WHY a scan may be useful, not WHICH
 * operating-system event caused the request.
 *
 * Reasons can originate from syscall observers, eBPF events,
 * secret extractors, other analysis components, or explicit
 * user requests.
 *
 * The coordinator is independent of concrete system calls.
 */
enum class MemoryScanReason {
    InitialInspection,
    SensitiveDataDiscovery,
    MemoryStateChange,
    DataBoundaryCrossing,
    ExplicitRequest
};

/**
 * @brief Configurable limits for runtime memory scanning.
 *
 * Limits are enforced independently for each process image.
 *
 * max_scans_per_reason prevents repeated events of the same
 * semantic type from triggering unlimited scans.
 *
 * max_scans_per_process_image limits the total number of scans,
 * regardless of their reasons.
 *
 * Page limits constrain the amount of memory inspected.
 * A page represents one scanner accounting unit, currently
 * based on 4096-byte chunks.
 *
 * Observation limits constrain the number of findings produced
 * by an individual scan.
 *
 * Default values are experimental policy settings.
 */
struct MemoryScanPolicy {
    static constexpr size_t kDefaultScansPerReason = 1;
    static constexpr size_t kDefaultScansPerProcessImage = 3;
    static constexpr size_t kDefaultPagesPerScan = 1000;
    static constexpr size_t kDefaultPagesPerProcessImage = 2000;
    static constexpr size_t kDefaultObservationsPerScan = 50;

    size_t max_scans_per_reason = kDefaultScansPerReason;

    size_t max_scans_per_process_image = kDefaultScansPerProcessImage;

    size_t max_pages_per_scan = kDefaultPagesPerScan;

    size_t max_pages_per_process_image = kDefaultPagesPerProcessImage;

    size_t max_observations_per_scan = kDefaultObservationsPerScan;
};

/**
 * @brief Request to inspect memory following a runtime observation.
 *
 * image identifies the process executable image whose memory
 * should be inspected.
 *
 * reason describes the semantic motivation for scanning.
 *
 * related_event_seq optionally identifies the originating
 * lineage event. Zero means no event is attached.
 *
 * The event reference is contextual metadata and does not
 * establish causality between that event and secrets found
 * during the scan.
 */
struct MemoryScanRequest {
    ProcessImageKey image;

    MemoryScanReason reason = MemoryScanReason::InitialInspection;

    uint64_t related_event_seq = 0;
};

/**
 * @brief Authorization to perform one bounded memory scan.
 *
 * The coordinator issues a permit only when the applicable
 * policy and remaining resource budget allow scanning.
 *
 * reservation_id uniquely identifies an outstanding
 * reservation within the coordinator instance.
 *
 * Zero represents an invalid reservation.
 *
 * max_pages and max_observations define the resource
 * limits that the scanner must respect.
 *
 * The original request context is retained for accounting
 * and possible future correlation with runtime events.
 *
 * @note A permit represents authorization, not evidence
 *       that memory has been scanned successfully.
 */
struct MemoryScanPermit {
    uint64_t reservation_id = 0;

    ProcessImageKey image;

    MemoryScanReason reason = MemoryScanReason::InitialInspection;

    uint64_t related_event_seq = 0;

    size_t max_pages = 0;
    size_t max_observations = 0;
};

/**
 * @brief Coordinates bounded, event-driven process memory scans.
 *
 * Responsibilities:
 *
 * - Evaluate requests against configured scan limits.
 * - Track scan counts by semantic reason.
 * - Enforce aggregate limits for each process image.
 * - Reserve page budgets before scanning begins.
 * - Refund unused reserved pages after completion.
 *
 * Non-responsibilities:
 *
 * - Reading /proc/<pid>/maps.
 * - Selecting or prioritizing memory regions.
 * - Accessing another process's address space.
 * - Recognizing credentials or other sensitive data.
 * - Inferring causal relationships between observations.
 *
 * Process-image identity is supplied by the component that
 * maintains process lifetimes and exec generations.
 *
 * @note The coordinator is not thread-safe. Callers must
 *       serialize access or provide external synchronization.
 */
class MemoryScanCoordinator {
public:
    /**
     * @brief Construct a coordinator with the supplied policy.
     *
     * @param policy Resource limits applied to scan requests.
     */
    explicit MemoryScanCoordinator(MemoryScanPolicy policy = {});

    /**
     * @brief Request permission to perform a memory scan.
     *
     * Checks:
     *
     * - Valid process-image identity.
     * - Available scans for the requested reason.
     * - Available scans for the process image.
     * - Remaining process-image page budget.
     *
     * When approved, the granted page budget is reserved
     * immediately, preventing outstanding requests from
     * collectively exceeding the configured page limit.
     *
     * Requests without available budget are rejected.
     *
     * @param request Runtime observation requesting inspection.
     * @return Scan permit if approved; std::nullopt otherwise.
     */
    std::optional<MemoryScanPermit> request_scan(const MemoryScanRequest& request);

    /**
     * @brief Complete a previously authorized scan.
     *
     * Records the actual number of pages attempted and refunds
     * the unused portion of the reserved page budget.
     *
     * Each permit may be completed exactly once.
     *
     * A scan that fails to read memory must still be completed
     * with its actual page-attempt count.
     *
     * Completion is rejected if the permit is unknown,
     * was already completed, does not match the original
     * reservation, or reports more pages than authorized.
     *
     * @param permit Permit issued by this coordinator.
     * @param pages_scanned Number of page attempts actually made.
     * @return True on valid completion; false otherwise.
     */
    bool complete_scan(const MemoryScanPermit& permit, size_t pages_scanned);

private:
    /**
     * @brief Scan accounting for one process executable image.
     *
     * scan_counts_by_reason records approved requests for
     * each semantic reason.
     *
     * total_scans records all approved requests.
     *
     * accounted_pages includes completed page attempts and
     * outstanding reservations. Unused pages are refunded
     * when their reservations complete.
     */
    struct ImageScanState {
        std::map<MemoryScanReason, size_t> scan_counts_by_reason;

        size_t total_scans = 0;
        size_t accounted_pages = 0;
    };

    /**
     * @brief Outstanding reservation awaiting completion.
     *
     * Retains the original permit so invalid or repeated
     * completion attempts cannot change resource accounting.
     */
    struct ActiveReservation {
        MemoryScanPermit permit;
    };

    MemoryScanPolicy policy_;

    uint64_t next_reservation_id_ = 1;

    std::map<ProcessImageKey, ImageScanState> image_states_;

    std::map<uint64_t, ActiveReservation> active_reservations_;
};

} // namespace runtimexray

#endif // RUNTIMEXRAY_MEMORY_SCAN_COORDINATOR_HPP
