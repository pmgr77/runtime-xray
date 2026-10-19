
/**
 * @file    memory_scan_coordinator.cpp
 * @brief   Implements policy-driven coordination of runtime memory scans.
 *
 * The coordinator evaluates semantic scan requests, reserves bounded
 * resources, and accounts for completed scans.
 *
 * Scan authorization is independent of particular system calls,
 * tracing backends, and secret extraction mechanisms.
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

#include <algorithm>
#include <limits>
#include <utility>

namespace runtimexray {

namespace {

/**
 * @brief Compare two process-image identities for equality.
 *
 * ProcessImageKey intentionally provides operator< for std::map.
 * This helper avoids requiring additional public operators.
 *
 * @param lhs First process image.
 * @param rhs Second process image.
 * @return True if both fields match.
 */
bool same_process_image(const ProcessImageKey& lhs, const ProcessImageKey& rhs)
{
    return lhs.process_instance_id == rhs.process_instance_id &&
           lhs.exec_generation == rhs.exec_generation;
}

/**
 * @brief Compare a supplied permit against the issued reservation.
 *
 * The reservation ID alone is insufficient: a caller must not be
 * able to change the permitted budget or request metadata when
 * reporting completion.
 *
 * @param lhs Permit supplied by the caller.
 * @param rhs Originally issued permit.
 * @return True if all permit fields match.
 */
bool same_permit(const MemoryScanPermit& lhs, const MemoryScanPermit& rhs)
{
    return lhs.reservation_id == rhs.reservation_id &&
           same_process_image(lhs.image, rhs.image) &&
           lhs.reason == rhs.reason &&
           lhs.related_event_seq == rhs.related_event_seq &&
           lhs.max_pages == rhs.max_pages &&
           lhs.max_observations == rhs.max_observations;
}

} // anonymous namespace

MemoryScanCoordinator::MemoryScanCoordinator(MemoryScanPolicy policy)
    : policy_(std::move(policy))
{
}

std::optional<MemoryScanPermit>
MemoryScanCoordinator::request_scan(const MemoryScanRequest& request)
{
    // A zero process-instance ID means that lineage has not
    // assigned a stable identity. Do not track such a request
    // under a potentially shared or ambiguous identity.
    if (request.image.process_instance_id == 0) {
        return std::nullopt;
    }

    // Reject requests when the policy disables scanning
    // or does not permit producing any observations.
    if (policy_.max_scans_per_reason == 0 ||
        policy_.max_scans_per_process_image == 0 ||
        policy_.max_pages_per_scan == 0 ||
        policy_.max_pages_per_process_image == 0 ||
        policy_.max_observations_per_scan == 0) {
        return std::nullopt;
    }

    // Reservation IDs are unique for the coordinator's lifetime.
    // Never wrap around and accidentally reuse an old ID.
    if (next_reservation_id_ == 0) {
        return std::nullopt;
    }

    // Look up existing accounting without creating a state
    // for a request that may ultimately be rejected.
    const auto state_it = image_states_.find(request.image);

    size_t total_scans = 0;
    size_t reason_scans = 0;
    size_t accounted_pages = 0;

    if (state_it != image_states_.end()) {
        const ImageScanState& state = state_it->second;

        total_scans = state.total_scans;
        accounted_pages = state.accounted_pages;

        const auto reason_it = state.scan_counts_by_reason.find(request.reason);

        if (reason_it != state.scan_counts_by_reason.end()) {
            reason_scans = reason_it->second;
        }
    }

    // Enforce the limit for this semantic reason and the
    // aggregate scan-count limit for the process image.
    if (reason_scans >= policy_.max_scans_per_reason ||
        total_scans >= policy_.max_scans_per_process_image) {
        return std::nullopt;
    }

    // accounted_pages includes both completed page attempts
    // and outstanding page reservations.
    //
    // All accounting is subtractive here to avoid unsigned
    // overflow when computing the remaining page budget.
    if (accounted_pages >= policy_.max_pages_per_process_image) {
        return std::nullopt;
    }

    const size_t remaining_pages = policy_.max_pages_per_process_image - accounted_pages;

    const size_t granted_pages = std::min(remaining_pages, policy_.max_pages_per_scan);

    if (granted_pages == 0) {
        return std::nullopt;
    }

    MemoryScanPermit permit;

    permit.reservation_id = next_reservation_id_;
    permit.image = request.image;
    permit.reason = request.reason;
    permit.related_event_seq = request.related_event_seq;
    permit.max_pages = granted_pages;
    permit.max_observations = policy_.max_observations_per_scan;

    // Register the outstanding reservation before committing
    // its accounting to the process-image state.
    //
    // The issued permit is stored internally and will be
    // checked again when complete_scan() is called.
    const auto inserted = active_reservations_.emplace(
        permit.reservation_id,
        ActiveReservation{permit});

    if (!inserted.second) {
        return std::nullopt;
    }

    // Create the state if this is the first approved scan
    // for the process image.
    ImageScanState& state = image_states_[request.image];

    ++state.scan_counts_by_reason[request.reason];
    ++state.total_scans;

    // Safe because granted_pages cannot exceed the remaining
    // process-image page budget.
    state.accounted_pages += granted_pages;

    // If this was the largest possible reservation ID,
    // wrap to zero. Zero is permanently rejected above,
    // preventing any subsequent ID reuse.
    if (next_reservation_id_ == std::numeric_limits<uint64_t>::max()) {
        next_reservation_id_ = 0;
    } else {
        ++next_reservation_id_;
    }

    return permit;
}

bool MemoryScanCoordinator::complete_scan(const MemoryScanPermit& permit, size_t pages_scanned)
{
    // Zero is reserved as an invalid reservation ID.
    if (permit.reservation_id == 0) {
        return false;
    }

    const auto reservation_it = active_reservations_.find(permit.reservation_id);

    // Unknown or already completed permits cannot modify
    // resource accounting.
    if (reservation_it == active_reservations_.end()) {
        return false;
    }

    const MemoryScanPermit& original = reservation_it->second.permit;

    // Validate the entire originally issued permit, rather
    // than trusting a potentially modified caller-owned copy.
    if (!same_permit(permit, original)) {
        return false;
    }

    // A scan cannot report more attempted pages than it
    // was authorized to inspect.
    if (pages_scanned > original.max_pages) {
        return false;
    }

    const auto state_it = image_states_.find(original.image);

    if (state_it == image_states_.end()) {
        return false;
    }

    ImageScanState& state = state_it->second;

    // Defensive check: a valid outstanding reservation
    // must already be included in the accounted total.
    if (state.accounted_pages < original.max_pages) {
        return false;
    }

    // The full grant was reserved in request_scan().
    // Keep the pages actually attempted and refund the rest.
    const size_t unused_pages = original.max_pages - pages_scanned;

    state.accounted_pages -= unused_pages;

    // Erasing the reservation makes a second completion
    // of the same permit impossible.
    active_reservations_.erase(reservation_it);

    return true;
}

} // namespace runtimexray
