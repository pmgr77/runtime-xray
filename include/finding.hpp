/**
 * @file    finding.hpp
 * @brief   Defines security findings produced by RuntimeXRay detection rules.
 *
 * A Finding is the canonical security result produced by a DetectionRule.
 *
 * Detection rules analyze the LineageGraph and create Findings describing
 * security-relevant behavior or properties discovered in that graph.
 *
 * Findings do not analyze the graph themselves. They contain the security
 * conclusion, structured attributes, and stable references to the graph
 * evidence supporting that conclusion.
 *
 * Composite detection rules may also reference Findings produced by an
 * earlier detection stage.
 *
 * @author  Peter Magram
 * @date    2026-10-10
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

#ifndef RUNTIMEXRAY_FINDING_HPP
#define RUNTIMEXRAY_FINDING_HPP

#include "lineage.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace runtimexray {

/**
 * @brief Severity of a security finding.
 */
enum class FindingSeverity {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Info = 4
};

/**
 * @brief One graph relationship used as evidence for a Finding.
 *
 * Graph vector indices are intentionally not stored here because they are an
 * internal representation detail. Findings reference observations through
 * stable Observation::seq values.
 */
struct FindingEdgeEvidence {
    uint64_t from_seq = 0;
    uint64_t to_seq = 0;
    RelationType relation = RelationType::Chronological;
};

/**
 * @brief Supported value types for rule-specific Finding attributes.
 *
 * Attributes allow detection rules to expose structured information without
 * introducing a dedicated C++ details structure for every possible rule.
 *
 * Examples:
 *
 *     "path"        -> "/etc/shadow"
 *     "outcome"     -> "denied"
 *     "errno"       -> 13
 *     "count"       -> 4
 *     "destination" -> "10.0.0.5:443"
 *
 * Vector forms support composite Findings such as reconnaissance findings
 * involving several paths or process instances.
 */
using FindingAttributeValue = std::variant<
    std::string,
    int64_t,
    uint64_t,
    double,
    bool,
    std::vector<std::string>,
    std::vector<int64_t>,
    std::vector<uint64_t>
>;

/**
 * @brief Structured rule-specific Finding attributes.
 *
 * std::map is used rather than unordered_map to preserve deterministic
 * iteration and report output.
 */
using FindingAttributes =
    std::map<std::string, FindingAttributeValue>;

/**
 * @brief Canonical security result produced by a DetectionRule.
 *
 * A Finding answers:
 *
 *     "What security-relevant condition did RuntimeXRay conclude exists?"
 *
 * It does not discover new behavior by traversing the LineageGraph. That
 * responsibility belongs exclusively to DetectionRule implementations.
 *
 * Evidence fields point back to the graph so NarrativeBuilder and reporters
 * can explain and present the conclusion without duplicating graph data.
 */
struct Finding {
    /**
     * @brief Stable Finding identity within one RuntimeXRay analysis.
     *
     * Assigned by the detection engine after a rule produces the Finding.
     * Zero means "not assigned".
     *
     * Composite Findings reference earlier Findings through this identity.
     */
    uint64_t finding_id = 0;

    /**
     * @brief Stable identity of the rule that produced this Finding.
     *
     * This identifies the implementation, not the semantic type of result.
     *
     * Examples:
     *
     *     "builtin.sensitive_file_access"
     *     "acme.internal_secret_file"
     */
    std::string rule_id;

    /**
     * @brief Stable semantic type of the detected security condition.
     *
     * Composite rules should normally depend on kind rather than rule_id so
     * compatible third-party rules can participate in higher-level analysis.
     *
     * Examples:
     *
     *     "sensitive_resource_access"
     *     "sensitive_data_flow"
     *     "credential_reconnaissance"
     */
    std::string kind;

    /**
     * @brief Severity assigned by the rule that produced this Finding.
     */
    FindingSeverity severity = FindingSeverity::Info;

    /**
     * @brief Short user-facing name of the security result.
     */
    std::string title;

    /**
     * @brief Concise user-facing explanation of the security conclusion.
     *
     * This describes what was concluded, not the complete evidence narrative.
     * Detailed evidence explanation belongs to NarrativeBuilder.
     */
    std::string summary;

    /**
     * @brief Stable graph observations directly supporting this Finding.
     *
     * Values are Observation::seq identifiers, never graph vector indices.
     */
    std::vector<uint64_t> evidence_observation_seqs;

    /**
     * @brief Explicit graph relationships supporting this Finding.
     *
     * Unary Findings such as a single sensitive-file access may leave this
     * empty. Flow or causality Findings should record the relationships that
     * support those claims.
     */
    std::vector<FindingEdgeEvidence> evidence_edges;

    /**
     * @brief Findings from an earlier detection stage supporting this result.
     *
     * Used primarily by composite rules.
     *
     * Example:
     *
     *     several sensitive_resource_access Findings
     *            ->
     *     one credential_reconnaissance Finding
     *
     * Values are Finding::finding_id identifiers.
     */
    std::vector<uint64_t> supporting_finding_ids;

    /**
     * @brief Optional CWE identifiers associated with this Finding.
     *
     * Rules should populate these only when the observed evidence justifies
     * the CWE claim. A suspicious behavior or risky API is not automatically
     * proof that a corresponding CWE exists.
     */
    std::vector<std::string> cwe_ids;

    /**
     * @brief Structured rule-specific facts describing the Finding.
     *
     * These values carry product-relevant context without duplicating the
     * LineageGraph itself.
     */
    FindingAttributes attributes;
};

/**
 * @brief Container for Findings from one RuntimeXRay analysis.
 */
using FindingList = std::vector<Finding>;

} // namespace runtimexray

#endif // RUNTIMEXRAY_FINDING_HPP