#!/bin/sh

# Copyright 2026 Peter Magram
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -u

RUNTIMEXRAY_BIN="${1:-}"
APP="${2:-}"
BACKEND="${3:-ptrace}"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$APP" ]; then
    echo "usage: $0 <runtimexray-bin> <test-app> [ptrace|ebpf]"
    exit 2
fi

if [ ! -x "$RUNTIMEXRAY_BIN" ]; then
    echo "FAIL: RuntimeXRay binary is not executable: $RUNTIMEXRAY_BIN"
    exit 1
fi

if [ ! -x "$APP" ]; then
    echo "FAIL: test application is not executable: $APP"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "FAIL: jq is required"
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    echo "FAIL: timeout is required"
    exit 1
fi

RUN_PREFIX=""

case "$BACKEND" in
    ptrace)
        ;;

    ebpf)
        if [ "$(id -u)" -eq 0 ]; then
            RUN_PREFIX=""
        elif sudo -n true >/dev/null 2>&1; then
            RUN_PREFIX="sudo -n"
        else
            echo "SKIP: eBPF test requires root or passwordless sudo"
            exit 125
        fi
        ;;

    *)
        echo "FAIL: unsupported backend: $BACKEND"
        exit 2
        ;;
esac

TMP="$(mktemp -d)"
J="$TMP/out.json"

cleanup()
{
    rm -rf "$TMP"
}

trap cleanup EXIT INT TERM

fail()
{
    echo "FAIL: $1"

    if [ -f "$J" ]; then
        echo "--- report ---"
        cat "$J"
        echo "--- end report ---"
    fi

    exit 1
}

SECRET='password=RXRAY_PIPE_CHAIN_ENV_X7kQ2mNv8pLr4ZtW9yBc3'

#
# Run fixture:
#
#   parent --pipe#1--> middle --pipe#2--> child
#
# The exact same sensitive value also exists independently in:
#
#   - environment
#   - process memory
#
# Same fingerprint proves value identity only.
# Causal flow must be backed exclusively by explicit DataFlow edges.
#
timeout 20 \
    $RUN_PREFIX \
    env RXRAY_TEST_SECRET="$SECRET" \
    "$RUNTIMEXRAY_BIN" trace \
        --backend "$BACKEND" \
        --follow-forks \
        --scan-memory \
        --json "$J" \
        "$APP" \
        >/dev/null

RC=$?

if [ "$RC" -ne 0 ]; then
    if [ "$RC" -eq 124 ]; then
        fail "RuntimeXRay timed out"
    fi

    fail "RuntimeXRay exited unsuccessfully with status $RC"
fi

if [ ! -s "$J" ]; then
    fail "JSON report was not created"
fi

#
# Exactly one composite cross-process pipe-chain Finding is expected.
#
CHAIN_COUNT=$(
    jq '
        [
            .findings[]
            | select(
                .kind ==
                    "sensitive_value_cross_process_pipe_chain"
            )
        ]
        | length
    ' "$J"
)

if [ "$CHAIN_COUNT" -ne 1 ]; then
    fail "expected exactly one sensitive pipe-chain finding, got $CHAIN_COUNT"
fi

#
# The composite Finding is authoritative for the fingerprint under test.
#
FP=$(
    jq -r '
        .findings[]
        | select(
            .kind ==
                "sensitive_value_cross_process_pipe_chain"
        )
        | .attributes.fingerprint
    ' "$J"
)

if [ -z "$FP" ] || [ "$FP" = "null" ]; then
    fail "pipe-chain finding has no fingerprint"
fi

echo "fingerprint=$FP"

#
# The same exact value must independently exist in environment.
#
jq -e --arg fp "$FP" '
    any(
        .findings[];

        .kind == "sensitive_data_presence"
        and .attributes.fingerprint == $fp
        and .attributes.location == "environment"
    )
' "$J" >/dev/null || {
    fail "same fingerprint was not observed in environment"
}

#
# The same exact value must independently exist in memory.
#
jq -e --arg fp "$FP" '
    any(
        .findings[];

        .kind == "sensitive_data_presence"
        and .attributes.fingerprint == $fp
        and .attributes.location == "memory"
    )
' "$J" >/dev/null || {
    fail "same fingerprint was not observed in memory"
}

echo "environment + memory identity assertions passed"

#
# Composite semantic contract:
#
#   - 2 explicit process boundaries
#   - 3 execution sessions
#   - 2 pipe resources
#   - explicit DataFlow evidence only
#
jq -e --arg fp "$FP" '
    any(
        .findings[];

        .kind ==
            "sensitive_value_cross_process_pipe_chain"
        and .attributes.fingerprint == $fp
        and .attributes.boundary_count == 2
        and .attributes.session_count == 3
        and (.attributes.resource_ids | length) == 2
        and (.attributes.process_instance_ids | length) == 3
        and (.attributes.sessions | length) == 3
        and .attributes.confidence ==
            "explicit-pipe-dataflow-chain"
        and (.evidence_edges | length) == 2
        and
        all(
            .evidence_edges[];
            .relation == "dataflow"
        )
    )
' "$J" >/dev/null || {
    fail "pipe-chain finding does not contain two explicit DataFlow boundaries"
}

#
# Strong causal-proof invariant:
#
# Every observation directly referenced by the composite Finding must be:
#
#   - Event
#   - same fingerprint
#   - pipe resource
#   - read/write endpoint
#
# Environment and memory findings may be supporting context, but must not
# appear inside evidence_observation_seqs.
#
jq -e --arg fp "$FP" '
    . as $root

    |

    (
        $root.findings[]
        | select(
            .kind ==
                "sensitive_value_cross_process_pipe_chain"
            and .attributes.fingerprint == $fp
        )
        | .evidence_observation_seqs
    ) as $seqs

    |

    all(
        $seqs[];

        . as $seq

        |

        any(
            $root.lineage.observations[];

            .seq == $seq
            and .type == "event"
            and .fingerprint == $fp
            and .resource_type == "pipe"
            and
            (
                .resource_role == "write"
                or
                .resource_role == "read"
            )
        )
    )
' "$J" >/dev/null || {
    fail "environment/memory evidence leaked into pipe-chain proof"
}

echo "pipe-chain evidence assertions passed"

#
# Exactly one NarrativeStory must explain the composite Finding.
#
NARRATIVE_COUNT=$(
    jq --arg fp "$FP" '
        [
            .narratives[]
            | select(
                .fingerprint == $fp
                and
                .title ==
                    "Sensitive value observed across a cross-process pipe chain"
            )
        ]
        | length
    ' "$J"
)

if [ "$NARRATIVE_COUNT" -ne 1 ]; then
    fail "expected exactly one pipe-chain narrative, got $NARRATIVE_COUNT"
fi

#
# One statement per explicit cross-process DataFlow boundary.
#
jq -e --arg fp "$FP" '
    any(
        .narratives[];

        .fingerprint == $fp
        and
        .title ==
            "Sensitive value observed across a cross-process pipe chain"
        and
        (.statements | length) == 2
    )
' "$J" >/dev/null || {
    fail "pipe-chain narrative does not contain exactly two boundary statements"
}

#
# Critical semantic invariant:
#
# Environment/memory fingerprint coincidence must NOT be promoted into
# causality by NarrativeBuilder.
#
jq -e --arg fp "$FP" '
    all(
        .narratives[]
        | select(.fingerprint == $fp)
        | .statements[];

        (
            .text
            | test(
                "environment|memory|inherited|caused";
                "i"
            )
            | not
        )
    )
' "$J" >/dev/null || {
    fail "narrative invented environment/memory causality"
}

#
# Narrative evidence must exactly equal Finding DataFlow evidence.
#
# Normalize both representations into:
#
#   [
#       [write_seq, read_seq],
#       ...
#   ]
#
# and compare the complete sorted arrays.
#
FINDING_EDGES=$(
    jq -c --arg fp "$FP" '
        [
            .findings[]
            | select(
                .kind ==
                    "sensitive_value_cross_process_pipe_chain"
                and .attributes.fingerprint == $fp
            )
            | .evidence_edges[]
            | [
                .from_seq,
                .to_seq
            ]
        ]
        | sort
    ' "$J"
)

NARRATIVE_EDGES=$(
    jq -c --arg fp "$FP" '
        [
            .narratives[]
            | select(
                .fingerprint == $fp
                and
                .title ==
                    "Sensitive value observed across a cross-process pipe chain"
            )
            | .statements[]
            | .evidence_observation_seqs
        ]
        | sort
    ' "$J"
)

echo "finding edges:   $FINDING_EDGES"
echo "narrative edges: $NARRATIVE_EDGES"

if [ "$FINDING_EDGES" != "$NARRATIVE_EDGES" ]; then
    fail "narrative evidence does not exactly match Finding DataFlow edges"
fi

echo "narrative evidence assertions passed"

echo "SENSITIVE PIPE CHAIN ENV SEMANTICS OK ($BACKEND)"