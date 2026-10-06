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

#
# Verifies pipe resource lineage across:
#
#   pipe -> fork -> dup2 -> exec -> read
#
# Expected flow:
#
#   parent write(pipe)
#          |
#          | same resource_id + same fingerprint
#          v
#   exec'd helper read(stdin)
#
# The read must occur in another process instance and after an exec
# generation transition.
#

set -e

BIN="${1:?missing runtimexray binary}"
PARENT="${2:?missing parent fixture}"
HELPER="${3:?missing helper fixture}"
BACKEND="${4:?missing backend: ptrace or ebpf}"

if [ "$BACKEND" != "ptrace" ] && [ "$BACKEND" != "ebpf" ]; then
    echo "FAIL: unsupported backend: $BACKEND" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq is required" >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
#trap 'rm -rf "$TMPDIR"' EXIT

OUT="$TMPDIR/out.json"

if [ "$BACKEND" = "ebpf" ]; then
    if ! sudo -n true >/dev/null 2>&1; then
        echo "SKIP: passwordless sudo required for eBPF test" >&2
        exit 125
    fi

    sudo "$BIN" trace \
        --backend ebpf \
        --follow-forks \
        --json "$OUT" \
        --report /dev/null \
        "$PARENT" "$HELPER"
else
    "$BIN" trace \
        --backend ptrace \
        --follow-forks \
        --json "$OUT" \
        --report /dev/null \
        "$PARENT" "$HELPER"
fi

if [ ! -s "$OUT" ]; then
    echo "FAIL: JSON report was not created" >&2
    exit 1
fi

#
# Find the parent-side secret-bearing pipe write.
#
WRITE_INFO="$(
    jq -c '
        .lineage.observations[]
        | select(
            .type == "event"
            and .syscall == "write"
            and .resource_type == "pipe"
            and .resource_role == "write"
            and .resource_id != null
            and .resource_id != 0
            and (.fingerprint // "") != ""
        )
        | {
            seq: .seq,
            resource_id: .resource_id,
            fingerprint: .fingerprint,
            process_instance_id: .process_instance_id,
            exec_generation: .exec_generation
        }
    ' "$OUT" | head -n 1
)"

if [ -z "$WRITE_INFO" ]; then
    echo "FAIL: no secret-bearing parent pipe write" >&2
    exit 1
fi

WRITE_SEQ="$(printf '%s\n' "$WRITE_INFO" | jq -r '.seq')"
RESOURCE_ID="$(printf '%s\n' "$WRITE_INFO" | jq -r '.resource_id')"
FINGERPRINT="$(printf '%s\n' "$WRITE_INFO" | jq -r '.fingerprint')"
WRITE_INSTANCE="$(printf '%s\n' "$WRITE_INFO" | jq -r '.process_instance_id')"

echo "parent write seq=$WRITE_SEQ resource_id=$RESOURCE_ID"

#
# Find the exec'd helper read from fd 0.
#
READ_INFO="$(
    jq -c \
        --arg fp "$FINGERPRINT" \
        --argjson rid "$RESOURCE_ID" '
        .lineage.observations[]
        | select(
            .type == "event"
            and .syscall == "read"
            and .args[0] == 0
            and .resource_type == "pipe"
            and .resource_role == "read"
            and .resource_id == $rid
            and .fingerprint == $fp
        )
        | {
            seq: .seq,
            process_instance_id: .process_instance_id,
            exec_generation: .exec_generation
        }
    ' "$OUT" | head -n 1
)"

if [ -z "$READ_INFO" ]; then
    echo "FAIL: no matching helper read from inherited pipe stdin" >&2
    exit 1
fi

READ_SEQ="$(printf '%s\n' "$READ_INFO" | jq -r '.seq')"
READ_INSTANCE="$(printf '%s\n' "$READ_INFO" | jq -r '.process_instance_id')"
READ_GENERATION="$(printf '%s\n' "$READ_INFO" | jq -r '.exec_generation')"

echo "helper read seq=$READ_SEQ resource_id=$RESOURCE_ID"
echo "helper process_instance=$READ_INSTANCE exec_generation=$READ_GENERATION"

#
# Parent and helper must be different process instances.
#
if [ "$WRITE_INSTANCE" = "$READ_INSTANCE" ]; then
    echo "FAIL: parent write and helper read have same process instance" >&2
    exit 1
fi

#
# The helper must have crossed an exec boundary.
#
# Generation 0 is inherited from the forked parent image.
# Successful exec should advance the child to generation >= 1.
#
if [ "$READ_GENERATION" -lt 1 ]; then
    echo "FAIL: helper read did not occur after exec transition" >&2
    exit 1
fi

#
# Verify that dup2 itself carried the same pipe resource onto fd 0.
#
if ! jq -e \
    --argjson rid "$RESOURCE_ID" \
    --argjson child "$READ_INSTANCE" '
    any(
        .lineage.observations[];
        .type == "event"
        and (.syscall == "dup2" or .syscall == "dup3")
        and .args[1] == 0
        and .process_instance_id == $child
        and .resource_id == $rid
        and .resource_type == "pipe"
        and .resource_role == "read"
        and .return_value == 0
    )
' "$OUT" >/dev/null; then
    echo "FAIL: dup2 did not preserve pipe resource identity onto fd 0" >&2
    exit 1
fi

echo "dup2 resource identity assertion passed"

#
# The parent write and helper read must be connected by a real DataFlow edge.
#
if ! jq -e \
    --argjson from "$WRITE_SEQ" \
    --argjson to "$READ_SEQ" '
    any(
        .lineage.edges[];
        .from_seq == $from
        and .to_seq == $to
        and .relation == "dataflow"
    )
' "$OUT" >/dev/null; then
    echo "FAIL: no DataFlow edge from parent write to exec'd helper read" >&2
    exit 1
fi

echo "DataFlow assertion passed"
echo "fork/dup2/exec flow test passed ($BACKEND)"