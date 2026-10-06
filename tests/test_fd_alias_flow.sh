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

set -e

BIN="${1:?missing runtimexray binary}"
APP="${2:?missing fd_alias_flow binary}"
BACKEND="${3:?missing backend: ptrace or ebpf}"

if [ "$BACKEND" != "ptrace" ] && [ "$BACKEND" != "ebpf" ]; then
    echo "FAIL: unsupported backend: $BACKEND" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq is required" >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

OUT="$TMPDIR/out.json"

run_trace()
{
    if [ "$BACKEND" = "ebpf" ]; then
        if ! sudo -n true >/dev/null 2>&1; then
            echo "SKIP: passwordless sudo required for eBPF test" >&2
            exit 125
        fi

        sudo "$BIN" trace \
            --backend ebpf \
            --json "$OUT" \
            --report /dev/null \
            "$APP"
    else
        "$BIN" trace \
            --backend ptrace \
            --json "$OUT" \
            --report /dev/null \
            "$APP"
    fi
}

run_trace

if [ ! -s "$OUT" ]; then
    echo "FAIL: JSON report was not created" >&2
    exit 1
fi

#
# Find the secret-bearing pipe write.
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
            fingerprint: .fingerprint
        }
    ' "$OUT" | head -n 1
)"

if [ -z "$WRITE_INFO" ]; then
    echo "FAIL: no secret-bearing write through duplicated pipe FD" >&2
    cat "$OUT" >&2
    exit 1
fi

WRITE_SEQ="$(printf '%s\n' "$WRITE_INFO" | jq -r '.seq')"
RESOURCE_ID="$(printf '%s\n' "$WRITE_INFO" | jq -r '.resource_id')"
FINGERPRINT="$(printf '%s\n' "$WRITE_INFO" | jq -r '.fingerprint')"

echo "write_seq=$WRITE_SEQ resource_id=$RESOURCE_ID"
echo "fingerprint=$FINGERPRINT"

#
# The secret-bearing read must use the same pipe resource and value.
#
READ_SEQ="$(
    jq -r \
        --arg fp "$FINGERPRINT" \
        --argjson rid "$RESOURCE_ID" '
        .lineage.observations[]
        | select(
            .type == "event"
            and .syscall == "read"
            and .resource_type == "pipe"
            and .resource_role == "read"
            and .resource_id == $rid
            and .fingerprint == $fp
        )
        | .seq
    ' "$OUT" | head -n 1
)"

if [ -z "$READ_SEQ" ]; then
    echo "FAIL: no matching read through duplicated pipe FD" >&2
    cat "$OUT" >&2
    exit 1
fi

echo "read_seq=$READ_SEQ resource_id=$RESOURCE_ID"

#
# There must be a dup() observation for the read endpoint carrying
# the same resource identity.
#
if ! jq -e \
    --argjson rid "$RESOURCE_ID" '
    any(
        .lineage.observations[];
        .type == "event"
        and .syscall == "dup"
        and .resource_id == $rid
        and .resource_type == "pipe"
        and .resource_role == "read"
        and .return_value >= 0
    )
' "$OUT" >/dev/null; then
    echo "FAIL: duplicated read FD did not preserve pipe resource identity" >&2
    cat "$OUT" >&2
    exit 1
fi

#
# Same check for the write endpoint.
#
if ! jq -e \
    --argjson rid "$RESOURCE_ID" '
    any(
        .lineage.observations[];
        .type == "event"
        and .syscall == "dup"
        and .resource_id == $rid
        and .resource_type == "pipe"
        and .resource_role == "write"
        and .return_value >= 0
    )
' "$OUT" >/dev/null; then
    echo "FAIL: duplicated write FD did not preserve pipe resource identity" >&2
    cat "$OUT" >&2
    exit 1
fi

echo "dup resource identity assertions passed"

#
# C2 should work unchanged: once the aliases resolve to the same pipe
# resource, exact fingerprint + shared resource establishes DataFlow.
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
    echo "FAIL: no DataFlow edge from aliased pipe write to aliased pipe read" >&2
    cat "$OUT" >&2
    exit 1
fi

echo "DataFlow assertion passed"
echo "fd alias flow test passed ($BACKEND)"