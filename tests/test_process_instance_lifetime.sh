#!/bin/sh

set -e

RUNTIMEXRAY_BIN="${1:-./build/runtimexray}"
APP="${2:-./build/tests/dynamic_analysis/thread_lifecycle_test}"

TMP=$(mktemp -d)

cleanup()
{
    rc=$?

    if [ -f "$TMP/out.json" ]; then
        cat "$TMP/out.json"
    fi

    rm -rf "$TMP"
    exit "$rc"
}

trap cleanup EXIT INT TERM

timeout 10 "$RUNTIMEXRAY_BIN" trace \
    --backend ptrace \
    --follow-forks \
    --json "$TMP/out.json" \
    "$APP" >/dev/null

J="$TMP/out.json"

[ -f "$J" ] || {
    echo "FAIL: no JSON report"
    exit 1
}

#
# Determine the TGID of the original target process.
#
TGID=$(jq -r '
    .lineage.observations[]
    | select(.syscall == "process" and .program != null)
    | .tgid
' "$J" | head -n 1)

[ -n "$TGID" ] || {
    echo "FAIL: could not determine target TGID"
    exit 1
}

echo "target tgid=$TGID"

#
# Sanity: the trace must actually contain more than one TID belonging
# to this TGID.
#
TID_COUNT=$(jq --argjson tgid "$TGID" '
    [
        .lineage.observations[]
        | select(.tgid == $tgid)
        | .tid
    ]
    | unique
    | length
' "$J")

echo "distinct tids=$TID_COUNT"

[ "$TID_COUNT" -ge 2 ] || {
    echo "FAIL: fixture did not exercise multiple threads"
    exit 1
}

#
# Core invariant #1:
# one active Linux TGID lifetime must have exactly one process node.
#
PROCESS_NODE_COUNT=$(jq --argjson tgid "$TGID" '
    [
        .lineage.observations[]
        | select(
            .tgid == $tgid
            and .syscall == "process"
        )
    ]
    | length
' "$J")

echo "process nodes=$PROCESS_NODE_COUNT"

[ "$PROCESS_NODE_COUNT" -eq 1 ] || {
    echo "FAIL: same TGID produced multiple process nodes"
    exit 1
}

#
# Core invariant #2:
# every observation from that TGID must carry the same process instance.
#
INSTANCE_COUNT=$(jq --argjson tgid "$TGID" '
    [
        .lineage.observations[]
        | select(.tgid == $tgid)
        | .process_instance_id
    ]
    | unique
    | length
' "$J")

echo "process instances=$INSTANCE_COUNT"

[ "$INSTANCE_COUNT" -eq 1 ] || {
    echo "FAIL: same TGID lifetime received multiple process_instance_ids"
    exit 1
}

echo "PROCESS INSTANCE LIFETIME OK"