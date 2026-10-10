#!/bin/sh
#
# Regression test for cross-process same-value observations.
#
# parent write(pipe)
#       ->
# child read(pipe)
#       ->
# child memory
#       ->
# child write(stdout)
#
# There is no file source and no socket destination.
#
# The current implementation is expected to FAIL the final semantic
# assertion if it incorrectly constructs a "file to socket" correlation.
#

set -e

# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------
# Linux date supports %N (nanoseconds). Fall back to seconds on platforms
# without it. Resolution on this host is ~1ms via the `date` syscall.

now_ms() {
    d=$(date +%s%N 2>/dev/null) || d=""
    if [ -n "$d" ] && [ "$d" -gt 1000000000 ] 2>/dev/null; then
        # Strip last 6 digits to get milliseconds.
        printf '%s' "$((d / 1000000))"
    else
        printf '%s' "$(($(date +%s) * 1000))"
    fi
}

T0=$(now_ms)
LAST=$T0

# mark <label> : print elapsed time since the last mark, update LAST.
mark() {
    t=$(now_ms)
    delta=$((t - LAST))
    total=$((t - T0))
    printf 'T+%d.%03ds (+%d.%03ds) %s\n' \
        $((total / 1000)) $((total % 1000)) \
        $((delta / 1000)) $((delta % 1000)) \
        "$1" >&2
    LAST=$t
}

mark "script start"

RUNTIMEXRAY_BIN="${1:-./build/runtimexray}"
APP="${2:-./build/tests/dynamic_analysis/pipe_flow}"

mark "config: bin=$RUNTIMEXRAY_BIN app=$APP"

# ---------------------------------------------------------------------------
# Sudo detection
# ---------------------------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    RUN_PREFIX=""
    mark "sudo: already root"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    RUN_PREFIX="sudo -n"
    mark "sudo: passwordless sudo available"
else
    echo "Skipping eBPF sensitive-object flow test: root or passwordless sudo required." >&2
    exit 125
fi

TMP=$(mktemp -d)

cleanup()
{
    rc=$?

    if [ -f "$TMP/out.json" ]; then
        echo "--- report ---"
        cat "$TMP/out.json"
    fi

    rm -rf "$TMP"
    exit "$rc"
}

trap cleanup EXIT INT TERM

$RUN_PREFIX "$RUNTIMEXRAY_BIN" trace \
    --backend ebpf \
    --follow-forks \
    --scan-memory \
    --json "$TMP/out.json" \
    "$APP" >/dev/null

mark "tracer returned"

J="$TMP/out.json"

[ -f "$J" ] || {
    echo "FAIL: no JSON report"
    exit 1
}

#
# Pick the scanner-derived password fingerprint.
#
FP=$(jq -r '
    .findings[]
    | select(
        .kind == "sensitive_data_presence"
        and .attributes.location == "memory"
        and (.attributes.fingerprint // "") != ""
    )
    | .attributes.fingerprint
' "$J" | head -n 1)

[ -n "$FP" ] || {
    echo "FAIL: no scanner-derived secret fingerprint"
    exit 1
}

echo "fingerprint=$FP"

#
# Collection assertions.
#
# These prove that the fixture actually exercises the situation we're
# interested in before testing the semantic conclusion.
#

jq -e --arg fp "$FP" '
    any(
        .lineage.observations[];
        .fingerprint == $fp
        and .type == "event"
        and .syscall == "read"
    )
' "$J" >/dev/null || {
    echo "FAIL: fingerprint never observed in read()"
    exit 1
}

jq -e --arg fp "$FP" '
    any(
        .lineage.observations[];
        .fingerprint == $fp
        and .type == "event"
        and .syscall == "write"
    )
' "$J" >/dev/null || {
    echo "FAIL: fingerprint never observed in write()"
    exit 1
}

jq -e --arg fp "$FP" '
    any(
        .lineage.observations[];
        .fingerprint == $fp
        and .type == "data"
        and .data_type == "memory"
    )
' "$J" >/dev/null || {
    echo "FAIL: no scanner-derived memory occurrence"
    exit 1
}

#
# Same value must be observed in more than one process instance.
#
jq -e --arg fp "$FP" '
    [
        .lineage.observations[]
        | select(.fingerprint == $fp)
        | .process_instance_id
    ]
    | unique
    | length >= 2
' "$J" >/dev/null || {
    echo "FAIL: fixture did not produce cross-process value history"
    exit 1
}

echo "collection assertions passed"

#
# Resource identity assertions.
#
# A pipe is one kernel resource exposed through two FD endpoints.
# The write in the parent and read in the child must therefore resolve
# to the same RuntimeXRay resource identity.
#

PIPE_RID=$(jq -r '
    .lineage.observations[]
    | select(
        .syscall == "pipe2"
        and (.resource_type? // "") == "pipe"
        and (.resource_id? // 0) != 0
    )
    | .resource_id
' "$J" | head -n 1)

[ -n "$PIPE_RID" ] && [ "$PIPE_RID" != "null" ] || {
    echo "FAIL: pipe2 did not create a resource identity"
    exit 1
}

echo "pipe resource_id=$PIPE_RID"

WRITE_RID=$(jq -r --arg fp "$FP" '
    .lineage.observations[]
    | select(
        .type == "event"
        and .syscall == "write"
        and .fingerprint == $fp
    )
    | .resource_id // 0
' "$J" | head -n 1)

READ_RID=$(jq -r --arg fp "$FP" '
    .lineage.observations[]
    | select(
        .type == "event"
        and .syscall == "read"
        and .fingerprint == $fp
    )
    | .resource_id // 0
' "$J" | head -n 1)

echo "parent write resource_id=$WRITE_RID"
echo "child  read  resource_id=$READ_RID"

[ "$WRITE_RID" != "0" ] || {
    echo "FAIL: parent write has no resource identity"
    exit 1
}

[ "$READ_RID" != "0" ] || {
    echo "FAIL: child read has no resource identity"
    exit 1
}

[ "$WRITE_RID" = "$PIPE_RID" ] || {
    echo "FAIL: parent write is not bound to the pipe resource"
    exit 1
}

[ "$READ_RID" = "$PIPE_RID" ] || {
    echo "FAIL: child read is not bound to the inherited pipe resource"
    exit 1
}

jq -e --argjson rid "$PIPE_RID" '
    any(
        .lineage.observations[];
        .resource_id? == $rid
        and .syscall == "write"
        and .resource_role? == "write"
    )
' "$J" >/dev/null || {
    echo "FAIL: pipe write endpoint role missing"
    exit 1
}

jq -e --argjson rid "$PIPE_RID" '
    any(
        .lineage.observations[];
        .resource_id? == $rid
        and .syscall == "read"
        and .resource_role? == "read"
    )
' "$J" >/dev/null || {
    echo "FAIL: pipe read endpoint role missing"
    exit 1
}

echo "resource identity assertions passed"

WRITE_SEQ=$(jq -r --arg fp "$FP" --argjson rid "$PIPE_RID" '
    .lineage.observations[]
    | select(
        .type == "event"
        and .syscall == "write"
        and .fingerprint == $fp
        and .resource_id == $rid
        and .resource_role == "write"
    )
    | .seq
' "$J" | head -n 1)

READ_SEQ=$(jq -r --arg fp "$FP" --argjson rid "$PIPE_RID" '
    .lineage.observations[]
    | select(
        .type == "event"
        and .syscall == "read"
        and .fingerprint == $fp
        and .resource_id == $rid
        and .resource_role == "read"
    )
    | .seq
' "$J" | head -n 1)

echo "pipe transfer write_seq=$WRITE_SEQ read_seq=$READ_SEQ"

jq -e \
    --argjson from "$WRITE_SEQ" \
    --argjson to "$READ_SEQ" '
    any(
        .lineage.edges[];
        .from_seq == $from
        and .to_seq == $to
        and .relation == "dataflow"
    )
' "$J" >/dev/null || {
    echo "FAIL: no DataFlow edge from pipe write to pipe read"
    exit 1
}

echo "pipe DataFlow assertion passed"

#
# Semantic assertion.
#
# Same fingerprint + read + memory + write is NOT enough evidence to call
# this a file-to-socket flow.
#
jq -e '
    all(
        .findings[];
        .kind != "sensitive_data_flow"
    )
' "$J" >/dev/null || {
    echo "FAIL: pipe/stdout flow incorrectly became a sensitive_data_flow finding"
    exit 1
}

jq -e '
    all(
        .narratives[];
        .title != "Sensitive object observed from file to socket"
    )
' "$J" >/dev/null || {
    echo "FAIL: pipe/stdout flow incorrectly became a file-to-socket narrative"
    exit 1
}

echo "PIPE FLOW SEMANTICS OK"