#!/bin/sh
#
# Regression test for cross-boundary sensitive-value observations.
#
# The same sensitive value is:
#
#   parent -> stdout
#   child  -> stdout
#   child  -> socket send
#
# This proves that RuntimeXRay can observe the same value across several
# output boundaries and process instances.
#
# It does NOT prove a file -> socket flow because there is no file source
# and no read-from-file evidence.
#

set -e

RUNTIMEXRAY_BIN="$1"
EXEC_TEST_BIN="$2"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$EXEC_TEST_BIN" ]; then
    echo "Usage: $0 <runtimexray> <cross_boundary_test>"
    exit 125
fi

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1 ||
       ! sudo -n true 2>/dev/null; then
        echo "Skipping cross-boundary test: root or passwordless sudo required."
        exit 125
    fi

    RUN_PREFIX="sudo -n"
else
    RUN_PREFIX=""
fi

TMP=$(mktemp -d)

cleanup()
{
    rc=$?

    if [ -f "$TMP/out.json" ] && [ "$rc" -ne 0 ]; then
        echo "--- report ---"
        cat "$TMP/out.json"
    fi

    rm -rf "$TMP"
    exit "$rc"
}

trap cleanup EXIT INT TERM

SECRET='password=secret123'

$RUN_PREFIX "$RUNTIMEXRAY_BIN" trace \
    --follow-forks \
    --timeout 10 \
    --json "$TMP/out.json" \
    "$EXEC_TEST_BIN" "$SECRET" >/dev/null

J="$TMP/out.json"

[ -f "$J" ] || {
    echo "FAIL: no JSON report"
    exit 1
}

#
# Obtain the exact-value identity from the network-side observation.
#
FP=$(jq -r '
    .findings[]
    | select(
        .kind == "sensitive_data_presence"
        and .attributes.location == "sendto_data"
        and (.attributes.fingerprint // "") != ""
    )
    | .attributes.fingerprint
' "$J" | head -n 1)

[ -n "$FP" ] && [ "$FP" != "null" ] || {
    echo "FAIL: no network sensitive-data fingerprint"
    exit 1
}

echo "fingerprint=$FP"

#
# The same exact sensitive value must have been observed in stdout.
#
jq -e --arg fp "$FP" '
    any(
        .findings[];
        .kind == "sensitive_data_presence"
        and .attributes.location == "stdout"
        and .attributes.fingerprint == $fp
    )
' "$J" >/dev/null || {
    echo "FAIL: same sensitive value not observed in stdout"
    exit 1
}

echo "stdout observation present"

#
# The same exact value must have been observed in socket-bound data.
#
jq -e --arg fp "$FP" '
    any(
        .findings[];
        .kind == "sensitive_data_presence"
        and .attributes.location == "sendto_data"
        and .attributes.fingerprint == $fp
    )
' "$J" >/dev/null || {
    echo "FAIL: same sensitive value not observed in network send"
    exit 1
}

echo "network observation present"

#
# Verify the syscall-level evidence too.
#
jq -e --arg fp "$FP" '
    any(
        .lineage.observations[];
        .type == "event"
        and (
            .syscall == "write"
            or .syscall == "writev"
        )
        and .fingerprint == $fp
    )
' "$J" >/dev/null || {
    echo "FAIL: no stdout write event carrying fingerprint"
    exit 1
}

jq -e --arg fp "$FP" '
    any(
        .lineage.observations[];
        .type == "event"
        and .syscall == "sendto"
        and .fingerprint == $fp
    )
' "$J" >/dev/null || {
    echo "FAIL: no network send event carrying fingerprint"
    exit 1
}

echo "syscall evidence present"

#
# The fixture forks. The same value should therefore be visible across
# more than one RuntimeXRay process instance.
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
    echo "FAIL: value was not observed across process instances"
    exit 1
}

echo "cross-process value history present"

#
# Critical semantic assertion:
#
# Exact fingerprint equality across stdout and network output does not
# establish provenance or causal file -> socket flow.
#
jq -e '
    all(
        .findings[];
        .kind != "sensitive_data_flow"
    )
' "$J" >/dev/null || {
    echo "FAIL: output observations incorrectly became sensitive_data_flow"
    exit 1
}

jq -e '
    all(
        .narratives[];
        .title != "Sensitive object observed from file to socket"
    )
' "$J" >/dev/null || {
    echo "FAIL: output observations incorrectly became file-to-socket narrative"
    exit 1
}

echo "CROSS-BOUNDARY EVIDENCE SEMANTICS OK"