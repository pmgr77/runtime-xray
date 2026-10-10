#!/bin/sh
# Ptrace end-to-end test for the sensitive-object flow:
#   file -> read -> sensitive object -> memory -> send -> socket
set -e

RUNTIMEXRAY_BIN="${1:-./build/runtimexray}"
APP="${2:-${APP:-./build/tests/dynamic_analysis/sensitive_object_flow}}"

TMP=$(mktemp -d)
LISTENER=""

cleanup() {
    rc=$?
    if [ -n "${LISTENER:-}" ]; then
        kill "$LISTENER" 2>/dev/null || true
        wait "$LISTENER" 2>/dev/null || true
    fi
    if [ -f "$TMP/out.json" ]; then
        cat "$TMP/out.json" 2>/dev/null || true
    fi
    rm -rf "$TMP"
    exit $rc
}
trap cleanup EXIT INT TERM

SECRET='password=SuperSecret123!'
printf '%s\n' "$SECRET" > "$TMP/cred.txt"

python3 - "$TMP" >/dev/null 2>&1 <<'PY' &
import socket, sys, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
# Non-blocking accept with a hard cap so the listener cannot outlive the
# test even if the app never connects.
srv.settimeout(10)
open(sys.argv[1] + "/port", "w").write(str(srv.getsockname()[1]))
try:
    c, _ = srv.accept()
    c.recv(4096)
except socket.timeout:
    pass
time.sleep(3)
PY
LISTENER=$!

for _ in $(seq 1 30); do
    [ -s "$TMP/port" ] && break
    sleep 0.1
done
[ -s "$TMP/port" ] || { echo "FAIL: listener did not publish a port"; exit 1; }
PORT=$(cat "$TMP/port")

# ptrace runs as the invoking user; timeout terminates cleanly.
timeout 10 "$RUNTIMEXRAY_BIN" trace \
    --backend ptrace \
    --show-secrets \
    --scan-memory \
    --json "$TMP/out.json" \
    --report "$TMP/out.txt" \
    "$APP" "$TMP/cred.txt" 127.0.0.1 "$PORT" >/dev/null

wait "$LISTENER" 2>/dev/null || true
LISTENER=""

J="$TMP/out.json"
T="$TMP/out.txt"
[ -f "$J" ] || { echo "FAIL: no JSON report produced"; exit 1; }
[ -f "$T" ] || { echo "FAIL: no TEXT report produced"; exit 1; }

echo "--- composite flow finding ---"

jq -e '
    any(
        .findings[];
        .kind == "sensitive_data_flow"
        and .rule_id == "builtin.sensitive_data_flow"
        and .title == "Sensitive object observed from file to socket"
    )
' "$J" >/dev/null \
    || { echo FAIL: no sensitive_data_flow finding; exit 1; }

echo "--- assertions ---"

#
# Validate the semantic finding and its structured attributes.
#
jq -e --arg endpoint "127.0.0.1:$PORT" '
    any(
        .findings[];
        .kind == "sensitive_data_flow"
        and (.attributes.source_file | endswith("/cred.txt"))
        and .attributes.socket_destination == $endpoint
        and .attributes.confidence == "exact-fingerprint-match"
        and .attributes.secret_type == "password"
    )
' "$J" >/dev/null \
    || { echo FAIL: sensitive_data_flow attributes are incomplete; exit 1; }

#
# The flow must be backed by a genuine read/recvfrom Event.
#
jq -e '
    . as $doc
    |
    any(
        .findings[];
        .kind == "sensitive_data_flow"
        and (
            .evidence_observation_seqs as $evidence
            |
            any(
                $doc.lineage.observations[];
                (.seq as $seq | $evidence | index($seq)) != null
                and .type == "event"
                and (
                    .syscall == "read"
                    or .syscall == "recvfrom"
                )
            )
        )
    )
' "$J" >/dev/null \
    || { echo FAIL: flow has no read-event evidence; exit 1; }

#
# The flow must contain scanner-derived memory evidence with a real address.
#
jq -e '
    . as $doc
    |
    any(
        .findings[];
        .kind == "sensitive_data_flow"
        and (
            .evidence_observation_seqs as $evidence
            |
            any(
                $doc.lineage.observations[];
                (.seq as $seq | $evidence | index($seq)) != null
                and .type == "data"
                and .data_type == "memory"
                and (.address // 0) > 0
            )
        )
    )
' "$J" >/dev/null \
    || { echo FAIL: flow has no scanner-derived memory evidence; exit 1; }

#
# The flow must contain an outbound syscall carrying the same value.
#
jq -e '
    . as $doc
    |
    any(
        .findings[];
        .kind == "sensitive_data_flow"
        and (
            .evidence_observation_seqs as $evidence
            |
            any(
                $doc.lineage.observations[];
                (.seq as $seq | $evidence | index($seq)) != null
                and .type == "event"
                and (
                    .syscall == "write"
                    or .syscall == "writev"
                    or .syscall == "sendto"
                )
            )
        )
    )
' "$J" >/dev/null \
    || { echo FAIL: flow has no outbound-event evidence; exit 1; }

#
# Composite finding must explicitly reference the Primary findings
# from which it was derived.
#
jq -e '
    any(
        .findings[];
        .kind == "sensitive_data_flow"
        and (.supporting_finding_ids | length) > 0
    )
' "$J" >/dev/null \
    || { echo FAIL: flow has no supporting primary findings; exit 1; }

#
# RuntimeXRay reports observations, not unsupported intent claims.
#
! grep -Eiq 'malware|exfiltration|backdoor|attack detected' "$J" \
    || { echo FAIL: forbidden claim; exit 1; }

echo "--- narrative text assertions ---"

grep -q '^Narratives:' "$T" \
    || { echo FAIL: no narrative section in text report; exit 1; }

grep -q 'Sensitive object observed from file to socket' "$T" \
    || { echo FAIL: no correlated narrative title; exit 1; }

grep -q 'read() from file' "$T" \
    || { echo FAIL: narrative missing file-read statement; exit 1; }

grep -q 'process memory at address 0x' "$T" \
    || { echo FAIL: narrative missing memory statement; exit 1; }

grep -q "socket connected to 127.0.0.1:$PORT" "$T" \
    || { echo FAIL: narrative missing socket destination; exit 1; }

grep -q 'Evidence: seq=' "$T" \
    || { echo FAIL: narrative missing evidence references; exit 1; }


echo "--- narrative JSON assertions ---"

jq -e '.schema_version == "2.0"' "$J" >/dev/null \
    || { echo FAIL: wrong JSON schema version; exit 1; }

jq -e '.narratives | type == "array" and length > 0' "$J" >/dev/null \
    || { echo FAIL: no JSON narratives; exit 1; }

jq -e '
    any(
        .narratives[];
        .title == "Sensitive object observed from file to socket"
    )
' "$J" >/dev/null \
    || { echo FAIL: correlated narrative missing from JSON; exit 1; }

# validate the structure of that narrative:

jq -e '
    .narratives[]
    | select(.title == "Sensitive object observed from file to socket")
    | .sessions | length >= 1
' "$J" >/dev/null \
    || { echo FAIL: narrative has no session context; exit 1; }

jq -e '
    .narratives[]
    | select(.title == "Sensitive object observed from file to socket")
    | .statements | length == 3
' "$J" >/dev/null \
    || { echo FAIL: narrative does not contain three statements; exit 1; }

# prove that statements have evidence:

jq -e '
    .narratives[]
    | select(.title == "Sensitive object observed from file to socket")
    | all(
        .statements[];
        (.evidence_observation_seqs | length) > 0
    )
' "$J" >/dev/null \
    || { echo FAIL: narrative statement missing observation evidence; exit 1; }

# Validate the actual meaning too

jq -e --arg endpoint "127.0.0.1:$PORT" '
    .narratives[]
    | select(.title == "Sensitive object observed from file to socket")
    | any(
        .statements[];
        (.text | contains($endpoint))
    )
' "$J" >/dev/null \
    || { echo FAIL: JSON narrative missing socket endpoint; exit 1; }

# temporary credential file:

jq -e '
    .narratives[]
    | select(.title == "Sensitive object observed from file to socket")
    | any(
        .statements[];
        (.text | contains("cred.txt"))
    )
' "$J" >/dev/null \
    || { echo FAIL: JSON narrative missing source file; exit 1; }

# memory:
jq -e '
    .narratives[]
    | select(.title == "Sensitive object observed from file to socket")
    | any(
        .statements[];
        (.text | contains("process memory at address 0x"))
    )
' "$J" >/dev/null \
    || { echo FAIL: JSON narrative missing memory observation; exit 1; }

echo "--- lineage reference assertions ---"

jq -e '
    .lineage.observations
    | type == "array" and length > 0
' "$J" >/dev/null \
    || { echo FAIL: lineage observations missing; exit 1; }

jq -e '
    .lineage.edges
    | type == "array"
' "$J" >/dev/null \
    || { echo FAIL: lineage edges missing; exit 1; }

jq -e '
    (.lineage.observations | map(.seq)) as $seqs
    |
    all(
        .findings[]
        .evidence_observation_seqs[]?;
        . as $seq
        | ($seqs | index($seq)) != null
    )
' "$J" >/dev/null \
    || {
        echo FAIL: finding evidence reference missing from lineage;
        exit 1;
    }

jq -e '
    (.lineage.observations | map(.seq)) as $seqs
    |
    all(
        .narratives[]
        .statements[]
        .evidence_observation_seqs[];
        . as $seq
        | ($seqs | index($seq)) != null
    )
' "$J" >/dev/null \
    || {
        echo FAIL: narrative evidence reference missing from lineage;
        exit 1;
    }

jq -e '
    all(
        .lineage.observations[];
        .seq > 0
    )
' "$J" >/dev/null \
    || { echo FAIL: zero lineage sequence; exit 1; }

echo "SENSITIVE OBJECT FLOW OK (ptrace)"
