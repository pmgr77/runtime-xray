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

echo "--- correlated json findings ---"
grep -o '"location": *"correlated"' "$J" || echo "(none)"
echo "--- correlated text findings ---"
grep 'Location: correlated' "$T" || echo "(none)"

echo "--- assertions ---"
grep -q 'correlated'                  "$J" || { echo FAIL: no correlated finding;  exit 1; }
grep -q "cred.txt"                    "$J" || { echo FAIL: no source_file;         exit 1; }
grep -q 'read_event'                  "$J" || { echo FAIL: no read_event;          exit 1; }
grep -q 'memory_observation'          "$J" || { echo FAIL: no memory_observation;  exit 1; }
# Strengthened: the correlated finding must be backed by a genuine
# scanner-derived memory observation, not just the read buffer.
#
# (a) At least one raw finding with location "memory" exists.
#     That is the marker the scanner writes.
MEM_COUNT=$(grep -c '"location": "memory"' "$J" 2>/dev/null || echo 0)
[ "$MEM_COUNT" -ge 1 ] \
    || { echo FAIL: no scanner-derived memory observation; exit 1; }

# (b) The correlated finding's memory_observation carries a non-zero
#     address. If the emit ever falls back to a non-scanner Data node,
#     this catches it — the read-buffer fallback produces 0x0 under eBPF.
grep -q 'memory_observation{[^}]*address=0x0 ' "$J" \
    && { echo FAIL: correlated memory address is 0x0; exit 1; } || true
grep -q 'memory_observation{[^}]*address=0x[1-9a-f][0-9a-f]*' "$J" \
    || { echo FAIL: correlated memory address missing or zero; exit 1; }
grep -q 'send_event'                  "$J" || { echo FAIL: no send_event;          exit 1; }
grep -q "127.0.0.1:$PORT"             "$J" || { echo FAIL: no socket_destination;  exit 1; }
grep -q 'exact-fingerprint-match'     "$J" || { echo FAIL: no confidence tag;      exit 1; }
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

jq -e '.schema_version == "1.3"' "$J" >/dev/null \
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
