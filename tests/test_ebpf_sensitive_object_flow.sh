#!/bin/sh
# eBPF end-to-end test for the sensitive-object flow:
#   file -> read -> sensitive object -> memory -> send -> socket
#
# Skips (exit 125) if eBPF is not available or permissions are insufficient.
#
# Every phase is timed. Timings are printed to stderr with a "T+NNN.NNNs"
# prefix so they show up under CTest's --output-on-failure output and are
# easy to grep.
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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RUNTIMEXRAY_BIN="${1:-./build/runtimexray}"
APP="${2:-${APP:-./build/tests/dynamic_analysis/sensitive_object_flow}}"

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

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
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

mark "tmpdir created: $TMP"

SECRET='password=SuperSecret123!'
printf '%s\n' "$SECRET" > "$TMP/cred.txt"
mark "credential file written"

# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------
mark "starting python listener"

python3 - "$TMP" </dev/null >/dev/null 2>&1 <<'PY' &
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

mark "listener process spawned (pid=$LISTENER), waiting for port file"

# ---------------------------------------------------------------------------
# Wait for the port file
# ---------------------------------------------------------------------------
for _ in $(seq 1 30); do
    [ -s "$TMP/port" ] && break
    sleep 0.1
done
if [ ! -s "$TMP/port" ]; then
    mark "FAIL: listener did not publish a port within 3s"
    exit 1
fi
PORT=$(cat "$TMP/port")

mark "port published: $PORT"

# ---------------------------------------------------------------------------
# Trace
# ---------------------------------------------------------------------------
mark "starting tracer (this is where most of the wall time goes)"

$RUN_PREFIX "$RUNTIMEXRAY_BIN" trace \
    --backend ebpf \
    --show-secrets \
    --scan-memory \
    --json "$TMP/out.json" \
    "$APP" "$TMP/cred.txt" 127.0.0.1 "$PORT" </dev/null >/dev/null

mark "tracer returned"

# ---------------------------------------------------------------------------
# Hand the file back to the invoking user if it was written by root.
# ---------------------------------------------------------------------------
if [ -n "$RUN_PREFIX" ] && [ -f "$TMP/out.json" ]; then
    $RUN_PREFIX chown "$(id -u):$(id -g)" "$TMP/out.json" 2>/dev/null || true
    mark "out.json chowned back to user"
fi

# ---------------------------------------------------------------------------
# Wait for the listener to finish
# ---------------------------------------------------------------------------
mark "waiting for listener to exit (should be < 4s)"

wait "$LISTENER" 2>/dev/null || true
LISTENER=""

mark "listener exited"

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------
J="$TMP/out.json"
[ -f "$J" ] || { echo "FAIL: no JSON report produced"; exit 1; }
mark "json report present ($(wc -c < "$J") bytes)"

echo "--- correlated findings ---"
grep -o '"location": *"correlated"' "$J" || echo "(none)"

echo "--- assertions ---"
grep -q 'correlated'                  "$J" || { echo FAIL: no correlated finding;  exit 1; }
grep -q "cred.txt"                    "$J" || { echo FAIL: no source_file;         exit 1; }
grep -q 'read_event'                  "$J" || { echo FAIL: no read_event;          exit 1; }
grep -q 'memory_observation'          "$J" || { echo FAIL: no memory_observation;  exit 1; }
grep -q 'send_event'                  "$J" || { echo FAIL: no send_event;          exit 1; }
grep -q "127.0.0.1:$PORT"             "$J" || { echo FAIL: no socket_destination;  exit 1; }
grep -q 'exact-fingerprint-match'     "$J" || { echo FAIL: no confidence tag;      exit 1; }
! grep -Eiq 'malware|exfiltration|backdoor|attack detected' "$J" \
    || { echo FAIL: forbidden claim; exit 1; }

mark "assertions passed"
echo "SENSITIVE OBJECT FLOW OK (ebpf)"
