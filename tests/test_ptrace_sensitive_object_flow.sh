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
    "$APP" "$TMP/cred.txt" 127.0.0.1 "$PORT" >/dev/null

wait "$LISTENER" 2>/dev/null || true
LISTENER=""

J="$TMP/out.json"
[ -f "$J" ] || { echo "FAIL: no JSON report produced"; exit 1; }

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

echo "SENSITIVE OBJECT FLOW OK (ptrace)"
