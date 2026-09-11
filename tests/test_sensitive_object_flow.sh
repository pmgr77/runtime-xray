#!/usr/bin/env bash
#
# Phase 1 end-to-end test:
#   file -> read -> sensitive object -> memory -> send -> socket
#
# Verifies that a single sensitive object (fingerprint) is observed on all
# three sides of the flow and correlated into one attacker-oriented result.
set -euo pipefail

BIN="${BIN:-./build/runtimexray}"
APP="${APP:-./build/tests/dynamic_analysis/sensitive_object_flow}"
TMP=$(mktemp -d)
trap 'cat $TMP/out.json; rm -rf "$TMP"; kill ${LISTENER:-} 2>/dev/null || true' EXIT

SECRET='password=SuperSecret123!'
printf '%s\n' "$SECRET" > "$TMP/cred.txt"
echo ">> secret saved to $TMP/cred.txt"

# Loopback listener: publishes its port, accepts one connection, reads, sleeps.
python3 - "$TMP" <<'PY' &
import socket, sys, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
open(sys.argv[1] + "/port", "w").write(str(srv.getsockname()[1]))
c, _ = srv.accept()
c.recv(4096)
time.sleep(4)
PY
LISTENER=$!

for _ in $(seq 1 50); do
    [ -s "$TMP/port" ] && break
    sleep 0.1
done
PORT=$(cat "$TMP/port")

echo ">> JSON file is $TMP/out.json"

"$BIN" trace \
    --backend ptrace \
    --scan-memory \
    --json "$TMP/out.json" \
    "$APP" "$TMP/cred.txt" 127.0.0.1 "$PORT" >/dev/null

wait "$LISTENER" || true
J="$TMP/out.json"

echo "--- correlated findings ---"
grep -o '"location": *"correlated"' "$J" || echo "(none)"

echo "--- assertions ---"
grep -q 'correlated'                        "$J" || { echo FAIL: no correlated finding;  exit 1; }
grep -q "cred.txt"                          "$J" || { echo FAIL: no source_file;         exit 1; }
grep -q 'read_event'                        "$J" || { echo FAIL: no read_event;          exit 1; }
grep -q 'memory_observation'                "$J" || { echo FAIL: no memory_observation;  exit 1; }
grep -q 'send_event'                        "$J" || { echo FAIL: no send_event;          exit 1; }
grep -q "127.0.0.1:$PORT"                   "$J" || { echo FAIL: no socket_destination;  exit 1; }
grep -q 'exact-fingerprint-match'           "$J" || { echo FAIL: no confidence tag;      exit 1; }
! grep -Eiq 'malware|exfiltration|backdoor|attack detected' "$J" \
    || { echo FAIL: forbidden claim; exit 1; }

echo "SENSITIVE OBJECT FLOW OK"