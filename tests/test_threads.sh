#!/bin/sh
set -eu

RUNTIMEXRAY_BIN="${1:-}"
THREAD_TEST_BIN="${2:-}"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$THREAD_TEST_BIN" ]; then
    echo "Usage: $0 <runtimexray> <thread_test>" >&2
    exit 125
fi

if [ "$(id -u)" -eq 0 ]; then
    RUN_PREFIX=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    RUN_PREFIX="sudo -n"
else
    echo "Skipping thread test: root or passwordless sudo required." >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
REPORT="$TMPDIR/report.json"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

$RUN_PREFIX "$RUNTIMEXRAY_BIN" trace     --follow-forks     --timeout 5     --json "$REPORT"     --report /dev/null     "$THREAD_TEST_BIN"

if [ -n "$RUN_PREFIX" ]; then
    $RUN_PREFIX chown "$(id -u):$(id -g)" "$REPORT" 2>/dev/null || true
fi

python3 - "$REPORT" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
observations = data.get("lineage", {}).get("observations", [])

thread_event = any(
    obs.get("type") == "event"
    and isinstance(obs.get("tid"), int)
    and isinstance(obs.get("tgid"), int)
    and obs["tid"] > 0
    and obs["tgid"] > 0
    and obs["tid"] != obs["tgid"]
    for obs in observations
)

if not thread_event:
    raise SystemExit("FAIL: no lineage event from a non-leader thread")

print("PASS: thread activity is represented by distinct TID/TGID")
PY
