#!/bin/sh
set -eu

RUNTIMEXRAY_BIN="${1:-}"
EXEC_TEST_BIN="${2:-}"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$EXEC_TEST_BIN" ]; then
    echo "Usage: $0 <runtimexray> <exec_test>" >&2
    exit 125
fi

if [ "$(id -u)" -eq 0 ]; then
    RUN_PREFIX=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    RUN_PREFIX="sudo -n"
else
    echo "Skipping capture program name test: root or passwordless sudo required." >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
REPORT="$TMPDIR/report.json"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

$RUN_PREFIX "$RUNTIMEXRAY_BIN" trace \
    --timeout 2 \
    --json "$REPORT" \
    --report /dev/null \
    "$EXEC_TEST_BIN"

if [ -n "$RUN_PREFIX" ]; then
    $RUN_PREFIX chown "$(id -u):$(id -g)" "$REPORT" 2>/dev/null || true
fi

python3 - "$REPORT" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
observations = data.get("lineage", {}).get("observations", [])

matched = any(
    obs.get("type") == "event"
    and obs.get("syscall") in {"execve", "execveat"}
    and obs.get("program") == "/bin/echo"
    for obs in observations
)

if not matched:
    raise SystemExit(
        "FAIL: no execve/execveat lineage observation has program=/bin/echo"
    )

print("PASS: exec lineage observation captured program=/bin/echo")
PY
