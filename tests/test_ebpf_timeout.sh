#!/bin/sh
set -eu

RUNTIMEXRAY_BIN="${1:-}"
if [ -z "$RUNTIMEXRAY_BIN" ]; then
    echo "Usage: $0 <runtimexray>" >&2
    exit 125
fi

if [ "$(id -u)" -eq 0 ]; then
    RUN_PREFIX=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    RUN_PREFIX="sudo -n"
else
    echo "Skipping eBPF timeout test: root or passwordless sudo required." >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
REPORT="$TMPDIR/report.json"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

$RUN_PREFIX "$RUNTIMEXRAY_BIN" trace \
    --backend ebpf \
    --timeout 1 \
    --json "$REPORT" \
    --report /dev/null \
    /bin/sleep 10

if [ -n "$RUN_PREFIX" ]; then
    $RUN_PREFIX chown "$(id -u):$(id -g)" "$REPORT" 2>/dev/null || true
fi

python3 - "$REPORT" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

if data.get("backend") != "ebpf":
    raise SystemExit("FAIL: JSON does not identify ebpf backend")

if data.get("timed_out") is not True:
    raise SystemExit("FAIL: timed_out is not true")

print("PASS: eBPF timeout is represented structurally")
PY
