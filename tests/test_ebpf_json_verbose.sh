#!/bin/sh
set -eu

RUNTIMEXRAY_BIN="${1:-}"
TARGET="${2:-}"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$TARGET" ]; then
    echo "Usage: $0 <runtimexray> <dynamic_target>" >&2
    exit 125
fi

if [ "$(id -u)" -eq 0 ]; then
    RUN_PREFIX=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    RUN_PREFIX="sudo -n"
else
    echo "Skipping eBPF Low-severity JSON test: root or passwordless sudo required." >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
REPORT="$TMPDIR/report.json"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

$RUN_PREFIX "$RUNTIMEXRAY_BIN" trace \
    --backend ebpf \
    --timeout 5 \
    --min-severity Low \
    --json "$REPORT" \
    --report /dev/null \
    "$TARGET"

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

low = [
    finding
    for finding in data.get("findings", [])
    if finding.get("severity") == "Low"
]

if not low:
    raise SystemExit("FAIL: --min-severity Low produced no Low finding")

print("PASS: Low-severity finding is present in eBPF JSON output")
PY
