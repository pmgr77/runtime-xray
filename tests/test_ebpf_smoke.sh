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
    echo "Skipping eBPF smoke test: root or passwordless sudo required." >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
REPORT="$TMPDIR/report.json"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

$RUN_PREFIX "$RUNTIMEXRAY_BIN" trace \
    --backend ebpf \
    --timeout 5 \
    --json "$REPORT" \
    --report /dev/null \
    /bin/true

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

observations = data.get("lineage", {}).get("observations", [])
if not any(
    obs.get("type") == "event"
    and obs.get("syscall") not in (None, "", "process")
    for obs in observations
):
    raise SystemExit("FAIL: eBPF backend produced no syscall lineage observations")

print("PASS: eBPF backend produced structured syscall lineage")
PY
