#!/bin/sh
set -eu

RUNTIMEXRAY_BIN="${1:-}"
if [ -z "$RUNTIMEXRAY_BIN" ]; then
    echo "Usage: $0 <runtimexray>" >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
REPORT="$TMPDIR/report.json"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

"$RUNTIMEXRAY_BIN" trace \
    --timeout 2 \
    --json "$REPORT" \
    --report /dev/null \
    /bin/true

python3 - "$REPORT" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
observations = data.get("lineage", {}).get("observations", [])

events = [
    obs for obs in observations
    if obs.get("type") == "event"
    and obs.get("syscall") not in (None, "", "process")
]

if not events:
    raise SystemExit("FAIL: trace produced no syscall lineage observations")

print("PASS: trace produced structured syscall lineage")
PY
