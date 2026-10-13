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
    echo "Skipping mem lineage test: root or passwordless sudo required." >&2
    exit 125
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../build"
SECRET_HOLDER="${BUILD_DIR}/tests/dynamic_analysis/secret_holder"

if [ ! -x "$SECRET_HOLDER" ]; then
    echo "Skipping test: secret_holder not built." >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
REPORT="$TMPDIR/report.json"

export ENV_SECRET="password=env345"
"$SECRET_HOLDER" "password=cmd678" >/dev/null 2>&1 &
PID=$!

cleanup() {
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

sleep 1

MAX_PAGES="$(
    python3 - "$PID" <<'PY'
import os
import sys

pid = sys.argv[1]
page_size = os.sysconf("SC_PAGE_SIZE")
pages = 0

with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as maps:
    for line in maps:
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith("r"):
            continue

        start_text, end_text = parts[0].split("-", 1)
        start = int(start_text, 16)
        end = int(end_text, 16)
        pages += (end - start + page_size - 1) // page_size

print(pages)
PY
)"

if [ -z "$MAX_PAGES" ] || [ "$MAX_PAGES" -le 0 ]; then
    echo "FAIL: unable to determine readable page count for PID $PID" >&2
    exit 1
fi

echo "Scanning $MAX_PAGES readable pages"

$RUN_PREFIX "$RUNTIMEXRAY_BIN" mem \
    --json "$REPORT" \
    --report /dev/null \
    --max-pages "$MAX_PAGES" \
    "$PID"

if [ -n "$RUN_PREFIX" ]; then
    $RUN_PREFIX chown "$(id -u):$(id -g)" "$REPORT" 2>/dev/null || true
fi

python3 - "$REPORT" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
observations = data.get("lineage", {}).get("observations", [])

memory = [
    obs for obs in observations
    if obs.get("type") == "data"
    and obs.get("data_type") == "memory"
    and str(obs.get("fingerprint", "")).startswith("hmac-sha256:")
]

if not memory:
    raise SystemExit("FAIL: no scanner-derived memory Data observation")

for obs in memory:
    seq = obs.get("seq")
    fingerprint = obs.get("fingerprint")

    for finding in data.get("findings", []):
        attrs = finding.get("attributes", {})
        if (
            finding.get("kind") == "sensitive_data_presence"
            and attrs.get("location") == "memory"
            and attrs.get("fingerprint") == fingerprint
            and seq in finding.get("evidence_observation_seqs", [])
        ):
            print(
                "PASS: memory Data observation is referenced by "
                "sensitive_data_presence finding"
            )
            raise SystemExit(0)

raise SystemExit(
    "FAIL: memory observation exists, but no finding references that exact evidence"
)
PY
