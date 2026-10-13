#!/bin/sh
set -eu

RUNTIMEXRAY_BIN="${1:-}"
TARGET="${2:-}"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$TARGET" ]; then
    echo "Usage: $0 <runtimexray> <dynamic_target>" >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
REPORT="$TMPDIR/report.json"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

"$RUNTIMEXRAY_BIN" trace \
    --json "$REPORT" \
    --report /dev/null \
    "$TARGET"

python3 - "$REPORT" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
observations = data.get("lineage", {}).get("observations", [])
findings = data.get("findings", [])

stdout_data = [
    obs for obs in observations
    if obs.get("type") == "data"
    and obs.get("data_type") == "stdout"
    and str(obs.get("fingerprint", "")).startswith("hmac-sha256:")
]

if not stdout_data:
    raise SystemExit("FAIL: no sensitive stdout Data observation")

for data_obs in stdout_data:
    fingerprint = data_obs.get("fingerprint")
    seq = data_obs.get("seq")

    write_event = any(
        obs.get("type") == "event"
        and obs.get("syscall") in {"write", "writev"}
        and len(obs.get("args", [])) > 0
        and obs["args"][0] == 1
        and obs.get("fingerprint") == fingerprint
        for obs in observations
    )

    finding = any(
        f.get("kind") == "sensitive_data_presence"
        and f.get("attributes", {}).get("location") == "stdout"
        and f.get("attributes", {}).get("fingerprint") == fingerprint
        and seq in f.get("evidence_observation_seqs", [])
        for f in findings
    )

    if write_event and finding:
        print("PASS: stdout secret is backed by write event and finding evidence")
        raise SystemExit(0)

raise SystemExit(
    "FAIL: sensitive stdout observation was not correlated to both "
    "the write event and its finding"
)
PY
