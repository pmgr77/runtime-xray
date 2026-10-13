#!/bin/sh
set -eu

RUNTIMEXRAY_BIN="${1:-}"
if [ -z "$RUNTIMEXRAY_BIN" ]; then
    echo "Usage: $0 <path-to-runtimexray>" >&2
    exit 1
fi

SECRET="password=cli_secret_test"
TMPDIR="$(mktemp -d)"
REPORT="$TMPDIR/report.json"
TEXT="$TMPDIR/report.txt"

/bin/sh -c 'sleep 5' "$SECRET" >/dev/null 2>&1 &
pid=$!

cleanup() {
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

sleep 0.5

"$RUNTIMEXRAY_BIN" mem \
    --json "$REPORT" \
    --report "$TEXT" \
    "$pid"

python3 - "$REPORT" "$TEXT" "$SECRET" <<'PY'
import json
import pathlib
import sys

report_path, text_path, secret = sys.argv[1:4]
data = json.loads(pathlib.Path(report_path).read_text(encoding="utf-8"))
text = pathlib.Path(text_path).read_text(encoding="utf-8")

observations = data.get("lineage", {}).get("observations", [])
cmdline = [
    obs for obs in observations
    if obs.get("type") == "data"
    and obs.get("data_type") == "cmdline"
    and str(obs.get("fingerprint", "")).startswith("hmac-sha256:")
]

if not cmdline:
    raise SystemExit("FAIL: no cmdline Data observation")

matched = False
for obs in cmdline:
    for finding in data.get("findings", []):
        attrs = finding.get("attributes", {})
        if (
            finding.get("kind") == "sensitive_data_presence"
            and attrs.get("location") == "cmdline"
            and attrs.get("fingerprint") == obs.get("fingerprint")
            and obs.get("seq") in finding.get("evidence_observation_seqs", [])
        ):
            matched = True
            break
    if matched:
        break

if not matched:
    raise SystemExit("FAIL: cmdline observation has no matching finding/evidence")

serialized = pathlib.Path(report_path).read_text(encoding="utf-8")
if secret in serialized or secret in text:
    raise SystemExit("FAIL: raw secret leaked without --show-secrets")

if "<redacted>" not in text:
    raise SystemExit("FAIL: text report did not redact secret")

print("PASS: cmdline secret detected with structured evidence and redaction")
PY
