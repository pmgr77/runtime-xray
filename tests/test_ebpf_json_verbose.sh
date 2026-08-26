#!/bin/sh
# Regression test for eBPF JSON verbose output.
# Ensures that findings with Low severity are included when --verbose is used.
# Skips (exit code 125) if eBPF is not available or permissions are insufficient.

set -e

RUNTIMEXRAY_BIN="$1"
if [ -z "$RUNTIMEXRAY_BIN" ]; then
    echo "Usage: $0 <path-to-runtimexray>"
    exit 125
fi

# Determine if we need sudo
if [ "$(id -u)" -eq 0 ]; then
    RUN_PREFIX=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    RUN_PREFIX="sudo -n"
else
    echo "Skipping eBPF verbose JSON test: root or passwordless sudo required."
    exit 125
fi

# Run trace with eBPF, JSON, and verbose on curl (opens /etc/resolv.conf, /etc/hosts)
OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --backend ebpf --verbose --timeout 5 --output-format json /usr/bin/curl https://example.com 2>&1)
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "eBPF backend failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Parse JSON and check for a finding with severity "Low"
if command -v python3 >/dev/null 2>&1; then
    echo "$OUTPUT" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError as e:
    print(f"Invalid JSON: {e}")
    sys.exit(1)

findings = data.get("findings", [])
low_found = any(f.get("severity") == "Low" for f in findings)
if not low_found:
    print("No Low severity finding found.")
    print("Output:", json.dumps(data, indent=2))
    sys.exit(1)
print("Low severity finding detected. Test passed.")
' || exit 1
else
    echo "python3 not found, cannot validate JSON. Exiting as skipped."
    exit 125
fi

exit 0