#!/bin/sh
# Regression test: eBPF backend JSON output when no findings are expected.
# Ensures valid empty report structure.
# Skips (exit code 125) if eBPF is not available or permissions insufficient.

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
    echo "Skipping eBPF empty JSON test: root or passwordless sudo required."
    exit 125
fi

# Run a simple command that should not generate sensitive findings
OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --backend ebpf --timeout 1 --output-format json /bin/true 2>&1)
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "eBPF backend failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Validate JSON and check that findings is an empty list and summary.total == 0
echo "$OUTPUT" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError as e:
    print(f"Invalid JSON: {e}")
    sys.exit(1)

if "findings" not in data or "summary" not in data:
    print("Missing findings/summary fields")
    sys.exit(1)
if len(data["findings"]) != 0:
    print("Expected no findings, got", data["findings"])
    sys.exit(1)
if data["summary"].get("total", -1) != 0:
    print("Expected total=0, got", data["summary"].get("total"))
    sys.exit(1)
print("Empty JSON test passed.")
'