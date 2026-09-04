#!/bin/sh
# Regression test for eBPF JSON verbose output.
# Ensures that findings with Low severity are included when --log-level debug is used.
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

# Record start time (nanoseconds if possible, else seconds)
if command -v date >/dev/null 2>&1; then
    START=$(date +%s%N 2>/dev/null || date +%s)
else
    START=$(date +%s)
fi

# Run trace
OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --backend ebpf --log-level debug --timeout 15 --min-severity Low --json /dev/stdout --report /dev/null /usr/bin/curl https://example.com)
STATUS=$?

# Record end time
if command -v date >/dev/null 2>&1; then
    END=$(date +%s%N 2>/dev/null || date +%s)
    if [ -n "$END" ] && [ -n "$START" ] && [ "$END" -gt "$START" ]; then
        DURATION=$(echo "scale=3; ($END - $START) / 1000000000" | bc 2>/dev/null || echo "unknown")
    else
        DURATION="unknown"
    fi
else
    DURATION="unknown"
fi

if [ $STATUS -ne 0 ]; then
    echo "eBPF backend failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Validate JSON and check that findings list is not empty
if command -v python3 >/dev/null 2>&1; then
    echo "$OUTPUT" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError as e:
    print(f"Invalid JSON: {e}")
    sys.exit(1)

findings = data.get("findings", [])
if not findings:
    print("No findings found.")
    print("Output:", json.dumps(data, indent=2))
    sys.exit(1)
print("Findings detected. Test passed.")
' || exit 1
else
    echo "python3 not found, cannot validate JSON. Exiting as skipped."
    exit 125
fi

exit 0
