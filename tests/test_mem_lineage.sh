#!/bin/sh
# Test that mem command produces lineage graph with data observations

set -e

RUNTIMEXRAY_BIN="$1"
if [ -z "$RUNTIMEXRAY_BIN" ]; then
    echo "Usage: $0 <runtimexray>"
    exit 125
fi

# Find secret_holder binary
SCRIPT_DIR=$(dirname "$0")
BUILD_DIR="${SCRIPT_DIR}/../build"
SECRET_HOLDER="${BUILD_DIR}/tests/dynamic_analysis/secret_holder"
if [ ! -x "$SECRET_HOLDER" ]; then
    echo "Skipping test: secret_holder not built."
    exit 125
fi

# Set environment secret and run with command-line secret
export ENV_SECRET="password=env345"
"$SECRET_HOLDER" "password=cmd678" &
PID=$!
sleep 2

# Run mem with debug logs and capture output
OUTPUT=$(sudo "$RUNTIMEXRAY_BIN" mem --log-level debug --max-pages 5000 --json /dev/stdout $PID 2>&1)
STATUS=$?
kill $PID 2>/dev/null || true

if [ $STATUS -ne 0 ]; then
    echo "mem failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Check for any of the secrets (all start with "password=")
if echo "$OUTPUT" | grep -q "password="; then
    echo "Lineage graph contains data observation."
    exit 0
else
    echo "Lineage graph does not contain any secret."
    echo "$OUTPUT"
    exit 1
fi