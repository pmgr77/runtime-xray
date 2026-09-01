#!/bin/sh
# Test that lineage graph captures program name from execve

set -e

RUNTIMEXRAY_BIN="$1"
EXEC_TEST_BIN="$2"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$EXEC_TEST_BIN" ]; then
    echo "Usage: $0 <runtimexray> <exec_test>"
    exit 125
fi

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
        echo "Skipping capture program name test: root or passwordless sudo required."
        exit 125
    fi
    RUN_PREFIX="sudo -n"
else
    RUN_PREFIX=""
fi

OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --log-level debug --timeout 2 "$EXEC_TEST_BIN" 2>&1)
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "Trace failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Check that the graph shows program name "/bin/echo"
if echo "$OUTPUT" | grep -q "/bin/echo"; then
    echo "Program name detected in lineage graph."
    exit 0
else
    echo "Program name not found in lineage graph."
    echo "$OUTPUT"
    exit 1
fi