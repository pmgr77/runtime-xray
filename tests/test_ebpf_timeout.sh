#!/bin/sh
# Regression test for eBPF backend timeout handling.
# Ensures that --timeout terminates the trace and sets a timeout indicator.
# Skips (exit code 125) if eBPF is not available or permissions insufficient.

set -e

RUNTIMEXRAY_BIN="$1"
if [ -z "$RUNTIMEXRAY_BIN" ]; then
    echo "Usage: $0 <path-to-runtimexray>"
    exit 125
fi

if [ "$(id -u)" -ne 0 ]; then
    if ! sudo -n true 2>/dev/null; then
        echo "Skipping eBPF timeout test: root or passwordless sudo required."
        exit 125
    fi
fi

# Run a command that sleeps longer than the timeout
OUTPUT=$(sudo -n "$RUNTIMEXRAY_BIN" trace --backend ebpf --timeout 1 /bin/sleep 10 2>&1)
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "eBPF backend failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Check for timeout message (only printed in non-JSON mode)
if echo "$OUTPUT" | grep -q "Trace timed out"; then
    exit 0
else
    echo "Timeout message not found"
    echo "$OUTPUT"
    exit 1
fi