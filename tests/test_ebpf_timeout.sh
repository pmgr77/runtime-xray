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

set -x   # echo every command

# Determine if we need sudo
if [ "$(id -u)" -eq 0 ]; then
    RUN_PREFIX=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    RUN_PREFIX="sudo -n"
else
    echo "Skipping eBPF timeout JSON test: root or passwordless sudo required."
    exit 125
fi

# Run a command that sleeps longer than the timeout
OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --backend ebpf --timeout 1 /bin/sleep 10 2>&1)
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "eBPF backend failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Check for timeout indication in metadata
if echo "$OUTPUT" | grep -q "Timed out: yes"; then
    exit 0
else
    echo "Timeout message not found"
    echo "$OUTPUT"
    exit 1
fi
