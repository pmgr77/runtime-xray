#!/bin/sh
# Test that --follow-forks traces child processes.

set -e

RUNTIMEXRAY_BIN="$1"
FORK_TEST_BIN="$2"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$FORK_TEST_BIN" ]; then
    echo "Usage: $0 <runtimexray> <fork_test>"
    exit 125
fi

# Determine if we need sudo (for ptrace)
if [ "$(id -u)" -eq 0 ]; then
    RUN_PREFIX=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    RUN_PREFIX="sudo -n"
else
    echo "Skipping fork test: root or passwordless sudo required."
    exit 125
fi

# Run trace with --follow-forks (default) and capture output
OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --timeout 2 "$FORK_TEST_BIN" 2>&1)
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "Trace failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Extract unique PIDs from syscall lines (format: "pid=12345")
PIDS=$(echo "$OUTPUT" | grep -o "pid=[0-9]*" | sed 's/pid=//' | sort -u)
COUNT=$(echo "$PIDS" | wc -l)

if [ $COUNT -ge 2 ]; then
    echo "Found $COUNT distinct PIDs, fork tracing works."
    exit 0
else
    echo "Expected at least 2 distinct PIDs, got $COUNT"
    echo "$OUTPUT"
    exit 1
fi