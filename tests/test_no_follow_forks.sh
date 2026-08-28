#!/bin/sh
# Test that --no-follow-forks disables child process tracing.

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
    echo "Skipping no-follow-forks test: root or passwordless sudo required."
    exit 125
fi

# Run trace with --no-follow-forks
OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --no-follow-forks --timeout 2 "$FORK_TEST_BIN" 2>&1)
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "Trace failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Extract unique PIDs from syscall lines
PIDS=$(echo "$OUTPUT" | grep -o "pid=[0-9]*" | sed 's/pid=//' | sort -u)
COUNT=$(echo "$PIDS" | wc -l)

if [ $COUNT -eq 1 ]; then
    echo "Only one PID detected, --no-follow-forks works as expected."
    exit 0
else
    echo "Expected exactly 1 PID, got $COUNT (PIDs: $PIDS)"
    echo "$OUTPUT"
    exit 1
fi