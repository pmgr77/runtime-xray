#!/bin/sh
# Test that thread creation is traced: at least two distinct PIDs appear.

set -e

RUNTIMEXRAY_BIN="$1"
THREAD_TEST_BIN="$2"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$THREAD_TEST_BIN" ]; then
    echo "Usage: $0 <runtimexray> <thread_test>"
    exit 125
fi

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
        echo "Skipping thread test: root or passwordless sudo required."
        exit 125
    fi
    RUN_PREFIX="sudo -n"
else
    RUN_PREFIX=""
fi

OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --log-level debug --timeout 2 "$THREAD_TEST_BIN" 2>&1)
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "Trace failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Extract unique PIDs from syscall lines
PIDS=$(echo "$OUTPUT" | grep -o "pid=[0-9]*" | sed 's/pid=//' | sort -u)
COUNT=$(echo "$PIDS" | wc -l)

if [ $COUNT -ge 2 ]; then
    echo "Found $COUNT distinct PIDs, thread tracing works."
    exit 0
else
    echo "Expected at least 2 distinct PIDs, got $COUNT"
    echo "$OUTPUT"
    exit 1
fi
