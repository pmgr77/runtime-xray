#!/bin/sh
# Test eBPF backend thread tracing by checking for distinct TIDs

set -e

RUNTIMEXRAY_BIN="$1"
THREAD_TEST_BIN="$2"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$THREAD_TEST_BIN" ]; then
    echo "Usage: $0 <runtimexray> <thread_test>"
    exit 125
fi

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
        echo "Skipping eBPF thread test: root or passwordless sudo required."
        exit 125
    fi
    RUN_PREFIX="sudo -n"
else
    RUN_PREFIX=""
fi

# Run with --log-level debug to capture all syscalls (including those from child thread)
OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --backend ebpf --follow-forks --log-level debug --timeout 10 "$THREAD_TEST_BIN" 2>&1)
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "eBPF trace failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Extract TIDs from the output (format: tid=12345)
TIDS=$(echo "$OUTPUT" | grep -o "tid=[0-9]*" | sed 's/tid=//' | sort -u)
COUNT=$(echo "$TIDS" | wc -l)

if [ $COUNT -ge 2 ]; then
    echo "Found $COUNT distinct TIDs, eBPF thread tracing works."
    exit 0
else
    echo "Expected at least 2 TIDs, got $COUNT"
    echo "$OUTPUT"
    exit 1
fi
