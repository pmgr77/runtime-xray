#!/bin/sh
# Test eBPF backend fork-following

set -e

RUNTIMEXRAY_BIN="$1"
FORK_TEST_BIN="$2"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$FORK_TEST_BIN" ]; then
    echo "Usage: $0 <runtimexray> <fork_test>"
    exit 125
fi

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
        echo "Skipping eBPF follow-forks test: root or passwordless sudo required."
        exit 125
    fi
    RUN_PREFIX="sudo -n"
else
    RUN_PREFIX=""
fi

OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --backend ebpf --follow-forks --timeout 5 "$FORK_TEST_BIN" 2>&1)
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "eBPF trace failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

PIDS=$(echo "$OUTPUT" | grep -o "pid=[0-9]*" | sed 's/pid=//' | sort -u)
COUNT=$(echo "$PIDS" | wc -l)

if [ $COUNT -ge 2 ]; then
    echo "Found $COUNT distinct PIDs, eBPF fork tracing works."
    exit 0
else
    echo "Expected at least 2 PIDs, got $COUNT"
    echo "$OUTPUT"
    exit 1
fi