#!/bin/sh
# Smoke test for eBPF backend.
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
    echo "Skipping eBPF smoke JSON test: root or passwordless sudo required."
    exit 125
fi

# Check if eBPF tracepoint is accessible
if ! $RUN_PREFIX cat /sys/kernel/tracing/available_filter_functions >/dev/null 2>&1; then
    echo "Skipping eBPF test: tracing filesystem not accessible."
    exit 125
fi

# Run the trace with eBPF backend for a short time on /bin/ls
output=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --backend ebpf --timeout 1 /bin/ls 2>&1)
status=$?
if [ $status -ne 0 ]; then
    echo "eBPF backend failed with status $status"
    echo "$output"
    exit 1
fi

# Check that we got some syscall output
if echo "$output" | grep -q "syscall"; then
    exit 0
else
    echo "No syscall output detected from eBPF backend"
    echo "$output"
    exit 1
fi