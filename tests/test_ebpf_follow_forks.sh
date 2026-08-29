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

OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --backend ebpf --follow-forks --log-level debug --timeout 5 "$FORK_TEST_BIN" 2>&1)
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "eBPF trace failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Extract PIDs from debug logs:
# - Parent PID from execve entry: "syscall=221 name=execve is_entry=1 ret=0" (then later ret=0, but we need the actual PID)
#   Actually, the parent PID is not in that line; it's in the "execve exit" line with ret=0? No, ret=0 is the return value.
#   Better: use the getpid syscall: "handle_fork_event: syscall=172 name=getpid is_entry=0 ret=291563" -> ret is the PID.
#   Or use the clone exit: "handle_fork_event: syscall=220 name=clone is_entry=0 ret=291564" -> ret is the child PID.
# Extract all ret values from getpid exit and clone exit, and also from other syscalls that return PID? Simpler: use the parent's getpid exit.
# We'll extract any number that appears after "ret=" in lines that contain "getpid" or "clone" and is_entry=0.

PIDS=$(echo "$OUTPUT" | grep -E "handle_fork_event: syscall=(172|220) name=(getpid|clone) is_entry=0" | grep -o "ret=[0-9]*" | sed 's/ret=//' | sort -u)
COUNT=$(echo "$PIDS" | wc -l)

if [ $COUNT -ge 2 ]; then
    echo "Found $COUNT distinct PIDs, eBPF fork tracing works."
    exit 0
else
    echo "Expected at least 2 PIDs, got $COUNT"
    echo "$OUTPUT"
    exit 1
fi