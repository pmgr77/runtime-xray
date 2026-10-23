#!/bin/sh
# Stage D.5: verify CLI parsing and actual memory-reader syscalls.
# Usage: tests/test_memory_reader_cli.sh ./build/runtimexray
# Exit: 0 PASS, 1 FAIL, 125 SKIP (missing tracing prerequisites).

set -eu

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
skip() { printf 'SKIP: %s\n' "$1" >&2; exit 125; }

[ "$#" -eq 1 ] || fail 'usage: test_memory_reader_cli.sh <runtimexray-binary>'
[ -x "$1" ] || fail "binary is not executable: $1"

BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd) || fail 'cannot resolve binary directory'
BIN="$BIN_DIR/$(basename -- "$1")"

TMP=$(mktemp -d) || fail 'cannot create temporary directory'
TARGET_JOB=''
cleanup() {
    if [ -n "$TARGET_JOB" ]; then
        kill "$TARGET_JOB" 2>/dev/null || true
        wait "$TARGET_JOB" 2>/dev/null || true
    fi
    rm -rf -- "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

expect_rejection() {
    label=$1
    shift
    if "$BIN" "$@" >"$TMP/rejected.log" 2>&1; then
        fail "$label: invalid CLI unexpectedly succeeded"
    fi
    grep -Fq 'memory-reader' "$TMP/rejected.log" ||
        fail "$label: rejection did not identify --memory-reader"
}

# Validate errors for both independent commands, including equals syntax.
expect_rejection 'mem invalid value' mem --memory-reader=bogus 1
expect_rejection 'trace invalid value' trace --memory-reader bogus /bin/true
expect_rejection 'mem missing value' mem --memory-reader
expect_rejection 'trace missing value' trace --memory-reader
printf 'PASS: both commands reject invalid and missing reader values\n'

command -v strace >/dev/null 2>&1 || skip 'strace is required for syscall-level verification'
command -v python3 >/dev/null 2>&1 || skip 'python3 is required for the mem fixture'
[ -x /bin/sleep ] || skip '/bin/sleep is unavailable'

# Avoid ptrace-following the tracee itself: strace observes only RuntimeXRay.
if ! strace -qq -o "$TMP/strace.probe" -e trace=process_vm_readv \
        /bin/true >/dev/null 2>&1; then
    skip 'strace cannot trace a child in this environment'
fi

# Linux Yama usually blocks sibling-process inspection. Give the disposable
# fixture explicit permission to be inspected by RuntimeXRay's mem command.
python3 -u -c '
import ctypes
import os
import sys
import time

libc = ctypes.CDLL(None, use_errno=True)
PR_SET_PTRACER = 0x59616d61
if libc.prctl(PR_SET_PTRACER, ctypes.c_ulong(-1), 0, 0, 0) != 0:
    sys.exit(125)
secret = ctypes.create_string_buffer(b"password=StageD5ReaderProbe123456")
print(os.getpid(), flush=True)
time.sleep(90)
' >"$TMP/target.pid" 2>"$TMP/fixture.err" &
TARGET_JOB=$!

i=0
while [ ! -s "$TMP/target.pid" ] && [ "$i" -lt 50 ]; do
    kill -0 "$TARGET_JOB" 2>/dev/null || skip 'mem target exited during setup'
    sleep 0.1
    i=$((i + 1))
done
[ -s "$TMP/target.pid" ] || skip 'mem target did not start'
TARGET_PID=$(sed -n '1p' "$TMP/target.pid")
case "$TARGET_PID" in
    ''|*[!0-9]*) fail 'fixture returned an invalid pid' ;;
esac

assert_reader_syscalls() {
    log=$1
    label=$2
    mode=$3
    case "$mode" in
        default|proc)
            grep -Eq '"/proc/[0-9]+/mem"' "$log" ||
                fail "$label: expected an open of /proc/<pid>/mem"
            if grep -Fq 'process_vm_readv(' "$log"; then
                fail "$label: unexpected process_vm_readv()"
            fi
            ;;
        vmread)
            grep -Fq 'process_vm_readv(' "$log" ||
                fail "$label: expected process_vm_readv()"
            if grep -Eq '"/proc/[0-9]+/mem"' "$log"; then
                fail "$label: unexpected /proc/<pid>/mem open"
            fi
            ;;
    esac
}

run_mem() {
    mode=$1
    log="$TMP/mem.$mode.strace"
    if [ "$mode" = default ]; then
        strace -qq -o "$log" -e trace=openat,pread64,process_vm_readv \
            "$BIN" mem --max-pages 64 --report /dev/null "$TARGET_PID" \
            >"$TMP/mem.$mode.output" 2>&1 || fail "mem/$mode: command failed"
    else
        strace -qq -o "$log" -e trace=openat,pread64,process_vm_readv \
            "$BIN" mem --memory-reader "$mode" --max-pages 64 \
            --report /dev/null "$TARGET_PID" \
            >"$TMP/mem.$mode.output" 2>&1 || fail "mem/$mode: command failed"
    fi
    assert_reader_syscalls "$log" "mem/$mode" "$mode"
}

run_trace() {
    mode=$1
    log="$TMP/trace.$mode.strace"
    if [ "$mode" = default ]; then
        strace -qq -o "$log" -e trace=openat,pread64,process_vm_readv \
            "$BIN" trace --backend ptrace --scan-memory \
            --report /dev/null /bin/sleep 1 \
            >"$TMP/trace.$mode.output" 2>&1 || fail "trace/$mode: command failed"
    else
        strace -qq -o "$log" -e trace=openat,pread64,process_vm_readv \
            "$BIN" trace --memory-reader "$mode" --backend ptrace \
            --scan-memory --report /dev/null /bin/sleep 1 \
            >"$TMP/trace.$mode.output" 2>&1 || fail "trace/$mode: command failed"
    fi
    assert_reader_syscalls "$log" "trace/$mode" "$mode"
}

for mode in default proc vmread; do
    run_mem "$mode"
    run_trace "$mode"
    printf 'PASS: %s selects the expected memory reader for mem and trace\n' "$mode"
done

printf 'PASS: Stage D.5 memory reader CLI regression\n'
