
#!/bin/sh
#
# @file    test_f2_inherited_fd3.sh
# @brief   F2 regression: resource identity for an inherited pipe on fd=3.
#
# Copyright 2026 Peter Magram
# SPDX-License-Identifier: Apache-2.0

set -eu
umask 077

fail()
{
    echo "FAIL: $1" >&2
    exit 1
}

skip()
{
    echo "SKIP: $1" >&2
    exit 125
}

[ "$#" -eq 1 ] || skip "usage: $0 <runtimexray-binary>"

BIN="$1"

[ -x "$BIN" ] || fail "RuntimeXRay binary not found"

for tool in bash python3 timeout; do
    command -v "$tool" >/dev/null 2>&1 ||
        skip "$tool is required"
done

if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 ||
        skip "sudo is unavailable"

    sudo -n true >/dev/null 2>&1 ||
        skip "passwordless sudo is required"
fi

TEST_DIR="$(mktemp -d)" || fail "mktemp failed"

trap 'rm -rf -- "$TEST_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

JSON="$TEST_DIR/f2.json"
REPORT="$TEST_DIR/f2-report.txt"
LOG="$TEST_DIR/f2.log"

# bash receives the pipe through stdin, duplicates it to fd=3,
# then redirects fd=0 to /dev/null.
#
# RuntimeXRay and its tracee inherit fd=3.
# The Python tracee reads fd=3 directly: no open() or dup()
# occurs inside the traced process to create that descriptor.

set -- bash -c '
    exec 3<&0
    exec 0</dev/null

    exec "$1" trace \
        --backend ptrace \
        --memory-reader proc \
        --json "$2" \
        --report "$3" \
        /usr/bin/python3 -c \
        "import os; assert os.read(3, 4096).startswith(b\"password=\")"
' f2-runner "$BIN" "$JSON" "$REPORT"

if [ "$(id -u)" -ne 0 ]; then
    set -- sudo -n "$@"
fi

RC=0

printf 'password=F2_inherited_pipe_only_2026\n' |
    timeout 120 "$@" >"$LOG" 2>&1 || RC=$?

[ "$RC" -eq 0 ] || fail "trace returned $RC"

[ -s "$JSON" ] || fail "JSON report missing"

if [ "$(id -u)" -ne 0 ]; then
    sudo -n chown "$(id -u):$(id -g)" "$JSON" "$REPORT" ||
        fail "cannot access generated reports"
fi

python3 - "$JSON" "$REPORT" "$LOG" <<'PY'
import json
import pathlib
import sys

json_path, report_path, log_path = map(pathlib.Path, sys.argv[1:])

for path in (json_path, report_path, log_path):
    if "F2_inherited_pipe_only_2026" in path.read_text(
        encoding="utf-8"
    ):
        raise SystemExit("FAIL: plaintext secret leaked")

report = json.loads(json_path.read_text(encoding="utf-8"))

reads = [
    obs
    for obs in report["lineage"]["observations"]
    if obs.get("type") == "event"
    and obs.get("syscall") == "read"
    and obs.get("args", [None])[0] == 3
    and obs.get("return_value") == 37
]

if not reads:
    raise SystemExit("FAIL: read(fd=3) observation missing")

matched = any(
    obs.get("resource_type") == "pipe"
    and obs.get("resource_role") == "read"
    and isinstance(obs.get("resource_id"), int)
    and obs["resource_id"] > 0
    and bool(obs.get("fingerprint"))
    for obs in reads
)

if not matched:
    raise SystemExit("FAIL: inherited fd=3 resource identity missing")

print("PASS: inherited pipe read(fd=3)")
print("PASS: fingerprint detected")
print("PASS: resource_type=pipe")
print("PASS: resource_role=read")
print("PASS: nonzero resource_id")
print("PASS: plaintext redaction")
print("PASS: F2 inherited FD regression")
PY
