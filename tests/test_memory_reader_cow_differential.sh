#!/bin/sh
#
# @file    test_memory_reader_cow_differential.sh
# @brief   Stage D: negative control for vmread; positive control for proc.
#
# Copyright 2026 Peter Magram
# Licensed under the Apache License, Version 2.0 (see LICENSE).
#
# The exit status of the RuntimeXRay CLI is NOT sufficient: the tracer may
# return zero even when the traced fixture exits with an assertion failure.
# Inspect the tracee's captured output AND the JSON process graph instead.
#
# Expected on kernels exhibiting read-only FOLL_PIN COW unsharing:
#   vmread: first forked COW page is already unshared before application write.
#           The fixture fails its strict PFN assertion (EXPECTED NEGATIVE).
#   proc:   both fork scenarios pass their strict physical-PFN assertions.
#           No early COW unsharing (EXPECTED POSITIVE).
#
# Exit status: 0 both controls behaved as expected; 1 regression;
#              125 prerequisites unavailable (including readable real PFNs).
#
# Usage: tests/test_memory_reader_cow_differential.sh ./build/runtimexray
#
set -eu

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
skip() { printf 'SKIP: %s\n' "$1" >&2; exit 125; }

[ "$#" -eq 1 ] || fail 'usage: test_memory_reader_cow_differential.sh <runtimexray-binary>'
[ -x "$1" ] || fail "RuntimeXRay binary is not executable: $1"

BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd) || fail 'cannot resolve binary directory'
BIN="$BIN_DIR/$(basename -- "$1")"

for cmd in cc python3 timeout; do
    command -v "$cmd" >/dev/null 2>&1 || skip "missing dependency: $cmd"
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE="$SCRIPT_DIR/dynamic_analysis/fork_cow_mutation.c"
[ -f "$SOURCE" ] || fail "fixture missing: $SOURCE"

SUDO=0
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || skip 'sudo unavailable'
    sudo -n true >/dev/null 2>&1 || skip 'root or passwordless sudo required'
    SUDO=1
fi

TMP=$(mktemp -d) || fail 'cannot create temporary directory'
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

FIXTURE="$TMP/fork_cow_mutation"
cc -std=c11 -O2 -Wall -Wextra -Werror "$SOURCE" -o "$FIXTURE" ||
    fail 'fixture compilation failed'

# Do not accept a masked PFN as positive evidence that COW is preserved.
# First establish the kernel/permission baseline *without* RuntimeXRay.
if [ "$SUDO" -eq 1 ]; then
    sudo -n env -u RXRAY_SKIP_PFN_CHECK "$FIXTURE" >"$TMP/baseline.log" 2>&1 ||
        fail 'untraced COW fixture failed its baseline physical-page assertions'
else
    env -u RXRAY_SKIP_PFN_CHECK "$FIXTURE" >"$TMP/baseline.log" 2>&1 ||
        fail 'untraced COW fixture failed its baseline physical-page assertions'
fi

if grep -Fq 'SKIP: physical PFN identity check' "$TMP/baseline.log"; then
    skip 'real PFNs masked or inaccessible; this test requires readable pagemap PFNs'
fi
grep -Fq 'PASS: physical PFN shared after reads; PFNs diverged after first COW write' \
    "$TMP/baseline.log" || fail 'baseline did not verify physical COW behavior'

# Every run is a new traced process and a new isolated JSON report.
# Select the memory reader explicitly via CLI.
# Remove PFN-bypass flags in both privileged and unprivileged runs.
run_backend() {
    mode="$1"
    report="$TMP/$mode.json"
    tracer_log="$TMP/$mode.tracer.log"
    trace_rc=0

    if [ "$SUDO" -eq 1 ]; then
        timeout 120 sudo -n env \
            -u RXRAY_SKIP_PFN_CHECK \
            "$BIN" trace \
            --memory-reader "$mode" \
            --backend ptrace --follow-forks --scan-memory \
            --log-level info --json "$report" --report /dev/null \
            "$FIXTURE" >"$tracer_log" 2>&1 || trace_rc=$?
    else
        timeout 120 env \
            -u RXRAY_SKIP_PFN_CHECK \
            "$BIN" trace \
            --memory-reader "$mode" \
            --backend ptrace --follow-forks --scan-memory \
            --log-level info --json "$report" --report /dev/null \
            "$FIXTURE" >"$tracer_log" 2>&1 || trace_rc=$?
    fi

    case "$trace_rc" in
        124|137) fail "$mode: trace timed out or was killed ($trace_rc)" ;;
    esac

    if [ "$SUDO" -eq 1 ]; then
        sudo -n test -s "$report" || fail "$mode: JSON report missing; tracer status=$trace_rc"
        sudo -n cat "$report" >"$TMP/$mode.readable.json" ||
            fail "$mode: cannot read JSON report"
    else
        [ -s "$report" ] || fail "$mode: JSON report missing; tracer status=$trace_rc"
        cp "$report" "$TMP/$mode.readable.json" || fail "$mode: cannot copy JSON report"
    fi

    # Locate the tracee stdout/stderr from the root *process* node, not
    # RuntimeXRay stdout. The latter does not contain the fixture's PFN proof.
    root_pid=$(python3 - "$TMP/$mode.readable.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding='utf-8') as f:
    observations = json.load(f)['lineage']['observations']
processes = [o for o in observations if o.get('syscall') == 'process']
if not processes:
    raise SystemExit('FAIL: no process node in JSON')
print(processes[0]['pid'])
PY
    ) || fail "$mode: cannot identify root tracee process"

    captured="/tmp/runtimexray_child_${root_pid}.log"
    if [ "$SUDO" -eq 1 ]; then
        sudo -n cat "$captured" >"$TMP/$mode.fixture.log" ||
            fail "$mode: cannot read tracee output: $captured"
    else
        cat "$captured" >"$TMP/$mode.fixture.log" ||
            fail "$mode: cannot read tracee output: $captured"
    fi
}

run_backend vmread
run_backend proc

python3 - "$TMP" <<'PY'
import json
from pathlib import Path
import re
import sys

base = Path(sys.argv[1])


def require(condition, message):
    if not condition:
        raise SystemExit('FAIL: ' + message)


def load(mode):
    report = json.loads((base / (mode + '.readable.json')).read_text(encoding='utf-8'))
    tracer = (base / (mode + '.tracer.log')).read_text(encoding='utf-8', errors='replace')
    fixture = (base / (mode + '.fixture.log')).read_text(encoding='utf-8', errors='replace')
    observations = report['lineage']['observations']
    processes = [o for o in observations if o.get('syscall') == 'process']
    instances = [p.get('process_instance_id') for p in processes]
    require(len(set(instances)) == len(instances), f'{mode}: duplicate process-instance IDs')
    return report, tracer, fixture, processes


vm_report, vm_trace, vm_output, vm_processes = load('vmread')
proc_report, proc_trace, proc_output, proc_processes = load('proc')

# Important: the NEGATIVE CONTROL passes only if the specific, expected PFN
# assertion fails. Unrelated fixture/tracer failures are not accepted.
require('FAIL: physical PFN relationship unexpected (before first write)' in vm_output,
        'vmread: expected an early PFN split, but fixture did not report one')
require('PASS: parent-first COW preserves' not in vm_output,
        'vmread: unexpectedly completed first COW case')
require(len(vm_processes) == 2,
        f'vmread: expected parent + first child before fixture abort; got {len(vm_processes)}')

# The POSITIVE CONTROL must complete both COW orders with strict PFN checks.
for line in (
    "PASS: parent-first COW preserves child's original, then isolates both edits",
    "PASS: child-first COW preserves parent's original, then isolates both edits",
    'PASS: physical PFN shared after reads; PFNs diverged after first COW write',
):
    require(line in proc_output, f'proc: missing expected fixture result: {line}')
require('FAIL:' not in proc_output and 'SKIP: physical PFN' not in proc_output,
        'proc: physical COW checks failed or were skipped')
require(len(proc_processes) == 3,
        f'proc: expected parent + two children, got {len(proc_processes)}')

# Ensure the expected work actually occurred under each backend.
scan_pattern = re.compile(
    r'Runtime memory scan:\s+TGID=(\d+)\s+instance=(\d+)\s+'
    r'generation=(\d+)\s+reason=(\w+)\s+pages=(\d+)\s+observations=(\d+)'
)
for mode, tracer, processes in (
    ('vmread', vm_trace, vm_processes),
    ('proc', proc_trace, proc_processes),
):
    scans = [
        (int(tgid), int(instance), int(gen), reason, int(pages))
        for tgid, instance, gen, reason, pages, _ in scan_pattern.findall(tracer)
    ]
    for child in processes[1:]:
        relevant = [s for s in scans if s[0] == child['tgid']
                    and s[1] == child['process_instance_id']
                    and s[2] == 0 and s[3] == 'InitialInspection']
        require(len(relevant) == 1 and 0 < relevant[0][4] <= 1000,
                f'{mode}: child {child["tgid"]} did not receive a bounded InitialInspection')

# Assert stronger PFN diagnostics if the locally instrumented fixture emits
# PFN_CHECK lines; the upstream fixture's specific FAIL/PASS strings suffice
# otherwise. This keeps the test independent of optional debug logging.
if 'PFN_CHECK stage=before_write' in vm_output:
    require(any('equal=0' in line for line in vm_output.splitlines()
                if line.startswith('PFN_CHECK stage=before_write')),
            'vmread: expected equal=0 before first write')
if 'PFN_CHECK stage=before_write' in proc_output:
    before = [line for line in proc_output.splitlines()
              if line.startswith('PFN_CHECK stage=before_write')]
    after = [line for line in proc_output.splitlines()
             if line.startswith('PFN_CHECK stage=after_first_write')]
    require(len(before) == 2 and all('equal=1' in line for line in before),
            'proc: expected two shared PFN observations before writes')
    require(len(after) == 2 and all('equal=0' in line for line in after),
            'proc: expected two distinct PFN observations after first writes')

print('PASS: baseline COW PFN behavior verified without RuntimeXRay')
print('PASS: vmread caused early COW PFN unsharing (expected negative control)')
print('PASS: proc preserved shared PFNs until application write, in both orders')
print('PASS: both backends performed bounded child InitialInspection scans')
print('PASS: Stage D differential COW regression')
PY
