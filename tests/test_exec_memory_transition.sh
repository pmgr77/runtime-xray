#!/bin/sh
#
# @file    test_exec_memory_transition.sh
# @brief   Stage C.2 regression: memory evidence across failed/successful execve.
#
# Copyright 2026 Peter Magram
# Licensed under the Apache License, Version 2.0 (see LICENSE).
#
# Expected fixture behavior:
#   - generation 0 contains a synthetic old password;
#   - failed execve(ENOENT) leaves generation 0 unchanged;
#   - successful execve replaces the image, preserving the process instance;
#   - generation 1 contains a different synthetic password, not the old one.
#
# The report is inspected without printing raw passwords or fingerprints.
# Exit: 0 PASS; 1 FAIL; 125 SKIP (missing test requirements).

set -eu

fail() { echo "FAIL: $1" >&2; exit 1; }
skip() { echo "SKIP: $1" >&2; exit 125; }

[ "$#" -eq 1 ] || skip "usage: $0 <runtimexray-binary>"
case "$1" in
    /*) BIN="$1" ;;
    *)  BIN="$(pwd)/$1" ;;
esac
[ -x "$BIN" ] || fail "RuntimeXRay binary is not executable"

for tool in cc python3 timeout; do
    command -v "$tool" >/dev/null 2>&1 || skip "$tool is required"
done

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SOURCE="$SCRIPT_DIR/dynamic_analysis/exec_memory_transition.c"
[ -f "$SOURCE" ] || fail "fixture source is missing: $SOURCE"

RUN_WITH_SUDO=0
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || skip "sudo is unavailable"
    sudo -n true >/dev/null 2>&1 || skip "root or passwordless sudo required"
    RUN_WITH_SUDO=1
fi

TEST_DIR="$(mktemp -d)" || fail "cannot create test directory"
cleanup() { rm -rf -- "$TEST_DIR"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

FIXTURE="$TEST_DIR/exec_memory_transition"
REPORT="$TEST_DIR/report.json"
LOG="$TEST_DIR/trace.log"

cc -std=c11 -O2 -Wall -Wextra -Werror "$SOURCE" -o "$FIXTURE" ||
    fail "cannot compile exec memory transition fixture"

# Generate a disposable password. The replacement image deterministically
# rotates it; both values remain confined to this test run.
OLD_VALUE="$(python3 - <<'PY'
import secrets
import string
alphabet = string.ascii_letters + string.digits
print('password=' + ''.join(secrets.choice(alphabet) for _ in range(32)))
PY
)" || fail "cannot generate disposable password"

# Exercise the fixture independently before tracing. This output contains
# no credentials and confirms the OS transition is valid on this machine.
if ! RXRAY_EXEC_OLD="$OLD_VALUE" "$FIXTURE" >"$TEST_DIR/fixture.log" 2>&1; then
    fail "fixture did not complete its failed/successful exec sequence"
fi
if ! grep -q '^PASS: failed exec preserved old image;' "$TEST_DIR/fixture.log"; then
    fail "fixture did not confirm the intended exec behavior"
fi

set -- "$BIN" trace \
    --backend ptrace \
    --follow-forks \
    --scan-memory \
    --log-level info \
    --json "$REPORT" \
    --report /dev/null \
    "$FIXTURE"

TRACE_RC=0
if [ "$RUN_WITH_SUDO" -eq 1 ]; then
    timeout 120 sudo -n env "HOME=$HOME" "RXRAY_EXEC_OLD=$OLD_VALUE" \
        "$@" >"$LOG" 2>&1 || TRACE_RC=$?
else
    RXRAY_EXEC_OLD="$OLD_VALUE" timeout 120 \
        "$@" >"$LOG" 2>&1 || TRACE_RC=$?
fi
unset OLD_VALUE

if [ "$TRACE_RC" -ne 0 ]; then
    grep -E '^(FAIL|Error|ERROR|FATAL|SKIP)' "$LOG" >&2 || true
    fail "RuntimeXRay returned exit code $TRACE_RC"
fi
[ -s "$REPORT" ] || fail "RuntimeXRay did not produce a JSON report"

if [ "$RUN_WITH_SUDO" -eq 1 ]; then
    sudo -n chown "$(id -u):$(id -g)" "$REPORT" ||
        fail "cannot make privileged report readable"
fi

python3 - "$REPORT" "$LOG" <<'PY'
import json
import pathlib
import re
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
log = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8', errors='replace')


def require(condition, message):
    if not condition:
        raise SystemExit('FAIL: ' + message)


lineage = report.get('lineage', {})
obs = lineage.get('observations', [])
edges = lineage.get('edges', [])
require(isinstance(obs, list) and obs, 'missing lineage observations')
require(isinstance(edges, list), 'missing lineage edges')

processes = [o for o in obs if o.get('type') == 'event'
             and o.get('syscall') == 'process']
require(len(processes) == 1,
        f'expected exactly one process node, got {len(processes)}')
process = processes[0]
instance = process.get('process_instance_id')
tgid = process.get('tgid')
require(isinstance(instance, int) and instance > 0, 'invalid process instance')
require(isinstance(tgid, int) and tgid > 0, 'invalid process TGID')

# A failed exec must stay in generation 0. A successful exec must advance
# to generation 1 without creating a new process instance.
image_events = [o for o in obs if o.get('type') == 'event'
                and o.get('process_instance_id') == instance
                and o.get('syscall') != 'process']
require(image_events, 'no syscall events recorded')
require(all(o.get('process_instance_id') == instance for o in obs),
        'observations unexpectedly belong to another process instance')
require(all(o.get('tgid') == tgid for o in image_events),
        'syscall events unexpectedly changed TGID')

generations = {o.get('exec_generation') for o in image_events}
require(generations == {0, 1},
        f'expected syscall generations 0 and 1, got {generations}')

exec_events = [o for o in image_events if o.get('syscall') == 'execve']
failed = [o for o in exec_events if o.get('exec_generation') == 0
          and isinstance(o.get('return_value'), int)
          and o['return_value'] < 0]
require(len(failed) == 1,
        f'expected one failed execve in generation 0, got {len(failed)}')
require(failed[0]['return_value'] == -2,
        'failed execve did not return ENOENT (-2)')

successful_attempts = [o for o in exec_events
                       if o.get('exec_generation') == 0
                       and o.get('seq', 0) > failed[0].get('seq', 0)]
require(successful_attempts,
        'second (successful) execve invocation not present in generation 0')

pre_getpids = [o for o in image_events if o.get('syscall') == 'getpid'
               and o.get('exec_generation') == 0
               and failed[0]['seq'] < o.get('seq', 0)
               < successful_attempts[0]['seq']]
post_getpids = [o for o in image_events if o.get('syscall') == 'getpid'
                and o.get('exec_generation') == 1]
require(pre_getpids, 'no generation-0 getpid after failed execve')
require(post_getpids, 'no generation-1 getpid after successful execve')

# Each executable generation gets one distinct bounded InitialInspection.
scan_pattern = re.compile(
    r'Runtime memory scan:\s+'
    r'TGID=(\d+)\s+instance=(\d+)\s+generation=(\d+)\s+'
    r'reason=(\w+)\s+pages=(\d+)\s+observations=(\d+)'
)
scans = [dict(tgid=int(m[0]), instance=int(m[1]), generation=int(m[2]),
              reason=m[3], pages=int(m[4]), observations=int(m[5]))
         for m in scan_pattern.findall(log)]
for generation in (0, 1):
    matched = [s for s in scans if s['tgid'] == tgid
               and s['instance'] == instance
               and s['generation'] == generation
               and s['reason'] == 'InitialInspection']
    require(len(matched) == 1,
            f'expected exactly one InitialInspection in generation {generation}')
    require(0 < matched[0]['pages'] <= 1000,
            f'InitialInspection page budget violated in generation {generation}')

# Use environment observations as an independent identity oracle for each
# secret. No raw value or HMAC is printed. Other environment secrets (e.g.
# PWD) must not interfere with the test.
def env_passwords(generation):
    return [o for o in obs if o.get('type') == 'data'
            and o.get('source') == 'environment'
            and o.get('secret_type') == 'password'
            and o.get('size') == 32
            and o.get('process_instance_id') == instance
            and o.get('exec_generation') == generation
            and str(o.get('fingerprint', '')).startswith('hmac-sha256:')]

old_env = env_passwords(0)
new_env = env_passwords(1)

old_fingerprints = {o['fingerprint'] for o in old_env}
new_fingerprints = {o['fingerprint'] for o in new_env}

require(
    len(old_fingerprints) == 1,
    f'expected one unique old environment secret, '
    f'got {len(old_fingerprints)} fingerprints '
    f'from {len(old_env)} observations'
)

require(
    len(new_fingerprints) == 1,
    f'expected one unique new environment secret, '
    f'got {len(new_fingerprints)} fingerprints '
    f'from {len(new_env)} observations'
)

old_fp = next(iter(old_fingerprints))
new_fp = next(iter(new_fingerprints))

require(
    old_fp != new_fp,
    'replacement image reused the old password'
)

def memory_with_fingerprint(generation, fingerprint):
    return [o for o in obs if o.get('type') == 'data'
            and o.get('source') == 'memory'
            and o.get('process_instance_id') == instance
            and o.get('exec_generation') == generation
            and o.get('tgid') == tgid
            and o.get('fingerprint') == fingerprint]

old_memory = memory_with_fingerprint(0, old_fp)
new_memory = memory_with_fingerprint(1, new_fp)
require(old_memory, 'old password missing from generation-0 memory')
require(new_memory, 'new password missing from generation-1 memory')

# The old password must not be misattributed to the replacement image,
# regardless of the observation source.
leaked_old = [o for o in obs if o.get('type') == 'data'
              and o.get('process_instance_id') == instance
              and o.get('exec_generation') == 1
              and o.get('fingerprint') == old_fp]
require(not leaked_old, 'old password incorrectly observed in generation 1')

# Memory observations in both generations should belong to this process
# node via explicit evidence, not merely be present in a flat list.
for generation, memories in ((0, old_memory), (1, new_memory)):
    require(any(any(e.get('relation') == 'observed_in'
                    and e.get('from_seq') == process.get('seq')
                    and e.get('to_seq') == m.get('seq')
                    for e in edges) for m in memories),
            f'no observed_in edge for generation-{generation} memory')

print('PASS: failed execve preserved generation 0 (ENOENT)')
print('PASS: successful execve advanced the same process instance to generation 1')
print('PASS: exactly one bounded InitialInspection per executable generation')
print('PASS: old and new passwords observed in their respective image memory')
print('PASS: no old password evidence attributed to generation 1')
print('PASS: both memory observations have observed_in lineage edges')
PY
