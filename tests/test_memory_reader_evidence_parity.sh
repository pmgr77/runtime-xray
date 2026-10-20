#!/bin/sh
#
# @file    test_memory_reader_evidence_parity.sh
# @brief   Stage D.2: compare semantic evidence produced by both memory readers.
#
# Copyright 2026 Peter Magram
# Licensed under the Apache License, Version 2.0 (see LICENSE).
#
# Two workloads are traced independently with vmread and proc:
#   fork_cow_secret: inherited MAP_PRIVATE secret, parent erases its own copy.
#   exec_memory_transition: failed execve, successful execve, changed secret.
#
# This is NOT a byte-for-byte JSON comparison. PIDs, addresses, event sequence
# numbers, duplicated observations, and scan sizes may legitimately vary.
# Most importantly, RuntimeXRay creates a new random HMAC key on each run:
# comparing fingerprint STRINGS across independent reports is invalid.
# Instead, the test checks fingerprint equality/inequality WITHIN each report,
# then compares normalized secret identities, process-image attribution, and
# observed_in evidence relationships across the two readers.
#
# Exit status: 0 = PASS, 1 = FAIL, 125 = prerequisites unavailable (SKIP).
# Usage: tests/test_memory_reader_evidence_parity.sh ./build/runtimexray

set -eu

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
skip() { printf 'SKIP: %s\n' "$1" >&2; exit 125; }

[ "$#" -eq 1 ] || fail 'usage: test_memory_reader_evidence_parity.sh <runtimexray-binary>'
[ -x "$1" ] || fail "RuntimeXRay binary not executable: $1"
BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd) || fail 'cannot resolve binary path'
BIN="$BIN_DIR/$(basename -- "$1")"

for cmd in cc python3 timeout; do
    command -v "$cmd" >/dev/null 2>&1 || skip "missing dependency: $cmd"
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FORK_SOURCE="$SCRIPT_DIR/dynamic_analysis/fork_cow_secret.c"
EXEC_SOURCE="$SCRIPT_DIR/dynamic_analysis/exec_memory_transition.c"
[ -f "$FORK_SOURCE" ] || fail "missing fixture: $FORK_SOURCE"
[ -f "$EXEC_SOURCE" ] || fail "missing fixture: $EXEC_SOURCE"

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

cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$FORK_SOURCE" -o "$TMP/fork_cow_secret" || fail 'fork fixture compilation failed'
cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$EXEC_SOURCE" -o "$TMP/exec_memory_transition" || fail 'exec fixture compilation failed'

# The same disposable cleartext drives BOTH exec workloads; fingerprints do
# not match across reports because the HMAC keys are independently randomized.
OLD_SECRET=$(python3 - <<'PY'
import secrets
import string
alphabet = string.ascii_letters + string.digits
print('password=' + ''.join(secrets.choice(alphabet) for _ in range(32)))
PY
) || fail 'cannot generate synthetic secret'

run_case() {
    scenario=$1
    backend=$2
    report="$TMP/$scenario.$backend.json"
    tracer_log="$TMP/$scenario.$backend.trace.log"
    readable="$TMP/$scenario.$backend.readable.json"
    fixture_log="$TMP/$scenario.$backend.fixture.log"
    fixture="$TMP/$scenario"

    trace_rc=0
    if [ "$SUDO" -eq 1 ]; then
        if [ "$scenario" = 'exec_memory_transition' ]; then
            timeout 120 sudo -n env \
                -u RXRAY_SKIP_PFN_CHECK \
                "RXRAY_MEMORY_READ_BACKEND=$backend" \
                "RXRAY_EXEC_OLD=$OLD_SECRET" \
                "$BIN" trace --backend ptrace --follow-forks --scan-memory \
                --log-level info --json "$report" --report /dev/null \
                "$fixture" >"$tracer_log" 2>&1 || trace_rc=$?
        else
            timeout 120 sudo -n env \
                -u RXRAY_SKIP_PFN_CHECK \
                -u RXRAY_EXEC_OLD \
                "RXRAY_MEMORY_READ_BACKEND=$backend" \
                "$BIN" trace --backend ptrace --follow-forks --scan-memory \
                --log-level info --json "$report" --report /dev/null \
                "$fixture" >"$tracer_log" 2>&1 || trace_rc=$?
        fi
    else
        if [ "$scenario" = 'exec_memory_transition' ]; then
            timeout 120 env \
                -u RXRAY_SKIP_PFN_CHECK \
                "RXRAY_MEMORY_READ_BACKEND=$backend" \
                "RXRAY_EXEC_OLD=$OLD_SECRET" \
                "$BIN" trace --backend ptrace --follow-forks --scan-memory \
                --log-level info --json "$report" --report /dev/null \
                "$fixture" >"$tracer_log" 2>&1 || trace_rc=$?
        else
            timeout 120 env \
                -u RXRAY_SKIP_PFN_CHECK \
                -u RXRAY_EXEC_OLD \
                "RXRAY_MEMORY_READ_BACKEND=$backend" \
                "$BIN" trace --backend ptrace --follow-forks --scan-memory \
                --log-level info --json "$report" --report /dev/null \
                "$fixture" >"$tracer_log" 2>&1 || trace_rc=$?
        fi
    fi
    [ "$trace_rc" -eq 0 ] || fail "$scenario/$backend: tracer exit code $trace_rc"

    if [ "$SUDO" -eq 1 ]; then
        sudo -n test -s "$report" || fail "$scenario/$backend: JSON report missing"
        sudo -n cat "$report" >"$readable" || fail "$scenario/$backend: cannot read report"
    else
        [ -s "$report" ] || fail "$scenario/$backend: JSON report missing"
        cp "$report" "$readable" || fail "$scenario/$backend: cannot copy report"
    fi

    # The tracer's own return code may not reflect a failing fixture.
    # Its captured stdout/stderr is stored in a separate PID-specific file.
    root_pid=$(python3 - "$readable" <<'PY'
import json
import sys
with open(sys.argv[1], encoding='utf-8') as stream:
    observations = json.load(stream)['lineage']['observations']
processes = [o for o in observations if o.get('type') == 'event'
             and o.get('syscall') == 'process']
if not processes or not isinstance(processes[0].get('pid'), int):
    raise SystemExit('FAIL: missing tracee process in JSON')
print(processes[0]['pid'])
PY
    ) || fail "$scenario/$backend: cannot identify tracee PID"

    child_output="/tmp/runtimexray_child_${root_pid}.log"
    if [ "$SUDO" -eq 1 ]; then
        sudo -n cat "$child_output" >"$fixture_log" || \
            fail "$scenario/$backend: cannot read captured fixture output"
    else
        cat "$child_output" >"$fixture_log" || \
            fail "$scenario/$backend: cannot read captured fixture output"
    fi

    case "$scenario" in
        fork_cow_secret)
            grep -Fq 'PASS: child retained private secret after parent erased its copy' \
                "$fixture_log" || fail "$scenario/$backend: fixture did not pass" ;;
        exec_memory_transition)
            grep -Fq 'PASS: failed exec preserved old image; successful exec replaced environment' \
                "$fixture_log" || fail "$scenario/$backend: fixture did not pass" ;;
    esac
    if grep -Fq 'FAIL:' "$fixture_log"; then
        fail "$scenario/$backend: fixture reported failure"
    fi
}

for scenario in fork_cow_secret exec_memory_transition; do
    for backend in vmread proc; do
        run_case "$scenario" "$backend"
    done
done
unset OLD_SECRET

python3 - "$TMP" <<'PY'
import json
from pathlib import Path
import re
import sys

base = Path(sys.argv[1])
scan_re = re.compile(
    r'Runtime memory scan:\s+TGID=(\d+)\s+instance=(\d+)\s+'
    r'generation=(\d+)\s+reason=(\w+)\s+pages=(\d+)\s+observations=(\d+)'
)


def require(condition, description):
    if not condition:
        raise SystemExit('FAIL: ' + description)


def load(scenario, backend):
    name = f'{scenario}.{backend}'
    report = json.loads((base / f'{name}.readable.json').read_text(encoding='utf-8'))
    log = (base / f'{name}.trace.log').read_text(encoding='utf-8', errors='replace')
    observations = report.get('lineage', {}).get('observations')
    edges = report.get('lineage', {}).get('edges')
    require(isinstance(observations, list) and isinstance(edges, list),
            f'{name}: malformed lineage graph')
    scans = [dict(tgid=int(tgid), instance=int(instance), generation=int(generation),
                  reason=reason, pages=int(pages))
             for tgid, instance, generation, reason, pages, _ in scan_re.findall(log)]
    return observations, edges, scans


def inspection(scans, process, generation, label):
    selected = [s for s in scans if s['tgid'] == process['tgid']
                and s['instance'] == process['process_instance_id']
                and s['generation'] == generation
                and s['reason'] == 'InitialInspection']
    require(len(selected) == 1, f'{label}: expected one InitialInspection')
    require(0 < selected[0]['pages'] <= 1000,
            f'{label}: InitialInspection violates page budget')


def processes_of(observations):
    return [o for o in observations if o.get('type') == 'event'
            and o.get('syscall') == 'process']


def linked(parent, data, edges):
    return any(e.get('relation') == 'observed_in'
               and e.get('from_seq') == parent.get('seq')
               and e.get('to_seq') == data.get('seq') for e in edges)


def memory_secret(observations, process, generation):
    return [o for o in observations if o.get('type') == 'data'
            and o.get('source') == 'memory'
            and o.get('data_type') == 'memory'
            and o.get('secret_type') == 'password'
            and o.get('size') == 32
            and str(o.get('fingerprint', '')).startswith('hmac-sha256:')
            and o.get('process_instance_id') == process['process_instance_id']
            and o.get('exec_generation') == generation]


def check_fork(backend):
    obs, edges, scans = load('fork_cow_secret', backend)
    p = processes_of(obs)
    require(len(p) == 2, f'fork/{backend}: expected parent + child process')
    by_seq = {node['seq']: node for node in p}
    child_links = [e for e in edges if e.get('relation') == 'causality'
                   and e.get('details') == 'kernel task creation'
                   and e.get('from_seq') in by_seq and e.get('to_seq') in by_seq]
    require(len(child_links) == 1, f'fork/{backend}: expected one task-creation edge')
    parent = by_seq[child_links[0]['from_seq']]
    child = by_seq[child_links[0]['to_seq']]
    require(parent['process_instance_id'] != child['process_instance_id'],
            f'fork/{backend}: child reused parent instance ID')
    require(child.get('exec_generation') == 0,
            f'fork/{backend}: fork unexpectedly advanced generation')
    inspection(scans, child, 0, f'fork/{backend}/child')

    memory = memory_secret(obs, child, 0)
    require(memory, f"fork/{backend}: child private password not observed")
    require(any(linked(child, m, edges) for m in memory),
            f'fork/{backend}: missing child observed_in memory edge')
    child_syscalls = {o.get('syscall') for o in obs
                      if o.get('type') == 'event'
                      and o.get('process_instance_id') == child['process_instance_id']}
    require(not child_syscalls.intersection({'read', 'recvfrom', 'sendto'}),
            f'fork/{backend}: child unexpectedly read/received/sent secret')
    require(not any(e.get('relation') == 'dataflow' for e in edges),
            f'fork/{backend}: invented DataFlow in memory-only fixture')

    # Normalize the meaningful identity/relationship, not the random HMAC,
    # PID, address, observation count, or sequence number.
    return (
        ('task_creation', 'parent', 'child'),
        ('child_image', 0),
        ('secret', 'child', 'memory', 'password', 32),
        ('relationship', 'child', 'observed_in', 'memory'),
        ('inbound_or_network', False),
        ('dataflow', False),
    )


def check_exec(backend):
    obs, edges, scans = load('exec_memory_transition', backend)
    p = processes_of(obs)
    require(len(p) == 1, f'exec/{backend}: expected one process instance')
    process = p[0]
    instance = process['process_instance_id']
    events = [o for o in obs if o.get('type') == 'event'
              and o.get('process_instance_id') == instance
              and o.get('syscall') != 'process']
    require({o.get('exec_generation') for o in events} == {0, 1},
            f'exec/{backend}: missing before/after exec generations')
    failed = [o for o in events if o.get('syscall') == 'execve'
              and o.get('exec_generation') == 0 and o.get('return_value') == -2]
    require(len(failed) == 1, f'exec/{backend}: missing failed execve ENOENT')
    require(any(o.get('syscall') == 'getpid' and o.get('exec_generation') == 1
                for o in events), f'exec/{backend}: missing post-exec getpid')

    for generation in (0, 1):
        inspection(scans, process, generation, f'exec/{backend}/gen{generation}')

    env = {}
    memories = {}
    for generation in (0, 1):
        candidates = [o for o in obs if o.get('type') == 'data'
                      and o.get('source') == 'environment'
                      and o.get('secret_type') == 'password'
                      and o.get('size') == 32
                      and o.get('process_instance_id') == instance
                      and o.get('exec_generation') == generation
                      and str(o.get('fingerprint', '')).startswith('hmac-sha256:')]
        # Multiple scans may legitimately emit repeated environment evidence.
        # There must be exactly one DISTINCT secret fingerprint, not exactly
        # one observation. This retains the identity assertion without making
        # the test depend on the number of scans or duplicate observations.
        fingerprints = {o['fingerprint'] for o in candidates}
        require(len(fingerprints) == 1,
                f'exec/{backend}: expected one distinct environment password '
                f'in gen{generation}, got {len(fingerprints)} distinct '
                f'fingerprints across {len(candidates)} observations')
        env[generation] = candidates[0]
        memories[generation] = [o for o in memory_secret(obs, process, generation)
                                if o.get('fingerprint') == env[generation]['fingerprint']]
        require(memories[generation],
                f'exec/{backend}: gen{generation} secret not found in memory')
        require(any(linked(process, m, edges) for m in memories[generation]),
                f'exec/{backend}: gen{generation} memory lacks observed_in edge')

    require(env[0]['fingerprint'] != env[1]['fingerprint'],
            f'exec/{backend}: old/new passwords have same fingerprint')
    require(not any(o.get('type') == 'data' and o.get('exec_generation') == 1
                    and o.get('process_instance_id') == instance
                    and o.get('fingerprint') == env[0]['fingerprint'] for o in obs),
            f'exec/{backend}: old password wrongly attributed to generation 1')
    # execve may involve unrelated loader/file activity. Reject DataFlow
    # connecting observations of either synthetic secret, not all edges.
    secret_fps = {env[0]['fingerprint'], env[1]['fingerprint']}
    secret_seqs = {o.get('seq') for o in obs
                   if o.get('fingerprint') in secret_fps}
    require(not any(e.get('relation') == 'dataflow'
                    and (e.get('from_seq') in secret_seqs
                         or e.get('to_seq') in secret_seqs)
                    for e in edges),
            f'exec/{backend}: invented synthetic-secret DataFlow')

    return (
        ('single_instance', True),
        ('generations', 0, 1),
        ('failed_execve', 'ENOENT', 0),
        ('successful_execve', 'new_image', 1),
        ('secret', 0, 'password', 32, 'environment+memory'),
        ('secret', 1, 'password', 32, 'environment+memory'),
        ('secret_distinct_across_generations', True),
        ('relationship', 0, 'observed_in', 'memory'),
        ('relationship', 1, 'observed_in', 'memory'),
        ('old_secret_in_new_image', False),
        ('dataflow', False),
    )


fork_vm = check_fork('vmread')
fork_proc = check_fork('proc')
require(fork_vm == fork_proc, 'fork: semantic evidence mismatch across backends')
print('PASS: fork evidence parity (child password, observed_in, instance separation)')

exec_vm = check_exec('vmread')
exec_proc = check_exec('proc')
require(exec_vm == exec_proc, 'exec: semantic evidence mismatch across backends')
print('PASS: exec evidence parity (two generations, old/new secret isolation)')

print('PASS: both backends use bounded InitialInspection')
print('PASS: no invented secret DataFlow in either scenario')
print('PASS: Stage D.2 memory reader evidence parity')
PY
