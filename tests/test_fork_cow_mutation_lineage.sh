#!/bin/sh
#
# @file    test_fork_cow_mutation_lineage.sh
# @brief   Stage C regression: scan children in parent-first and child-first COW.
#
# Copyright 2026 Peter Magram
# Licensed under the Apache License, Version 2.0 (see LICENSE).
#
# This test distinguishes evidence obtained by RuntimeXRay from the
# physical-page evidence obtainable separately through /proc/pagemap.
# A CPU store to private memory is not a syscall: this test does NOT claim
# that RuntimeXRay observes the COW page fault or the PFN transition.
#
# Exit codes: 0 = pass, 1 = fail, 125 = unavailable prerequisites.

set -eu

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
skip() { printf 'SKIP: %s\n' "$1" >&2; exit 125; }

[ "$#" -eq 1 ] || skip 'Usage: test_fork_cow_mutation_lineage.sh <runtimexray-binary>'
case "$1" in
    /*) BIN="$1" ;;
    *) BIN="$(pwd)/$1" ;;
esac
[ -x "$BIN" ] || fail "RuntimeXRay binary is not executable: $BIN"

for command_name in cc python3 timeout; do
    command -v "$command_name" >/dev/null 2>&1 || skip "$command_name required"
done

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SOURCE="$SCRIPT_DIR/dynamic_analysis/fork_cow_mutation.c"
[ -f "$SOURCE" ] || fail "fixture missing: $SOURCE"

RUN_WITH_SUDO=0
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || skip 'sudo unavailable'
    sudo -n true >/dev/null 2>&1 || skip 'root or passwordless sudo required'
    RUN_WITH_SUDO=1
fi

TEST_DIR="$(mktemp -d)" || fail 'cannot create temporary directory'
cleanup() { rm -rf -- "$TEST_DIR"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

FIXTURE="$TEST_DIR/fork_cow_mutation"
REPORT="$TEST_DIR/report.json"
LOG="$TEST_DIR/tracer.log"

cc -std=c11 -O2 -Wall -Wextra -Werror "$SOURCE" -o "$FIXTURE" ||
    fail 'fixture compilation failed'

# The fixture itself checks that both mutation orders preserve COW isolation.
# PFN introspection is optional and is not required by this integration test.
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
    timeout 120 sudo -n env \
        "HOME=$HOME" \
        RXRAY_SKIP_PFN_CHECK=1 \
        "$@" >"$LOG" 2>&1 || TRACE_RC=$?
else
    timeout 120 env \
        RXRAY_SKIP_PFN_CHECK=1 \
        "$@" >"$LOG" 2>&1 || TRACE_RC=$?
fi

if [ "$TRACE_RC" -ne 0 ]; then
    grep -E '(^FAIL:|^Error:|^ERROR:|Runtime memory scan:)' "$LOG" >&2 || true
    fail "tracer returned $TRACE_RC (the COW fixture may also have failed)"
fi
[ -s "$REPORT" ] || fail 'JSON report missing'
if [ "$RUN_WITH_SUDO" -eq 1 ]; then
    sudo -n chown "$(id -u):$(id -g)" "$REPORT" || fail 'cannot read JSON report'
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
observations = lineage.get('observations', [])
edges = lineage.get('edges', [])
require(isinstance(observations, list) and isinstance(edges, list),
        'malformed lineage graph')

processes = [o for o in observations
             if o.get('type') == 'event' and o.get('syscall') == 'process']
require(len(processes) == 3,
        f'expected one parent and two separate children, got {len(processes)} nodes')

by_seq = {p['seq']: p for p in processes}
child_links = [e for e in edges
               if e.get('relation') == 'causality'
               and e.get('from_seq') in by_seq
               and e.get('to_seq') in by_seq
               and e.get('details') == 'kernel task creation']

# Both forked processes must have the same parent, but distinct lifetimes.
parents = {e['from_seq'] for e in child_links}
children = {e['to_seq'] for e in child_links}
require(len(parents) == 1 and len(children) == 2,
        'expected two task-creation edges from one parent to two children')
require(not (parents & children), 'unexpected cycle in task-creation edges')

parent = by_seq[next(iter(parents))]
child_nodes = [by_seq[s] for s in children]
parent_instance = parent.get('process_instance_id')
child_instances = {c.get('process_instance_id') for c in child_nodes}
require(len(child_instances) == 2 and parent_instance not in child_instances,
        'forked children do not have unique process-instance identities')
require(all(c.get('exec_generation') == 0 for c in child_nodes),
        'fork-only children unexpectedly changed executable generation')

pattern = re.compile(
    r'Runtime memory scan:\s+TGID=(\d+)\s+instance=(\d+)\s+'
    r'generation=(\d+)\s+reason=(\w+)\s+pages=(\d+)\s+'
    r'observations=(\d+)'
)
scans = [dict(tgid=int(m[0]), instance=int(m[1]), generation=int(m[2]),
              reason=m[3], pages=int(m[4]), found=int(m[5]))
         for m in pattern.findall(log)]

for child in child_nodes:
    instance = child['process_instance_id']
    tgid = child['tgid']
    relevant = [s for s in scans
                if s['tgid'] == tgid and s['instance'] == instance
                and s['generation'] == 0 and s['reason'] == 'InitialInspection']
    require(len(relevant) == 1,
            f'expected exactly one InitialInspection for child instance {instance}')
    require(0 < relevant[0]['pages'] <= 1000,
            f'child instance {instance} violated its scan page limit')

    # This fixture puts password=<32-byte value> in MAP_PRIVATE anonymous
    # memory. A scanner observation is only valid evidence when attributed
    # to the child's process instance and attached to it by observed_in.
    memory = [o for o in observations
              if o.get('type') == 'data'
              and o.get('data_type') == 'memory'
              and o.get('source') == 'memory'
              and o.get('secret_type') == 'password'
              and o.get('size') == 32
              and isinstance(o.get('address'), int) and o['address'] > 0
              and str(o.get('fingerprint', '')).startswith('hmac-sha256:')
              and o.get('process_instance_id') == instance
              and o.get('exec_generation') == 0]
    require(memory, f'no secret observed in child instance {instance}')
    require(any(e.get('relation') == 'observed_in'
                and e.get('from_seq') == child['seq']
                and e.get('to_seq') in {o['seq'] for o in memory}
                for e in edges),
            f'no child observed_in edge for instance {instance}')

    # Neither child needs to read a file or send a network message to
    # retain the inherited secret. Ordinary getpid/exit are permissible.
    inbound_or_network = [o for o in observations
                          if o.get('type') == 'event'
                          and o.get('process_instance_id') == instance
                          and o.get('syscall') in ('read', 'recvfrom', 'sendto')]
    require(not inbound_or_network,
            f'child instance {instance} unexpectedly used read/recvfrom/sendto')

# Do not infer DataFlow from matching fingerprints or identical VAs alone.
# No network or pipe data transfer of the secret occurs in this fixture.
require(not any(e.get('relation') == 'dataflow' for e in edges),
        'unexpected dataflow edge in a memory-only COW fixture')

print('PASS: parent and two independent forked child process instances')
print('PASS: both child images independently receive bounded InitialInspection')
print('PASS: both children have password evidence tied by observed_in')
print('PASS: no child read/recvfrom/sendto and no invented DataFlow')
print('NOTE: COW byte isolation is checked by fixture; physical PFNs are not observed by RuntimeXRay')
PY
