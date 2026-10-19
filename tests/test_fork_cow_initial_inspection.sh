#!/bin/sh
#
# @file    test_fork_cow_initial_inspection.sh
# @brief   Stage C regression: inherited private secret in a forked child.
#
# @author  Peter Magram
# @date    2026-10-19
# @copyright Copyright 2026 Peter Magram.
# @license Apache-2.0 (see LICENSE file in the repository root)
#
# Copyright 2026 Peter Magram
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This is a deliberately RED regression against Stage B: Stage B captures
# argv/environment on initial process observation, but does not yet scan
# process memory for MemoryScanReason::InitialInspection.
#
# The fixture allocates a MAP_PRIVATE anonymous page, constructs a synthetic
# password there, forks, erases only the parent's copy, then lets the child
# execute getpid() and exit. The child never reads or sends the secret.
#
# Success criteria:
#   1. A parent and a distinct child process instance are observed.
#   2. Their process nodes have an explicit task-creation causality edge.
#   3. The child makes the expected getpid() syscall.
#   4. An InitialInspection memory scan targets the CHILD image.
#   5. That scan obeys its per-scan and per-image page limits.
#   6. A 32-byte synthetic password is observed in the child's memory.
#   7. An observed_in edge attaches that Data evidence to the child process.
#   8. Child performed no read/recvfrom/sendto syscalls.
#
# The test never uses real credentials and never prints secret bytes or HMACs.
# Exit status: 0 = pass, 1 = fail, 125 = missing environment (CTest skip).
#

set -eu

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

[ "$#" -eq 1 ] || {
    echo "Usage: $0 <runtimexray-binary>" >&2
    exit 125
}

case "$1" in
    /*) BIN="$1" ;;
    *)  BIN="$(pwd)/$1" ;;
esac

[ -x "$BIN" ] || fail "RuntimeXRay binary is not executable: $BIN"

for command_name in cc python3 timeout; do
    command -v "$command_name" >/dev/null 2>&1 ||
        skip "$command_name is required"
done

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
FIXTURE_SOURCE="$SCRIPT_DIR/dynamic_analysis/fork_cow_secret.c"

[ -f "$FIXTURE_SOURCE" ] ||
    fail "missing fixture: $FIXTURE_SOURCE"

# Match existing ptrace integration tests: the tracer must be able to
# inspect another process's memory. No interactive sudo prompt is allowed.
RUN_WITH_SUDO=0

if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 ||
        skip "sudo is unavailable"

    sudo -n true >/dev/null 2>&1 ||
        skip "root or passwordless sudo required"

    RUN_WITH_SUDO=1
fi

TEST_DIR="$(mktemp -d)" ||
    fail "cannot create private test directory"

cleanup()
{
    rm -rf -- "$TEST_DIR"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

FIXTURE="$TEST_DIR/fork_cow_secret"
REPORT="$TEST_DIR/fork-cow.json"
LOG="$TEST_DIR/trace.log"

# Build the fixture directly so this regression can run BEFORE its CMake
# registration is added. Compiler errors are real test failures, not skips.
cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$FIXTURE_SOURCE" -o "$FIXTURE" ||
    fail "cannot compile fork/COW fixture"

# Keep the target process tree minimal and deterministic. Only the fixture is
# traced; the compiler and shell launching this test are not traced.
set -- \
    "$BIN" trace \
    --backend ptrace \
    --follow-forks \
    --scan-memory \
    --log-level info \
    --json "$REPORT" \
    --report /dev/null \
    "$FIXTURE"

TRACE_RC=0

if [ "$RUN_WITH_SUDO" -eq 1 ]; then
    timeout 90 sudo -n env "HOME=$HOME" "$@" >"$LOG" 2>&1 ||
        TRACE_RC=$?
else
    timeout 90 "$@" >"$LOG" 2>&1 ||
        TRACE_RC=$?
fi

if [ "$TRACE_RC" -ne 0 ]; then
    echo "--- tracer diagnostics (non-secret lines) ---" >&2

    grep -E \
        '^(Error|ERROR|FAIL|FATAL|SKIP|Runtime memory scan:)' \
        "$LOG" >&2 || true

    fail "RuntimeXRay returned exit code $TRACE_RC"
fi

[ -s "$REPORT" ] ||
    fail "RuntimeXRay did not produce JSON report"

# The privileged tracer may have created a root-owned report inside our
# private directory. chown only that file, not the directory or raw logs.
if [ "$RUN_WITH_SUDO" -eq 1 ]; then
    sudo -n chown "$(id -u):$(id -g)" "$REPORT" ||
        fail "cannot make JSON report readable"
fi

python3 - "$REPORT" "$LOG" <<'PY'
import json
import pathlib
import re
import sys

report = json.loads(
    pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
)

log = pathlib.Path(sys.argv[2]).read_text(
    encoding="utf-8",
    errors="replace"
)


def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)


lineage = report.get("lineage", {})
observations = lineage.get("observations", [])
edges = lineage.get("edges", [])

require(
    isinstance(observations, list) and observations,
    "lineage observations are missing"
)

require(
    isinstance(edges, list),
    "lineage edges are missing"
)

by_seq = {
    obs.get("seq"): obs
    for obs in observations
}

require(
    len(by_seq) == len(observations),
    "duplicate or missing observation sequence numbers"
)

# Process observation identities are stronger than bare PIDs, which Linux
# may reuse. This controlled fixture should create exactly two processes.
processes = [
    obs for obs in observations
    if obs.get("type") == "event"
    and obs.get("syscall") == "process"
]

require(
    len(processes) == 2,
    f"expected exactly two process instances; got {len(processes)}"
)

# Find the child's first post-fork syscall. It identifies the child without
# relying on PID ordering or arbitrary observation ordering.
getpids = [
    obs for obs in observations
    if obs.get("type") == "event"
    and obs.get("syscall") == "getpid"
]

require(
    len(getpids) == 1,
    f"expected one child getpid event; got {len(getpids)}"
)

getpid = getpids[0]

child_instance = getpid.get("process_instance_id")
child_generation = getpid.get("exec_generation")
child_tgid = getpid.get("tgid")

require(
    isinstance(child_instance, int) and child_instance > 0,
    "child getpid has no valid process instance"
)

require(
    isinstance(child_tgid, int) and child_tgid > 0,
    "child getpid has no valid TGID"
)

child_nodes = [
    obs for obs in processes
    if obs.get("process_instance_id") == child_instance
    and obs.get("tgid") == child_tgid
]

require(
    len(child_nodes) == 1,
    "child process node not found"
)

child_node = child_nodes[0]

parent_nodes = [
    obs for obs in processes
    if obs.get("process_instance_id") != child_instance
]

require(
    len(parent_nodes) == 1,
    "parent process node not found"
)

parent_node = parent_nodes[0]

require(
    any(
        edge.get("relation") == "causality"
        and edge.get("from_seq") == parent_node.get("seq")
        and edge.get("to_seq") == child_node.get("seq")
        for edge in edges
    ),
    "missing explicit parent-to-child task-creation edge"
)

# An explicit InitialInspection scan is required in the child's process
# image. A scan of the parent or another exec generation is not equivalent.
scan_pattern = re.compile(
    r"Runtime memory scan:\s+"
    r"TGID=(\d+)\s+"
    r"instance=(\d+)\s+"
    r"generation=(\d+)\s+"
    r"reason=(\w+)\s+"
    r"pages=(\d+)\s+"
    r"observations=(\d+)"
)

scans = [
    {
        "tgid": int(m[0]),
        "instance": int(m[1]),
        "generation": int(m[2]),
        "reason": m[3],
        "pages": int(m[4]),
        "observations": int(m[5]),
    }
    for m in scan_pattern.findall(log)
]

child_initial_scans = [
    scan for scan in scans
    if scan["tgid"] == child_tgid
    and scan["instance"] == child_instance
    and scan["generation"] == child_generation
    and scan["reason"] == "InitialInspection"
]

require(
    len(child_initial_scans) == 1,
    "expected one InitialInspection memory scan in the CHILD process image "
    "(expected failure until Stage C is implemented)"
)

scan = child_initial_scans[0]

require(
    0 < scan["pages"] <= 1000,
    "child initial scan exceeded its 1000-page permit"
)

# The parent and child may use independent budgets. A zero-page scan does
# not count as observation of the child secret.
require(
    scan["observations"] > 0,
    "child InitialInspection scan produced no sensitive observations"
)

# This fixture constructs a password= marker with a 32-byte value only
# in a MAP_PRIVATE anonymous mapping. No argv/environment secret is used.
child_memory = [
    obs for obs in observations
    if obs.get("type") == "data"
    and obs.get("source") == "memory"
    and obs.get("secret_type") == "password"
    and obs.get("size") == 32
    and str(obs.get("fingerprint", "")).startswith("hmac-sha256:")
    and obs.get("process_instance_id") == child_instance
    and obs.get("exec_generation") == child_generation
    and obs.get("tgid") == child_tgid
    and isinstance(obs.get("address"), int)
    and obs.get("address") > 0
]

require(
    child_memory,
    "synthetic 32-byte password not observed in CHILD process memory"
)

# The observation must be real graph evidence attached to the child's
# process node, not merely an unconnected scanner result.
linked = [
    obs for obs in child_memory
    if any(
        edge.get("relation") == "observed_in"
        and edge.get("from_seq") == child_node.get("seq")
        and edge.get("to_seq") == obs.get("seq")
        for edge in edges
    )
]

require(
    linked,
    "child memory observation is missing its observed_in process edge"
)

# The child does not perform these syscalls at all. That makes the test
# specifically about inherited memory, not a syscall-based discovery path.
child_io = [
    obs for obs in observations
    if obs.get("type") == "event"
    and obs.get("process_instance_id") == child_instance
    and obs.get("exec_generation") == child_generation
    and obs.get("syscall") in ("read", "recvfrom", "sendto")
]

require(
    not child_io,
    "the child unexpectedly executed read/recvfrom/sendto"
)

print("PASS: separate parent/child process instances and fork causality")
print("PASS: child getpid inspection opportunity observed")
print("PASS: exactly one child InitialInspection memory scan")
print(f"PASS: child scan respected page budget ({scan['pages']} pages)")
print("PASS: inherited synthetic password observed in child memory")
print("PASS: child memory Data evidence attached by observed_in edge")
print("PASS: child executed no read/recvfrom/sendto syscalls")
PY