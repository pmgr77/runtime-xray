
#!/bin/sh
#
# @file    test_c1_memory_scan_coordinator.sh
# @brief   C1 integration regression for event-driven memory scanning.
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
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ---------------------------------------------------------------------------
# Purpose
# ---------------------------------------------------------------------------
#
# Exercises RuntimeXRay against a local, Basic-auth-protected Docker
# registry using curl and a temporary .netrc file.
#
# Verifies:
#
#   1. SensitiveDataDiscovery authorizes a memory scan.
#   2. DataBoundaryCrossing independently authorizes another scan.
#   3. Both scans belong to the same process executable image.
#   4. A memory observation matches both a read and a sendto event.
#   5. Both syscall events have valid observed_at evidence edges.
#   6. The memory observation belongs to the expected process image.
#
# The test creates its own disposable credentials. It never needs
# a developer's personal .netrc file.
#
# Exit codes:
#
#   0   All regression assertions passed.
#   1   A test assertion or execution failed.
#   125 Required test environment is unavailable (CTest SKIP).
#
# Required local fixture:
#
#   http://127.0.0.1:5000/v2/
#
# It must respond with HTTP 401 to an unauthenticated request
# and support HTTP Basic authentication.
#
# The Docker registry is an external fixture: this script does
# not start or modify Docker containers.
#
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Validate command-line arguments and dependencies.
# ---------------------------------------------------------------------------

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <runtimexray-binary>" >&2
    exit 125
fi

case "$1" in
    /*) BIN="$1" ;;
    *)  BIN="$(pwd)/$1" ;;
esac

[ -x "$BIN" ] || fail "RuntimeXRay binary is not executable"

for tool in curl python3 timeout; do
    command -v "$tool" >/dev/null 2>&1 ||
        skip "$tool is required"
done

# Memory inspection needs process-memory access privileges.
#
# Use the existing RuntimeXRay test convention: either run
# directly as root or use passwordless sudo.
RUN_AS_ROOT=0

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1 ||
       ! sudo -n true >/dev/null 2>&1; then
        skip "root or passwordless sudo is required"
    fi

    RUN_AS_ROOT=1
fi

# ---------------------------------------------------------------------------
# Check the real Docker registry fixture.
#
# HTTP 401 is expected. This is an unauthenticated request.
# It does not use or disclose any test credentials.
# ---------------------------------------------------------------------------

REGISTRY_URL="http://127.0.0.1:5000/v2/"

HTTP_CODE="$(
    curl \
        --noproxy '*' \
        --silent \
        --output /dev/null \
        --max-time 5 \
        --write-out '%{http_code}' \
        "$REGISTRY_URL"
)" || skip "local Docker registry is unavailable"

[ "$HTTP_CODE" = "401" ] ||
    skip "local registry did not return HTTP 401 (got $HTTP_CODE)"

# ---------------------------------------------------------------------------
# Create isolated test files.
#
# A private temporary directory protects the .netrc contents.
# Cleanup runs on success, failure, or interruption.
# ---------------------------------------------------------------------------

TEST_DIR="$(mktemp -d)" ||
    fail "cannot create temporary directory"

cleanup()
{
    rm -rf -- "$TEST_DIR"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

NETRC="$TEST_DIR/c1.netrc"
REPORT="$TEST_DIR/c1.json"
LOG="$TEST_DIR/trace.log"

# Generate disposable credentials without printing them.
#
# The registry need not accept them: the purpose is to
# observe curl reading .netrc and sending Basic credentials.
#
# Mode 0600 is required by our test security policy.
python3 - "$NETRC" <<'PY'
import os
import secrets
import sys

path = sys.argv[1]

username = "rxray_c1_" + secrets.token_hex(4)
password = "C1secret_" + secrets.token_hex(12)

fd = os.open(
    path,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    0o600,
)

with os.fdopen(fd, "w", encoding="utf-8") as out:
    out.write(
        f"machine 127.0.0.1 "
        f"login {username} "
        f"password {password}\n"
    )
PY

# ---------------------------------------------------------------------------
# Execute the real traced application.
#
# Explicit ptrace backend avoids variations caused by the
# default backend configuration.
#
# The scanner runs during traced syscall processing.
#
# timeout protects the test suite against a hanging target.
# The timeout is deliberately larger than the observed C1
# execution time because memory inspection is expensive.
# ---------------------------------------------------------------------------

set -- \
    "$BIN" trace \
    --backend ptrace \
    --follow-forks \
    --scan-memory \
    --json "$REPORT" \
    --report /dev/null \
    /usr/bin/curl \
    --noproxy '*' \
    --silent \
    --show-error \
    --netrc-file "$NETRC" \
    --output /dev/null \
    "$REGISTRY_URL"

TRACE_RC=0

if [ "$RUN_AS_ROOT" -eq 1 ]; then
    timeout 120 \
        sudo -n env "HOME=$HOME" \
        "$@" >"$LOG" 2>&1 ||
        TRACE_RC=$?
else
    timeout 120 \
        "$@" >"$LOG" 2>&1 ||
        TRACE_RC=$?
fi

if [ "$TRACE_RC" -ne 0 ]; then
    fail "RuntimeXRay returned exit code $TRACE_RC"
fi

[ -s "$REPORT" ] ||
    fail "RuntimeXRay did not create a JSON report"

# The privileged tracer may own the report file.
# Make it readable by the unprivileged validator.
if [ "$RUN_AS_ROOT" -eq 1 ]; then
    sudo -n chown \
        "$(id -u):$(id -g)" \
        "$REPORT" ||
        fail "cannot read privileged JSON report"
fi

# ---------------------------------------------------------------------------
# Validate scan accounting and lineage evidence.
#
# Use Python's JSON parser instead of grep-based JSON checks.
#
# Fingerprints are used only for equality comparisons.
# The script never prints credentials or fingerprint values.
# ---------------------------------------------------------------------------

python3 - "$REPORT" "$LOG" <<'PY'
import json
import pathlib
import re
import sys

report_path = pathlib.Path(sys.argv[1])
log_path = pathlib.Path(sys.argv[2])


def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)


report = json.loads(report_path.read_text(encoding="utf-8"))
log = log_path.read_text(encoding="utf-8")

lineage = report.get("lineage", {})
observations = lineage.get("observations", [])
edges = lineage.get("edges", [])

require(
    isinstance(observations, list) and observations,
    "lineage observations are missing",
)

require(
    isinstance(edges, list),
    "lineage edges are missing",
)

# -----------------------------------------------------------------------
# Assertion 1: two independently authorized runtime memory scans.
#
# Capture identity and resource usage from structured log messages.
# PID alone is not used as the scan identity.
# -----------------------------------------------------------------------

scan_pattern = re.compile(
    r"Runtime memory scan:\s+"
    r"TGID=(\d+)\s+"
    r"instance=(\d+)\s+"
    r"generation=(\d+)\s+"
    r"reason=(\w+)\s+"
    r"pages=(\d+)\s+"
    r"observations=(\d+)"
)

scans = []

for match in scan_pattern.finditer(log):
    tgid, instance, generation, reason, pages, found = match.groups()

    scans.append({
        "tgid": int(tgid),
        "instance": int(instance),
        "generation": int(generation),
        "reason": reason,
        "pages": int(pages),
        "observations": int(found),
    })

require(scans, "no runtime memory scans were logged")

discovery_scans = [
    scan for scan in scans
    if scan["reason"] == "SensitiveDataDiscovery"
]

boundary_scans = [
    scan for scan in scans
    if scan["reason"] == "DataBoundaryCrossing"
]

require(
    len(discovery_scans) == 1,
    "expected exactly one SensitiveDataDiscovery scan",
)

require(
    len(boundary_scans) == 1,
    "expected exactly one DataBoundaryCrossing scan",
)

discovery = discovery_scans[0]
boundary = boundary_scans[0]

scan_identity = (
    discovery["instance"],
    discovery["generation"],
)

require(
    scan_identity == (
        boundary["instance"],
        boundary["generation"],
    ),
    "scans belong to different process images",
)

require(
    discovery["tgid"] == boundary["tgid"],
    "scans unexpectedly target different TGIDs",
)

require(
    0 < discovery["pages"] <= 1000,
    "discovery scan violated its page limit",
)

require(
    0 < boundary["pages"] <= 1000,
    "boundary scan violated its page limit",
)

require(
    discovery["pages"] + boundary["pages"] <= 2000,
    "process-image page budget exceeded",
)

# -----------------------------------------------------------------------
# Assertion 2: locate scanner-derived HTTP Basic credentials.
#
# We do not assume that the memory observation is produced
# by a particular scan: its timing depends on application state.
# -----------------------------------------------------------------------

memory_observations = [
    obs for obs in observations
    if obs.get("type") == "data"
    and obs.get("source") == "memory"
    and obs.get("secret_type") == "http_basic_password"
    and str(obs.get("fingerprint", "")).startswith("hmac-sha256:")
]

require(
    memory_observations,
    "no HTTP Basic credential found in process memory",
)

# -----------------------------------------------------------------------
# Assertion 3: validate real event -> Data evidence edges.
#
# Merely counting observed_at edges is insufficient:
# their endpoints must refer to the right observations.
# -----------------------------------------------------------------------

by_seq = {
    obs.get("seq"): obs
    for obs in observations
}

require(
    len(by_seq) == len(observations),
    "duplicate observation sequence numbers",
)


def has_observed_at_edge(event, fingerprint):
    """
    Verify that a syscall event has a matching Data observation
    linked by an observed_at edge using actual observation seq IDs.
    """

    event_seq = event.get("seq")

    for data in observations:
        if data.get("type") != "data":
            continue

        if data.get("fingerprint") != fingerprint:
            continue

        if data.get("source_event_seq") != event_seq:
            continue

        for edge in edges:
            if (
                edge.get("relation") == "observed_at"
                and edge.get("from_seq") == event_seq
                and edge.get("to_seq") == data.get("seq")
            ):
                return True

    return False


def same_image(obs, instance, generation):
    return (
        obs.get("process_instance_id") == instance
        and obs.get("exec_generation") == generation
    )


def has_process_observation_edge(memory, instance):
    """
    Confirm that the memory Data observation is attached to
    the process node by an observed_in edge.
    """

    process_seqs = {
        obs.get("seq")
        for obs in observations
        if obs.get("type") == "event"
        and obs.get("syscall") == "process"
        and obs.get("process_instance_id") == instance
    }

    return any(
        edge.get("relation") == "observed_in"
        and edge.get("from_seq") in process_seqs
        and edge.get("to_seq") == memory.get("seq")
        for edge in edges
    )


# -----------------------------------------------------------------------
# Assertion 4: one exact credential identity must be observed in:
#
#   memory
#   read()
#   sendto()
#
# All three observations must belong to the same process image.
# Both syscall paths must retain valid observed_at evidence edges.
# -----------------------------------------------------------------------

matched = False

for memory in memory_observations:
    instance = memory.get("process_instance_id")
    generation = memory.get("exec_generation")
    fingerprint = memory.get("fingerprint")

    if (instance, generation) != scan_identity:
        continue

    reads = [
        obs for obs in observations
        if obs.get("type") == "event"
        and obs.get("syscall") == "read"
        and obs.get("fingerprint") == fingerprint
        and same_image(obs, instance, generation)
        and has_observed_at_edge(obs, fingerprint)
    ]

    sends = [
        obs for obs in observations
        if obs.get("type") == "event"
        and obs.get("syscall") == "sendto"
        and obs.get("fingerprint") == fingerprint
        and same_image(obs, instance, generation)
        and has_observed_at_edge(obs, fingerprint)
    ]

    if (
        reads
        and sends
        and has_process_observation_edge(memory, instance)
    ):
        matched = True
        break

require(
    matched,
    "memory/read/sendto credential correlation or "
    "lineage evidence edges are incomplete",
)

# -----------------------------------------------------------------------
# Report only non-sensitive results.
# -----------------------------------------------------------------------

print("PASS: SensitiveDataDiscovery scan authorized")
print("PASS: DataBoundaryCrossing scan authorized")
print("PASS: both scans share one process-image identity")

print(
    "PASS: page budget respected "
    f"({discovery['pages']} + {boundary['pages']} pages)"
)

print("PASS: matching HTTP Basic credential observed in memory")
print("PASS: matching fingerprint observed in read and sendto")
print("PASS: read and sendto observed_at edges verified")
print("PASS: memory observed_in process edge verified")
print("PASS: C1 MemoryScanCoordinator regression")
PY
