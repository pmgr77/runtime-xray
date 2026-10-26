#!/bin/sh
#
# @file    test_b1_curl_config.sh
# @brief   B1 integration regression for curl config credential discovery.
#
# @author  Peter Magram
# @date    2026-10-26
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
# Exercises RuntimeXRay against a local Basic-auth-protected registry,
# using credentials supplied through an explicit curl configuration file.
#
# Verifies:
#
#   1. The config-file read produces a password fingerprint.
#   2. The read is associated with a file resource.
#   3. The same fingerprint appears in process memory.
#   4. The same fingerprint appears in the sendto payload.
#   5. All observations belong to the same process image.
#   6. Syscall/Data and process/memory evidence edges are valid.
#   7. Plaintext credentials do not appear in generated artifacts.
#
# Fingerprint equality establishes correlation, not proven data flow.
#
# Exit codes:
#
#   0   All regression assertions passed.
#   1   Test failure.
#   125 Required test environment unavailable (CTest SKIP).
#
# Required fixture:
#
#   http://127.0.0.1:5000/v2/
#
# The registry must return HTTP 401 without credentials.
# The test does not start or modify Docker containers.
#
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Dependencies and privileges.
# ---------------------------------------------------------------------------

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <runtimexray-binary>" >&2
    exit 125
fi

case "$1" in
    /*) BIN="$1" ;;
    *)  BIN="$(pwd)/$1" ;;
esac

[ -x "$BIN" ] ||
    fail "RuntimeXRay binary is not executable"

[ -x /usr/bin/curl ] ||
    skip "/usr/bin/curl is required"

for tool in curl python3 timeout; do
    command -v "$tool" >/dev/null 2>&1 ||
        skip "$tool is required"
done

RUN_AS_ROOT=0

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1 ||
       ! sudo -n true >/dev/null 2>&1; then
        skip "root or passwordless sudo is required"
    fi

    RUN_AS_ROOT=1
fi

# ---------------------------------------------------------------------------
# Validate local registry.
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
    skip "local registry did not return HTTP 401"

# ---------------------------------------------------------------------------
# Create isolated test artifacts.
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

CONFIG="$TEST_DIR/b1.conf"
JSON_REPORT="$TEST_DIR/b1.json"
TEXT_REPORT="$TEST_DIR/b1-report.txt"
LOG="$TEST_DIR/trace.log"

# ---------------------------------------------------------------------------
# Generate disposable credentials.
#
# The configuration contains a real curl user directive.
# The credentials are random and used only against localhost.
# ---------------------------------------------------------------------------

python3 - "$CONFIG" <<'PY'
import os
import secrets
import sys

path = sys.argv[1]

username = "rxray_b1_" + secrets.token_hex(4)
password = "B1secret_" + secrets.token_hex(12)

fd = os.open(
    path,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    0o600,
)

with os.fdopen(fd, "w", encoding="utf-8") as out:
    out.write(f'user = "{username}:{password}"\n')
PY

# ---------------------------------------------------------------------------
# Execute RuntimeXRay.
#
# --disable prevents curl from loading an implicit .curlrc.
# --config selects our isolated fixture.
# --memory-reader proc makes the memory backend explicit.
# ---------------------------------------------------------------------------

set -- \
    "$BIN" trace \
    --backend ptrace \
    --memory-reader proc \
    --follow-forks \
    --scan-memory \
    --json "$JSON_REPORT" \
    --report "$TEXT_REPORT" \
    /usr/bin/curl \
    --disable \
    --noproxy '*' \
    --silent \
    --show-error \
    --config "$CONFIG" \
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

[ "$TRACE_RC" -eq 0 ] ||
    fail "RuntimeXRay returned exit code $TRACE_RC"

[ -s "$JSON_REPORT" ] ||
    fail "JSON report was not created"

[ -s "$TEXT_REPORT" ] ||
    fail "text report was not created"

# Allow the unprivileged validator to read generated reports.
if [ "$RUN_AS_ROOT" -eq 1 ]; then
    sudo -n chown \
        "$(id -u):$(id -g)" \
        "$JSON_REPORT" "$TEXT_REPORT" ||
        fail "cannot read privileged reports"
fi

# ---------------------------------------------------------------------------
# Validate confidentiality and lineage.
#
# No plaintext passwords or fingerprints are printed.
# ---------------------------------------------------------------------------

python3 - "$CONFIG" "$JSON_REPORT" "$TEXT_REPORT" "$LOG" <<'PY'
import json
import pathlib
import sys

config_path = pathlib.Path(sys.argv[1])
json_path = pathlib.Path(sys.argv[2])
text_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])


def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)


# -----------------------------------------------------------------------
# Recover the disposable test password for redaction checks.
# -----------------------------------------------------------------------

config = config_path.read_text(encoding="utf-8")

prefix = 'user = "'

require(
    config.startswith(prefix) and config.endswith('"\n'),
    "invalid generated curl configuration",
)

credentials = config[len(prefix):-2]

require(
    ":" in credentials,
    "generated configuration has no password separator",
)

username, password = credentials.split(":", 1)

require(
    bool(username) and bool(password),
    "generated credentials are incomplete",
)

# -----------------------------------------------------------------------
# Read reports and ensure that plaintext did not leak.
# -----------------------------------------------------------------------

json_text = json_path.read_text(encoding="utf-8")
report_text = text_path.read_text(encoding="utf-8")
log_text = log_path.read_text(encoding="utf-8")

for name, content in (
    ("JSON", json_text),
    ("text report", report_text),
    ("trace log", log_text),
):
    require(
        password not in content,
        "plaintext password leaked into " + name,
    )

print("PASS: plaintext credential redaction")

# -----------------------------------------------------------------------
# Parse lineage observations and edges.
# -----------------------------------------------------------------------

report = json.loads(json_text)

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

by_seq = {
    obs.get("seq"): obs
    for obs in observations
}

require(
    len(by_seq) == len(observations),
    "duplicate observation sequence numbers",
)


def same_image(obs, instance, generation):
    return (
        obs.get("process_instance_id") == instance
        and obs.get("exec_generation") == generation
    )


def has_observed_at_edge(event, fingerprint, source=None):
    """
    Verify an event -> Data observed_at edge.

    Both endpoints must refer to actual observations.
    A matching fingerprint alone is insufficient.
    """

    event_seq = event.get("seq")

    for data in observations:
        if data.get("type") != "data":
            continue

        if data.get("fingerprint") != fingerprint:
            continue

        if data.get("source_event_seq") != event_seq:
            continue

        if source is not None and data.get("source") != source:
            continue

        if not same_image(
            data,
            event.get("process_instance_id"),
            event.get("exec_generation"),
        ):
            continue

        if any(
            edge.get("relation") == "observed_at"
            and edge.get("from_seq") == event_seq
            and edge.get("to_seq") == data.get("seq")
            for edge in edges
        ):
            return True

    return False


def has_process_observation_edge(memory, instance):
    """
    Verify the process -> memory Data observed_in edge.
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
# Locate matching HTTP Basic password observations in memory.
# -----------------------------------------------------------------------

memories = [
    obs for obs in observations
    if obs.get("type") == "data"
    and obs.get("source") == "memory"
    and obs.get("secret_type") == "http_basic_password"
    and str(obs.get("fingerprint", "")).startswith("hmac-sha256:")
]

require(
    memories,
    "HTTP Basic password was not detected in memory",
)

# -----------------------------------------------------------------------
# Find one fingerprint shared by:
#
#   file read event
#   memory Data observation
#   sendto event and sendto_data observation
#
# All must belong to the same process executable image.
# -----------------------------------------------------------------------

matched = False

for memory in memories:
    fingerprint = memory.get("fingerprint")
    instance = memory.get("process_instance_id")
    generation = memory.get("exec_generation")

    reads = [
        obs for obs in observations
        if obs.get("type") == "event"
        and obs.get("syscall") == "read"
        and obs.get("fingerprint") == fingerprint
        and obs.get("resource_type") == "file"
        and obs.get("resource_role") == "read"
        and isinstance(obs.get("resource_id"), int)
        and same_image(obs, instance, generation)
        and has_observed_at_edge(obs, fingerprint)
    ]

    sends = [
        obs for obs in observations
        if obs.get("type") == "event"
        and obs.get("syscall") == "sendto"
        and obs.get("fingerprint") == fingerprint
        and same_image(obs, instance, generation)
        and has_observed_at_edge(
            obs,
            fingerprint,
            source="sendto_data",
        )
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
    "read/memory/sendto fingerprint correlation "
    "or lineage evidence is missing",
)

print("PASS: curl config password observed in file read")
print("PASS: matching password observed in memory")
print("PASS: matching password observed in sendto")
print("PASS: all observations share one process image")
print("PASS: observed_at and observed_in evidence edges")
print("PASS: B1 curl config regression")
PY