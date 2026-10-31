
#!/bin/sh
#
# @file    test_f1_stdin_credentials.sh
# @brief   F1 regression: credentials supplied through stdin pipe.
#
# @author  Peter Magram
# @date    2026-10-31
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
# Supply a disposable curl configuration through stdin (fd 0).
#
# Verify:
#
#   1. The secret is discovered during read(fd=0).
#   2. The read has valid observed_at evidence.
#   3. The same fingerprint appears in process memory.
#   4. The same fingerprint appears in sendto_data.
#   5. The network observation has valid observed_at evidence.
#   6. The memory observation has valid observed_in evidence.
#   7. All observations belong to the same process image.
#   8. Plaintext credentials are absent from generated artifacts.
#
# An inherited stdin pipe may have no resource_id. This test does
# not require one; inherited FD discovery is a separate feature.
#
# Fingerprint equality establishes correlation, not causality.
#
# Exit codes:
#   0   Passed
#   1   Failed
#   125 Required environment unavailable (CTest SKIP)
#
# Required fixture:
#   http://127.0.0.1:5000/v2/
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

if [ "$#" -ne 1 ]; then
    skip "usage: $0 <runtimexray-binary>"
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
# Validate the external registry fixture.
# ---------------------------------------------------------------------------

REGISTRY_URL="http://127.0.0.1:5000/v2/"

HTTP_CODE="$(
    curl \
        --disable \
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
# Prepare disposable credentials and test artifacts.
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

CONFIG="$TEST_DIR/stdin-config.txt"
CREDENTIALS="$TEST_DIR/credentials.json"
JSON_REPORT="$TEST_DIR/f1.json"
TEXT_REPORT="$TEST_DIR/f1-report.txt"
LOG="$TEST_DIR/trace.log"

python3 - "$CONFIG" "$CREDENTIALS" <<'PY'
import json
import os
import secrets
import sys

config_path, credentials_path = sys.argv[1:]

username = "rxray_f1_" + secrets.token_hex(4)
password = "F1secret_" + secrets.token_hex(12)

for path, content in (
    (config_path, f'user = "{username}:{password}"\n'),
    (credentials_path, json.dumps({"password": password})),
):
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(content)
PY

# ---------------------------------------------------------------------------
# Trace curl while supplying its configuration over a real pipe.
#
# cat -> pipe -> RuntimeXRay -> curl read(fd=0)
#
# The temporary config is an input fixture, not a file opened by curl.
# The tracer receives its contents through inherited stdin.
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
    --config - \
    --output /dev/null \
    "$REGISTRY_URL"

TRACE_RC=0

if [ "$RUN_AS_ROOT" -eq 1 ]; then
    cat "$CONFIG" |
        timeout 120 \
            sudo -n env "HOME=$HOME" \
            "$@" >"$LOG" 2>&1 ||
        TRACE_RC=$?
else
    cat "$CONFIG" |
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

if [ "$RUN_AS_ROOT" -eq 1 ]; then
    sudo -n chown \
        "$(id -u):$(id -g)" \
        "$JSON_REPORT" "$TEXT_REPORT" ||
        fail "cannot read privileged reports"
fi

# ---------------------------------------------------------------------------
# Validate confidentiality and exact-value correlation.
# ---------------------------------------------------------------------------

python3 - \
    "$CREDENTIALS" \
    "$JSON_REPORT" \
    "$TEXT_REPORT" \
    "$LOG" <<'PY'

import json
import pathlib
import sys


def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)


credentials_path, json_path, text_path, log_path = map(
    pathlib.Path, sys.argv[1:]
)

password = json.loads(
    credentials_path.read_text(encoding="utf-8")
)["password"]

json_text = json_path.read_text(encoding="utf-8")
text_report = text_path.read_text(encoding="utf-8")
log_text = log_path.read_text(encoding="utf-8")

# Never print secrets or fingerprint values.
for name, content in (
    ("JSON", json_text),
    ("text report", text_report),
    ("trace log", log_text),
):
    require(
        password not in content,
        "plaintext password leaked into " + name,
    )

print("PASS: plaintext credential redaction")

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

seqs = [obs.get("seq") for obs in observations]

require(
    all(type(seq) is int for seq in seqs),
    "invalid observation sequence number",
)

require(
    len(seqs) == len(set(seqs)),
    "duplicate observation sequence numbers",
)


def same_image(a, b):
    return (
        a.get("process_instance_id") is not None
        and a.get("exec_generation") is not None
        and a.get("process_instance_id") == b.get("process_instance_id")
        and a.get("exec_generation") == b.get("exec_generation")
    )


def data_observations(source, secret_type):
    return [
        obs for obs in observations
        if obs.get("type") == "data"
        and obs.get("source") == source
        and obs.get("secret_type") == secret_type
        and str(obs.get("fingerprint", "")).startswith("hmac-sha256:")
    ]


reads = data_observations("read", "password")
memories = data_observations("memory", "http_basic_password")
network = data_observations("sendto_data", "http_basic_password")

require(reads, "password not detected in read")
require(memories, "password not detected in memory")
require(network, "password not detected in sendto_data")

# -----------------------------------------------------------------------
# Evidence edges must reference real observations.
# -----------------------------------------------------------------------

def has_read_edge(data):
    return any(
        event.get("type") == "event"
        and event.get("syscall") == "read"
        and event.get("args", [None])[0] == 0
        and event.get("return_value", 0) > 0
        and event.get("seq") == data.get("source_event_seq")
        and event.get("fingerprint") == data.get("fingerprint")
        and same_image(event, data)
        and any(
            edge.get("relation") == "observed_at"
            and edge.get("from_seq") == event.get("seq")
            and edge.get("to_seq") == data.get("seq")
            for edge in edges
        )
        for event in observations
    )


def has_sendto_edge(data):
    return any(
        event.get("type") == "event"
        and event.get("syscall") == "sendto"
        and event.get("seq") == data.get("source_event_seq")
        and event.get("fingerprint") == data.get("fingerprint")
        and same_image(event, data)
        and any(
            edge.get("relation") == "observed_at"
            and edge.get("from_seq") == event.get("seq")
            and edge.get("to_seq") == data.get("seq")
            for edge in edges
        )
        for event in observations
    )


def has_memory_edge(data):
    return any(
        process.get("type") == "event"
        and process.get("syscall") == "process"
        and same_image(process, data)
        and any(
            edge.get("relation") == "observed_in"
            and edge.get("from_seq") == process.get("seq")
            and edge.get("to_seq") == data.get("seq")
            for edge in edges
        )
        for process in observations
    )


matched = any(
    read.get("fingerprint") == memory.get("fingerprint")
    and read.get("fingerprint") == sent.get("fingerprint")
    and same_image(read, memory)
    and same_image(read, sent)
    and has_read_edge(read)
    and has_memory_edge(memory)
    and has_sendto_edge(sent)
    for read in reads
    for memory in memories
    for sent in network
)

require(
    matched,
    "stdin/memory/network correlation or evidence edges missing",
)

print("PASS: credential detected in read(fd=0)")
print("PASS: matching credential detected in memory")
print("PASS: matching credential detected in sendto_data")
print("PASS: matching fingerprint across all three sources")
print("PASS: process-image identity")
print("PASS: observed_at and observed_in evidence edges")
print("PASS: F1 stdin credentials regression")
PY
