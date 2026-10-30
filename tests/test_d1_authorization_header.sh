
#!/bin/sh
#
# @file    test_d1_authorization_header.sh
# @brief   D1 integration regression for HTTP Basic Authorization headers.
#
# @author  Peter Magram
# @date    2026-10-30
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
# Trace curl sending an explicit HTTP Basic Authorization header.
#
# Verify:
#
#   1. Base64-encoded credentials are recognized in cmdline.
#   2. The same credential is observed in process memory.
#   3. The same credential is observed in sendto_data.
#   4. All three observations have matching HMAC fingerprints.
#   5. Observations belong to the same process image.
#   6. sendto -> sendto_data has a valid observed_at edge.
#   7. Process -> memory has a valid observed_in edge.
#   8. The plaintext password is absent from generated artifacts.
#
# Fingerprint equality demonstrates correlation, not proven causality.
#
# Exit codes:
#
#   0   Passed.
#   1   Failed.
#   125 Required environment unavailable (CTest SKIP).
#
# Requires a local Docker Registry responding HTTP 401 at:
#
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

# ---------------------------------------------------------------------------
# Arguments and dependencies.
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
# Check local registry fixture.
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
# Temporary files.
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

CREDENTIALS="$TEST_DIR/credentials.json"
JSON_REPORT="$TEST_DIR/d1.json"
TEXT_REPORT="$TEST_DIR/d1-report.txt"
LOG="$TEST_DIR/trace.log"

# ---------------------------------------------------------------------------
# Generate disposable credentials.
#
# The actual password is retained in a private 0600 JSON file.
# Only its Base64 representation is passed to curl.
#
# No credentials are printed to test output.
# ---------------------------------------------------------------------------

BASIC_TOKEN="$(
    python3 - "$CREDENTIALS" <<'PY'
import base64
import json
import os
import secrets
import sys

path = sys.argv[1]

username = "rxray_d1_" + secrets.token_hex(4)
password = "D1secret_" + secrets.token_hex(12)

raw = f"{username}:{password}".encode("ascii")
token = base64.b64encode(raw).decode("ascii")

fd = os.open(
    path,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    0o600,
)

with os.fdopen(fd, "w", encoding="utf-8") as out:
    json.dump({"password": password}, out)

print(token)
PY
)" || fail "cannot generate test credentials"

# ---------------------------------------------------------------------------
# Trace curl with an explicit Authorization header.
#
# --disable prevents implicit .curlrc loading.
# --memory-reader proc selects the low-impact memory reader.
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
    --header "Authorization: Basic $BASIC_TOKEN" \
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

unset BASIC_TOKEN

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
# Verify confidentiality, fingerprints and lineage.
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


credentials_path = pathlib.Path(sys.argv[1])
json_path = pathlib.Path(sys.argv[2])
text_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])

password = json.loads(
    credentials_path.read_text(encoding="utf-8")
)["password"]

json_text = json_path.read_text(encoding="utf-8")
text_report = text_path.read_text(encoding="utf-8")
log_text = log_path.read_text(encoding="utf-8")

# -----------------------------------------------------------------------
# Assertion 1: plaintext redaction.
# -----------------------------------------------------------------------

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

# -----------------------------------------------------------------------
# Assertion 2: structural integrity of lineage observations.
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

seqs = [obs.get("seq") for obs in observations]

require(
    all(isinstance(seq, int) for seq in seqs),
    "invalid observation sequence number",
)

require(
    len(seqs) == len(set(seqs)),
    "duplicate observation sequence numbers",
)


def same_image(a, b):
    return (
        a.get("process_instance_id") == b.get("process_instance_id")
        and a.get("exec_generation") == b.get("exec_generation")
    )


def data_observations(source):
    return [
        obs for obs in observations
        if obs.get("type") == "data"
        and obs.get("source") == source
        and obs.get("secret_type") == "http_basic_password"
        and obs.get("transformation") == "base64_decoded"
        and str(obs.get("fingerprint", "")).startswith("hmac-sha256:")
    ]


cmdline = data_observations("cmdline")
memory = data_observations("memory")
network = data_observations("sendto_data")

require(cmdline, "HTTP Basic password missing from cmdline")
require(memory, "HTTP Basic password missing from memory")
require(network, "HTTP Basic password missing from sendto_data")

# -----------------------------------------------------------------------
# Assertion 3: real evidence edges.
# -----------------------------------------------------------------------

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


# -----------------------------------------------------------------------
# Assertion 4: one exact secret across three sources.
# -----------------------------------------------------------------------

matched = False

for cmd in cmdline:
    for mem in memory:
        if not same_image(cmd, mem):
            continue

        if cmd.get("fingerprint") != mem.get("fingerprint"):
            continue

        if not has_memory_edge(mem):
            continue

        for sent in network:
            if not same_image(cmd, sent):
                continue

            if cmd.get("fingerprint") != sent.get("fingerprint"):
                continue

            if not has_sendto_edge(sent):
                continue

            matched = True
            break

        if matched:
            break

    if matched:
        break

require(
    matched,
    "cmdline/memory/sendto credential correlation "
    "or evidence edges are missing",
)

print("PASS: HTTP Basic password detected in cmdline")
print("PASS: matching credential detected in memory")
print("PASS: matching credential detected in sendto_data")
print("PASS: base64_decoded transformation preserved")
print("PASS: observations belong to the same process image")
print("PASS: observed_at and observed_in evidence edges")
print("PASS: D1 Authorization header regression")
PY
