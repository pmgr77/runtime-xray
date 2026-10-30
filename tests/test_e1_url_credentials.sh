
#!/bin/sh
#
# @file    test_e1_url_credentials.sh
# @brief   E1 regression: HTTP URL userinfo credential detection.
#
# @author  Peter Magram
# @date    2026-10-30
# @license Apache-2.0 (see LICENSE)
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
# Requires a local HTTP Basic-auth registry at 127.0.0.1:5000.
# Exit 125 means the required environment is unavailable.
#
# Fingerprint equality establishes correlation, not causality.

set -eu
umask 077

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

skip() {
    echo "SKIP: $1" >&2
    exit 125
}

[ "$#" -eq 1 ] || skip "usage: $0 <runtimexray-binary>"

case "$1" in
    /*) BIN="$1" ;;
    *) BIN="$(pwd)/$1" ;;
esac

[ -x "$BIN" ] || fail "RuntimeXRay binary is not executable"
[ -x /usr/bin/curl ] || skip "/usr/bin/curl is required"

for tool in curl python3 timeout; do
    command -v "$tool" >/dev/null 2>&1 ||
        skip "$tool is required"
done

RUN_AS_ROOT=0

if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 ||
        skip "sudo is unavailable"

    sudo -n true >/dev/null 2>&1 ||
        skip "passwordless sudo is required"

    RUN_AS_ROOT=1
fi

REGISTRY_URL="http://127.0.0.1:5000/v2/"

HTTP_CODE="$(
    curl --disable --noproxy '*' \
        --silent --output /dev/null \
        --max-time 5 \
        --write-out '%{http_code}' \
        "$REGISTRY_URL"
)" || skip "local Docker registry is unavailable"

[ "$HTTP_CODE" = "401" ] ||
    skip "local registry did not return HTTP 401"

TEST_DIR="$(mktemp -d)" || fail "cannot create temporary directory"

cleanup() {
    rm -rf -- "$TEST_DIR"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

CREDENTIALS="$TEST_DIR/credentials.json"
JSON_REPORT="$TEST_DIR/e1.json"
TEXT_REPORT="$TEST_DIR/e1-report.txt"
LOG="$TEST_DIR/trace.log"

# Generate fresh credentials. No developer secrets are used.
# The password uses URL-safe characters and requires no decoding.
URL="$(
    python3 - "$CREDENTIALS" <<'PY'
import json
import os
import secrets
import sys

username = "rxray_e1_" + secrets.token_hex(4)
password = "E1secret_" + secrets.token_hex(12)

fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

with os.fdopen(fd, "w", encoding="utf-8") as out:
    json.dump({"password": password}, out)

print(f"http://{username}:{password}@127.0.0.1:5000/v2/")
PY
)" || fail "cannot generate disposable credentials"

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
    --output /dev/null \
    "$URL"

TRACE_RC=0

if [ "$RUN_AS_ROOT" -eq 1 ]; then
    timeout 120 sudo -n env "HOME=$HOME" \
        "$@" >"$LOG" 2>&1 || TRACE_RC=$?
else
    timeout 120 \
        "$@" >"$LOG" 2>&1 || TRACE_RC=$?
fi

unset URL

[ "$TRACE_RC" -eq 0 ] ||
    fail "RuntimeXRay returned exit code $TRACE_RC"

[ -s "$JSON_REPORT" ] || fail "JSON report missing"
[ -s "$TEXT_REPORT" ] || fail "text report missing"

if [ "$RUN_AS_ROOT" -eq 1 ]; then
    sudo -n chown "$(id -u):$(id -g)" \
        "$JSON_REPORT" "$TEXT_REPORT" ||
        fail "cannot read privileged reports"
fi

python3 - "$CREDENTIALS" "$JSON_REPORT" "$TEXT_REPORT" "$LOG" <<'PY'
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

# Never print the password or fingerprint.
for label, content in (
    ("JSON", json_text),
    ("text report", text_report),
    ("trace log", log_text),
):
    require(password not in content, f"plaintext leaked into {label}")

print("PASS: plaintext credential redaction")

report = json.loads(json_text)
lineage = report.get("lineage", {})
observations = lineage.get("observations", [])
edges = lineage.get("edges", [])

require(isinstance(observations, list) and observations,
        "lineage observations missing")
require(isinstance(edges, list), "lineage edges missing")

seqs = [obs.get("seq") for obs in observations]
require(all(type(seq) is int for seq in seqs),
        "invalid observation sequence")
require(len(seqs) == len(set(seqs)),
        "duplicate observation sequence")


def same_image(a, b):
    return (
        a.get("process_instance_id") is not None
        and a.get("exec_generation") is not None
        and a.get("process_instance_id") == b.get("process_instance_id")
        and a.get("exec_generation") == b.get("exec_generation")
    )


def matches(source, secret_type):
    return [
        obs for obs in observations
        if obs.get("type") == "data"
        and obs.get("source") == source
        and obs.get("secret_type") == secret_type
        and str(obs.get("fingerprint", "")).startswith("hmac-sha256:")
    ]


cmdline = matches("cmdline", "password")
memory = matches("memory", "http_basic_password")
network = matches("sendto_data", "http_basic_password")

require(cmdline, "URL password not detected in cmdline")
require(memory, "password not detected in memory")
require(network, "password not detected in sendto_data")


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
    cmd.get("fingerprint") == mem.get("fingerprint")
    and cmd.get("fingerprint") == sent.get("fingerprint")
    and same_image(cmd, mem)
    and same_image(cmd, sent)
    and sent.get("transformation") == "base64_decoded"
    and mem.get("transformation") == "base64_decoded"
    and has_memory_edge(mem)
    and has_sendto_edge(sent)
    for cmd in cmdline
    for mem in memory
    for sent in network
)

require(
    matched,
    "URL/memory/network correlation or lineage evidence missing"
)

print("PASS: URL password detected in cmdline")
print("PASS: matching credential found in memory")
print("PASS: matching credential found in sendto_data")
print("PASS: Base64 transformation recognized")
print("PASS: process-image identity and evidence edges")
print("PASS: E1 URL credentials regression")
PY
