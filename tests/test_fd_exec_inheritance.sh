#!/bin/sh

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

set -u

RUNTIMEXRAY_BIN="${1:-}"
APP="${2:-}"
BACKEND="${3:-ptrace}"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$APP" ]; then
    echo "usage: $0 <runtimexray-bin> <test-app> [ptrace|ebpf]"
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "FAIL: jq is required"
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    echo "FAIL: timeout is required"
    exit 1
fi

RUN_PREFIX=""

case "$BACKEND" in
    ptrace)
        ;;

    ebpf)
        if [ "$(id -u)" -eq 0 ]; then
            RUN_PREFIX=""
        elif sudo -n true >/dev/null 2>&1; then
            RUN_PREFIX="sudo -n"
        else
            echo "SKIP: eBPF test requires root or passwordless sudo"
            exit 125
        fi
        ;;

    *)
        echo "FAIL: unsupported backend: $BACKEND"
        exit 2
        ;;
esac

TMP="$(mktemp -d)"
J="$TMP/report.json"
KEEP="$TMP/keep.txt"
DROP="$TMP/drop.txt"

cleanup()
{
    rm -rf "$TMP"
}

trap cleanup EXIT INT TERM

fail()
{
    echo "FAIL: $1"

    if [ -f "$J" ]; then
        echo "--- report ---"
        cat "$J"
        echo "--- end report ---"
    fi

    exit 1
}

printf 'K' > "$KEEP"
printf 'D' > "$DROP"

timeout 20 \
    $RUN_PREFIX \
    "$RUNTIMEXRAY_BIN" trace \
        --backend "$BACKEND" \
        --follow-forks \
        --json "$J" \
        "$APP" \
        "$KEEP" \
        "$DROP" \
        >/dev/null

RC=$?

if [ "$RC" -ne 0 ]; then
    if [ "$RC" -eq 124 ]; then
        fail "RuntimeXRay timed out"
    fi

    fail "RuntimeXRay exited unsuccessfully with status $RC"
fi

if [ ! -s "$J" ]; then
    fail "JSON report was not created"
fi

#
# FD 200:
#
# Opened before fork, duplicated without CLOEXEC and inherited through exec.
# The post-exec read must retain regular-file provenance.
#
jq -e --arg keep "$KEEP" '
    any(
        .lineage.observations[];

        .exec_generation == 1
        and .syscall == "read"
        and .args[0] == 200
        and .return_value == 1
        and .resource_id != null
        and .resource_type == "file"
        and .resource_role == "read"
        and .source == $keep
    )
' "$J" >/dev/null || {
    fail "inherited fd 200 lost regular-file provenance across exec"
}

echo "inherited regular-file provenance assertion passed"

#
# FD 201:
#
# Created before exec with O_CLOEXEC.
# The child fixture explicitly checks it with:
#
#     fcntl(201, F_GETFD)
#
# and expects EBADF (-9).
#
jq -e '
    any(
        .lineage.observations[];

        .exec_generation == 1
        and .syscall == "fcntl"
        and .args[0] == 201
        and .return_value == -9
    )
' "$J" >/dev/null || {
    fail "CLOEXEC fd 201 survived exec"
}

echo "CLOEXEC assertion passed"

#
# stdin must survive exec as the inherited read side of a pipe.
#
jq -e '
    any(
        .lineage.observations[];

        .exec_generation == 1
        and .syscall == "read"
        and .args[0] == 0
        and .return_value == 1
        and .resource_id != null
        and .resource_type == "pipe"
        and .resource_role == "read"
    )
' "$J" >/dev/null || {
    fail "stdin pipe provenance was not preserved across exec"
}

#
# stdout must survive exec as the inherited write side of a pipe.
#
jq -e '
    any(
        .lineage.observations[];

        .exec_generation == 1
        and .syscall == "write"
        and .args[0] == 1
        and .return_value == 1
        and .resource_id != null
        and .resource_type == "pipe"
        and .resource_role == "write"
    )
' "$J" >/dev/null || {
    fail "stdout pipe provenance was not preserved across exec"
}

echo "stdio pipe inheritance assertions passed"

#
# stderr is redirected before exec to /dev/null.
#
# The inherited descriptor must remain associated with that file resource.
#
jq -e '
    any(
        .lineage.observations[];

        .exec_generation == 1
        and .syscall == "write"
        and .args[0] == 2
        and .return_value == 8
        and .resource_id != null
        and .resource_type == "file"
        and .resource_role == "write"
        and .source == "/dev/null"
    )
' "$J" >/dev/null || {
    fail "stderr /dev/null provenance was not preserved across exec"
}

echo "stderr inheritance assertion passed"

echo "FD EXEC INHERITANCE SEMANTICS OK ($BACKEND)"