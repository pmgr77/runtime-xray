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
#
# Tests FD_CLOEXEC resource-lineage semantics across exec.
#
# Usage:
#   test_cloexec_exec_flow.sh <runtimexray> <fixture> <ptrace|ebpf>

set -eu

XRAY="$1"
TARGET="$2"
BACKEND="$3"

case "$BACKEND" in
    ptrace|ebpf)
        ;;
    *)
        echo "FAIL: unsupported backend: $BACKEND" >&2
        exit 2
        ;;
esac

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

REPORT="$TMPDIR/out.json"

if [ "$BACKEND" = "ebpf" ]; then
    if ! sudo -n true 2>/dev/null; then
        echo "SKIP: passwordless sudo is required for eBPF test" >&2
        exit 125
    fi

    sudo -n "$XRAY" trace \
        --backend ebpf \
        --json "$REPORT" \
        --report /dev/null \
        "$TARGET"
else
    "$XRAY" trace \
        --backend ptrace \
        --json "$REPORT" \
        --report /dev/null \
        "$TARGET"
fi

#
# Find the pipe resource created before exec.
#
PIPE_RESOURCE="$(
    jq -r '
        [
            .lineage.observations[]
            | select(
                .syscall == "pipe2" and
                .exec_generation == 0 and
                .resource_id != null
            )
            | .resource_id
        ][-1] // empty
    ' "$REPORT"
)"

if [ -z "$PIPE_RESOURCE" ]; then
    echo "FAIL: no tracked pipe2 resource before exec" >&2
    exit 1
fi

#
# Find the fd created by:
#
#     fcntl(pipefd[0], F_DUPFD, 110)
#
FCNTL_FD="$(
    jq -r '
        [
            .lineage.observations[]
            | select(
                .syscall == "fcntl" and
                .exec_generation == 0 and
                .return_value >= 110
            )
            | .return_value
        ][0] // empty
    ' "$REPORT"
)"

if [ -z "$FCNTL_FD" ]; then
    echo "FAIL: no F_DUPFD result >= 110 found" >&2
    exit 1
fi

#
# fd 100 was created with:
#
#     dup3(..., 100, O_CLOEXEC)
#
# Kernel must close it during exec.
# RuntimeXRay must therefore NOT attach the old pipe resource to the
# post-exec read(100).
#
if ! jq -e '
    any(
        .lineage.observations[];
        .syscall == "read" and
        .exec_generation == 1 and
        .args[0] == 100 and
        .return_value == -9 and
        (.resource_id // 0) == 0
    )
' "$REPORT" >/dev/null; then
    echo "FAIL: CLOEXEC dup3 fd 100 retained stale pipe resource after exec" >&2
    exit 1
fi

#
# fd 101 was created with:
#
#     dup3(..., 101, 0)
#
# It must survive exec and remain connected to the original pipe resource.
#
if ! jq -e --argjson resource_id "$PIPE_RESOURCE" '
    any(
        .lineage.observations[];
        .syscall == "read" and
        .exec_generation == 1 and
        .args[0] == 101 and
        .return_value == 0 and
        .resource_id == $resource_id and
        .resource_type == "pipe" and
        .resource_role == "read"
    )
' "$REPORT" >/dev/null; then
    echo "FAIL: non-CLOEXEC dup3 fd 101 did not preserve pipe identity across exec" >&2
    exit 1
fi

#
# The F_DUPFD result was subsequently marked with:
#
#     fcntl(fd, F_SETFD, FD_CLOEXEC)
#
# It must also disappear during exec.
#
if ! jq -e --argjson fd "$FCNTL_FD" '
    any(
        .lineage.observations[];
        .syscall == "read" and
        .exec_generation == 1 and
        .args[0] == $fd and
        .return_value == -9 and
        (.resource_id // 0) == 0
    )
' "$REPORT" >/dev/null; then
    echo "FAIL: F_SETFD FD_CLOEXEC fd retained stale pipe resource after exec" >&2
    exit 1
fi

echo "PASS: $BACKEND CLOEXEC resource lifetime across exec"