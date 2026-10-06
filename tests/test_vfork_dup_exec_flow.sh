#!/bin/sh

set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <runtimexray> <parent> <helper> <ptrace|ebpf>" >&2
    exit 2
fi

RUNTIMEXRAY="$1"
PARENT="$2"
HELPER="$3"
BACKEND="$4"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

REPORT="$TMPDIR/out.json"

case "$BACKEND" in
    ptrace|ebpf)
        ;;
    *)
        echo "unsupported backend: $BACKEND" >&2
        exit 2
        ;;
esac

if [ "$BACKEND" = "ebpf" ]; then
    # Determine if we need sudo
    if [ "$(id -u)" -eq 0 ]; then
        RUN_PREFIX=""
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        RUN_PREFIX="sudo -n"
    else
        echo "Skipping eBPF timeout JSON test: root or passwordless sudo required."
        exit 125
    fi

    $RUN_PREFIX "$RUNTIMEXRAY" trace \
        --backend "$BACKEND" \
        --follow-forks \
        --json "$REPORT" \
        "$PARENT" "$HELPER" \
        >/dev/null 2>&1
else
    "$RUNTIMEXRAY" trace \
        --backend "$BACKEND" \
        --follow-forks \
        --json "$REPORT" \
        "$PARENT" "$HELPER" \
        >/dev/null 2>&1
fi

WRITE_INFO="$(
    jq -c '
        .lineage.observations[]
        | select(
            .type == "event"
            and .syscall == "write"
            and (.fingerprint // "") != ""
            and (.resource_type // "") == "pipe"
            and (.resource_role // "") == "write"
        )
        | {
            seq,
            process_instance_id,
            resource_id,
            fingerprint
        }
    ' "$REPORT" | head -n 1
)"

if [ -z "$WRITE_INFO" ]; then
    echo "FAIL: secret-bearing parent pipe write not found" >&2
    exit 1
fi

WRITE_SEQ="$(printf '%s\n' "$WRITE_INFO" | jq -r '.seq')"
PARENT_INSTANCE="$(printf '%s\n' "$WRITE_INFO" | jq -r '.process_instance_id')"
RESOURCE_ID="$(printf '%s\n' "$WRITE_INFO" | jq -r '.resource_id')"
FINGERPRINT="$(printf '%s\n' "$WRITE_INFO" | jq -r '.fingerprint')"

echo "parent write seq=$WRITE_SEQ resource_id=$RESOURCE_ID"

REMAP_INFO="$(
    jq -c \
        --argjson rid "$RESOURCE_ID" '
        .lineage.observations[]
        | select(
            .type == "event"
            and
            (
                .syscall == "dup2"
                or .syscall == "dup3"
            )
            and .args[1] == 0
            and .return_value == 0
            and (.resource_id // 0) == $rid
            and (.resource_type // "") == "pipe"
            and (.resource_role // "") == "read"
        )
        | {
            seq,
            process_instance_id,
            exec_generation,
            syscall,
            resource_id
        }
    ' "$REPORT" | head -n 1
)"

if [ -z "$REMAP_INFO" ]; then
    echo "FAIL: CLONE_VFORK child fd remap did not inherit pipe resource" >&2
    exit 1
fi

echo "child fd remap:"
printf '%s\n' "$REMAP_INFO"

READ_INFO="$(
    jq -c \
        --arg fp "$FINGERPRINT" \
        --argjson rid "$RESOURCE_ID" '
        .lineage.observations[]
        | select(
            .type == "event"
            and .syscall == "read"
            and .args[0] == 0
            and (.fingerprint // "") == $fp
            and (.resource_id // 0) == $rid
            and (.resource_type // "") == "pipe"
            and (.resource_role // "") == "read"
        )
        | {
            seq,
            process_instance_id,
            exec_generation,
            resource_id,
            fingerprint
        }
    ' "$REPORT" | head -n 1
)"

if [ -z "$READ_INFO" ]; then
    echo "FAIL: helper stdin read did not preserve CLONE_VFORK pipe identity" >&2
    exit 1
fi

READ_SEQ="$(printf '%s\n' "$READ_INFO" | jq -r '.seq')"
CHILD_INSTANCE="$(printf '%s\n' "$READ_INFO" | jq -r '.process_instance_id')"
EXEC_GENERATION="$(printf '%s\n' "$READ_INFO" | jq -r '.exec_generation')"

echo "helper read seq=$READ_SEQ resource_id=$RESOURCE_ID"

if [ "$PARENT_INSTANCE" = "$CHILD_INSTANCE" ]; then
    echo "FAIL: helper read remained in parent process instance" >&2
    exit 1
fi

if [ "$EXEC_GENERATION" -lt 1 ]; then
    echo "FAIL: helper read is not in post-exec generation" >&2
    exit 1
fi

if ! jq -e \
    --argjson from "$WRITE_SEQ" \
    --argjson to "$READ_SEQ" '
        .lineage.edges[]
        | select(
            .relation == "dataflow"
            and .from_seq == $from
            and .to_seq == $to
        )
    ' "$REPORT" >/dev/null; then

    echo "FAIL: parent-write -> helper-read DataFlow edge missing" >&2
    exit 1
fi

echo "PASS: CLONE_VFORK pipe resource survives fd remap and exec"