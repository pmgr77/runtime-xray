#!/bin/sh
set -eu

RUNTIMEXRAY_BIN="${1:-}"
FORK_TEST_BIN="${2:-}"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$FORK_TEST_BIN" ]; then
    echo "Usage: $0 <runtimexray> <fork_test>" >&2
    exit 125
fi

if [ "$(id -u)" -eq 0 ]; then
    RUN_PREFIX=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    RUN_PREFIX="sudo -n"
else
    echo "Skipping fork test: root or passwordless sudo required." >&2
    exit 125
fi

TMPDIR="$(mktemp -d)"
REPORT="$TMPDIR/report.json"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

$RUN_PREFIX "$RUNTIMEXRAY_BIN" trace \
    --backend ptrace \
    --no-follow-forks \
    --timeout 5 \
    --json "$REPORT" \
    --report /dev/null \
    "$FORK_TEST_BIN"

if [ -n "$RUN_PREFIX" ]; then
    $RUN_PREFIX chown "$(id -u):$(id -g)" "$REPORT" 2>/dev/null || true
fi

python3 - "$REPORT" <<'PYTEST'
import json
import pathlib
import sys

data = json.loads(
    pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
)

observations = data.get("lineage", {}).get("observations", [])

fork_events = [
    obs
    for obs in observations
    if obs.get("type") == "event"
    and obs.get("syscall") in {"fork", "vfork", "clone", "clone3"}
    and isinstance(obs.get("return_value"), int)
    and obs["return_value"] > 0
]

if not fork_events:
    raise SystemExit("FAIL: no successful fork/clone event found")

child_pid = fork_events[0]["return_value"]

child_syscalls = [
    obs
    for obs in observations
    if obs.get("type") == "event"
    and obs.get("syscall") != "process"
    and obs.get("tgid") == child_pid
]

if "absent" == "present":
    if not child_syscalls:
        raise SystemExit(
            f"FAIL: child PID {child_pid} exists, "
            "but no child syscall events were traced"
        )

    print(
        f"PASS: child PID {child_pid} produced "
        f"{len(child_syscalls)} traced syscall events"
    )
else:
    if child_syscalls:
        names = [obs.get("syscall") for obs in child_syscalls]
        raise SystemExit(
            f"FAIL: child PID {child_pid} was traced despite "
            f"--no-follow-forks: {names}"
        )

    print(
        f"PASS: child PID {child_pid} is known from fork, "
        "but none of its syscalls were traced"
    )
PYTEST
