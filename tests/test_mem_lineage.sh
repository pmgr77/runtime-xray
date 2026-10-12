#!/bin/sh
# Test that mem command produces lineage graph with data observations

set -e

RUNTIMEXRAY_BIN="$1"
if [ -z "$RUNTIMEXRAY_BIN" ]; then
    echo "Usage: $0 <runtimexray>"
    exit 125
fi

# Determine if we need sudo
if [ "$(id -u)" -eq 0 ]; then
    RUN_PREFIX=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    RUN_PREFIX="sudo -n"
else
    echo "Skipping mem lineage test: root or passwordless sudo required."
    exit 125
fi

# Find secret_holder binary
SCRIPT_DIR=$(dirname "$0")
BUILD_DIR="${SCRIPT_DIR}/../build"
SECRET_HOLDER="${BUILD_DIR}/tests/dynamic_analysis/secret_holder"
if [ ! -x "$SECRET_HOLDER" ]; then
    echo "Skipping test: secret_holder not built."
    exit 125
fi

# Set environment secret and run with command-line secret
export ENV_SECRET="password=env345"
"$SECRET_HOLDER" "password=cmd678" &
PID=$!
sleep 2

MAX_PAGES=$(
    python3 - "$PID" <<'PY'
import sys

pid = sys.argv[1]
pages = 0

with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as maps:
    for line in maps:
        parts = line.split()

        if len(parts) < 2:
            continue

        if not parts[1].startswith("r"):
            continue

        start_text, end_text = parts[0].split("-", 1)
        start = int(start_text, 16)
        end = int(end_text, 16)

        pages += (end - start + 4095) // 4096

print(pages)
PY
)

if [ -z "$MAX_PAGES" ] || [ "$MAX_PAGES" -le 0 ]; then
    echo "Failed to determine readable page count for PID $PID"
    kill "$PID" 2>/dev/null || true
    exit 1
fi

echo "Scanning $MAX_PAGES readable pages"

# Run mem with JSON output to stdout and suppress text
OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" mem --json /dev/stdout --report /dev/null --max-pages "$MAX_PAGES" "$PID" 2>&1
)
STATUS=$?
kill $PID 2>/dev/null || true

if [ $STATUS -ne 0 ]; then
    echo "mem failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

# Verify that the mem command produced scanner-derived Data observations.
#
# Secret contents are intentionally not serialized into normal JSON output.
# Presence is represented by structured observation metadata and fingerprint.
if echo "$OUTPUT" | grep -q '"type": "data"' &&
   echo "$OUTPUT" | grep -q '"data_type": "memory"' &&
   echo "$OUTPUT" | grep -q '"kind": "sensitive_data_presence"' &&
   echo "$OUTPUT" | grep -q '"fingerprint": "hmac-sha256:'; then

    echo "Lineage graph contains sensitive memory data observations."
    exit 0
else
    echo "Lineage graph does not contain expected sensitive data observations."
    echo "$OUTPUT"
    exit 1
fi