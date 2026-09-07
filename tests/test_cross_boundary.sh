#!/bin/sh
set -e

RUNTIMEXRAY_BIN="$1"
EXEC_TEST_BIN="$2"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$EXEC_TEST_BIN" ]; then
    echo "Usage: $0 <runtimexray> <cross_boundary_test>"
    exit 125
fi

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
        echo "Skipping cross-boundary test: root or passwordless sudo required."
        exit 125
    fi
    RUN_PREFIX="sudo -n"
else
    RUN_PREFIX=""
fi

# Run the trace (timeout 10s is enough; the test program exits quickly)
OUTPUT=$($RUN_PREFIX "$RUNTIMEXRAY_BIN" trace \
    --log-level debug \
    --show-secrets \
    --follow-forks \
    --scan-memory \
    --timeout 10 \
    "$EXEC_TEST_BIN" "password=secret123" 2>&1)
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "Trace failed with status $STATUS"
    echo "$OUTPUT"
    exit 1
fi

echo "=== Checking for cross-boundary evidence ==="

# Extract the fingerprint of the secret (first occurrence) for diagnostic info
FINGERPRINT=$(echo "$OUTPUT" | grep -Eio 'fingerprint[=:][[:space:]]*[a-f0-9:]+' | head -1 | sed -E 's/.*[=:][[:space:]]*//')
if [ -z "$FINGERPRINT" ]; then
    echo "  [WARN] Could not extract fingerprint. Using known secret value for checks."
else
    echo "  [INFO] Extracted fingerprint: $FINGERPRINT"
fi

# Helper: check if a given pattern appears in the output
check_pattern() {
    local desc="$1"
    local pattern="$2"
    if echo "$OUTPUT" | grep -q -E "$pattern"; then
        echo "  [OK] $desc"
        return 0
    else
        echo "  [MISSING] $desc"
        return 1
    fi
}

# 1. Check that the secret was printed to stdout (parent or child)
#    We look for "Location: stdout" in the report, which comes from the write syscall.
check_pattern "Secret found in stdout" "Location: stdout"

# 2. Check that the secret was sent over the network (sendto_data)
check_pattern "Secret found in network send" "Location: sendto_data"

# 3. Optional: check that connect was detected (for completeness)
check_pattern "Network connect detected" "connect.*127.0.0.1:12345"

# 4. Finally, check that the cross‑boundary risk assessment produced the composite finding
if echo "$OUTPUT" | grep -q "Credential crossed an unexpected boundary"; then
    echo "✅ Cross-boundary risk assessment detected exfiltration."
    exit 0
else
    echo "❌ Cross-boundary risk assessment did NOT detect exfiltration."
    echo "--- Output (last 200 lines) ---"
    echo "$OUTPUT" | tail -200
    exit 1
fi