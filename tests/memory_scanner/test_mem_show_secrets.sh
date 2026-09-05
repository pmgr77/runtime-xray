#!/bin/sh
# Test that --show-secrets reveals the raw secret value

RUNTIMEXRAY_BIN="$1"
if [ -z "$RUNTIMEXRAY_BIN" ]; then
    echo "Usage: $0 <path-to-runtimexray>"
    exit 1
fi

SECRET="password=cli_secret_test"

# Start a short-lived background process with the secret in its command line.
# Redirect output to /dev/null so it does not keep the test pipe open.
/bin/sh -c 'sleep 1' "$SECRET" >/dev/null 2>&1 &
pid=$!

trap 'kill $pid 2>/dev/null' EXIT

sleep 0.5   # give it a moment to appear in /proc

output="$("$RUNTIMEXRAY_BIN" mem --show-secrets "$pid" 2>&1)"
status=$?
if [ $status -ne 0 ]; then
    echo "runtimexray mem exited with status $status"
    echo "$output"
    exit 1
fi

# Check that the raw secret appears in the output
if echo "$output" | grep -q "$SECRET"; then
    exit 0
else
    echo "Raw secret not found with --show-secrets:"
    echo "$output"
    exit 1
fi