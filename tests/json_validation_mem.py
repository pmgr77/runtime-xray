#!/usr/bin/env python3
"""
JSON validation for `runtimexray mem` with a controlled process.

Usage: json_validation_mem.py <runtimexray_binary>
"""
import json
import subprocess
import sys
import time
import os

def main():
    if len(sys.argv) != 2:
        print("Usage: json_validation_mem.py <runtimexray_binary>")
        sys.exit(1)

    runtimexray_bin = sys.argv[1]

    # Start a background process with a secret in its command line
    secret = "password=json_test_secret"
    process = subprocess.Popen(
        ["/bin/sh", "-c", f"sleep 5; echo {secret}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )
    pid = process.pid
    time.sleep(0.5)  # give it time to start

    # Run runtimexray mem with JSON output
    mem_cmd = [runtimexray_bin, "mem", "--output-format", "json", str(pid)]
    result = subprocess.run(mem_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Mem command failed with exit code {result.returncode}")
        print(f"stderr: {result.stderr}")
        sys.exit(1)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
        sys.exit(1)

    # Check required fields
    required = ["schema_version", "tool", "command", "target", "findings", "summary"]
    if not all(k in data for k in required):
        print("Missing required fields")
        sys.exit(1)
    if data["command"] != "mem":
        print(f"Expected command 'mem', got '{data['command']}'")
        sys.exit(1)
    if not isinstance(data["findings"], list):
        print("'findings' must be a list")
        sys.exit(1)

    # Optionally check that secret was found (though it may not be in memory)
    # For JSON structure, it's fine if findings is empty.
    print("JSON validation passed.")
    sys.exit(0)

if __name__ == "__main__":
    main()