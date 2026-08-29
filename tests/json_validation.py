#!/usr/bin/env python3
"""
JSON output validation script for RuntimeXRay CLI.

Usage: json_validation.py <expected_command> <runtimexray_binary> <subcommand> [args...]

The script constructs and runs:
    <runtimexray_binary> <subcommand> --json /dev/stdout [args...]

It validates that the output is valid JSON and contains required fields.
Exits with 0 on success, 1 on failure.
"""

import json
import subprocess
import sys

def main():
    if len(sys.argv) < 4:
        print("Usage: json_validation.py <expected_command> <runtimexray_binary> <subcommand> [args...]")
        sys.exit(1)

    expected_command = sys.argv[1]
    runtimexray_bin = sys.argv[2]
    subcommand = sys.argv[3]
    args = sys.argv[4:]

    command = [runtimexray_bin, subcommand, "--json", "/dev/stdout"] + args

    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        print(f"stderr: {result.stderr}")
        sys.exit(1)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
        sys.exit(1)

    # Validate required top-level keys
    required_keys = [
        "schema_version", "tool", "tool_version", "command", "target",
        "started_at", "duration_ms", "findings", "summary"
    ]
    missing = [k for k in required_keys if k not in data]
    if missing:
        print(f"Missing required keys: {missing}")
        sys.exit(1)

    if data["command"] != expected_command:
        print(f"Expected command '{expected_command}', got '{data['command']}'")
        sys.exit(1)

    if not isinstance(data["findings"], list):
        print("'findings' must be a list")
        sys.exit(1)

    if not isinstance(data["summary"], dict):
        print("'summary' must be a dict")
        sys.exit(1)

    # Optional: verify each finding has severity and description
    for idx, finding in enumerate(data["findings"]):
        if "severity" not in finding or "description" not in finding:
            print(f"Finding at index {idx} missing 'severity' or 'description'")
            sys.exit(1)

    print("JSON validation passed.")
    sys.exit(0)

if __name__ == "__main__":
    main()
