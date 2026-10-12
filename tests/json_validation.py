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

    command = [runtimexray_bin, subcommand, "--json", "/dev/stdout", "--report", "/dev/null"] + args

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

    # Verify each finding follows the canonical Finding JSON schema.
    for idx, finding in enumerate(data["findings"]):
        required_finding_keys = [
            "finding_id",
            "rule_id",
            "kind",
            "severity",
            "title",
            "summary",
        ]

        missing = [
            key
            for key in required_finding_keys
            if key not in finding
        ]

        if missing:
            print(
                f"Finding at index {idx} missing required fields: "
                f"{missing}"
            )
            sys.exit(1)

    assert data["schema_version"] == "2.0"
    assert "narratives" in data
    assert isinstance(data["narratives"], list)

    if "lineage" in data:
        lineage = data["lineage"]

        assert "summary" in lineage
        assert "observations" in lineage
        assert "edges" in lineage

        assert isinstance(lineage["observations"], list)
        assert isinstance(lineage["edges"], list)

        observation_seqs = {
            obs["seq"]
            for obs in lineage["observations"]
        }

        assert 0 not in observation_seqs

        for finding in data["findings"]:
            for seq in finding.get(
                "evidence_observation_seqs", []
            ):
                assert seq in observation_seqs

        for narrative in data["narratives"]:
            for statement in narrative.get(
                "statements", []
            ):
                for seq in statement.get(
                    "evidence_observation_seqs", []
                ):
                    assert seq in observation_seqs

    print("JSON validation passed.")
    sys.exit(0)

if __name__ == "__main__":
    main()
