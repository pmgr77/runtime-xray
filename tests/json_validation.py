#!/usr/bin/env python3
# JSON output validation script for RuntimeXRay CLI.

import json
import subprocess
import sys


def require(condition, message):
    if not condition:
        print(message)
        sys.exit(1)


def main():
    if len(sys.argv) < 4:
        print("Usage: json_validation.py <expected_command> <runtimexray_binary> <subcommand> [args...]")
        sys.exit(1)

    expected_command = sys.argv[1]
    runtimexray_bin = sys.argv[2]
    subcommand = sys.argv[3]
    args = sys.argv[4:]

    command = [
        runtimexray_bin,
        subcommand,
        "--json",
        "/dev/stdout",
        "--report",
        "/dev/null",
    ] + args

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    require(
        result.returncode == 0,
        f"Command failed with exit code {result.returncode}\nstderr:\n{result.stderr}",
    )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON: {exc}")
        sys.exit(1)

    required_keys = [
        "schema_version",
        "tool",
        "tool_version",
        "command",
        "target",
        "started_at",
        "duration_ms",
        "findings",
        "summary",
    ]

    missing = [key for key in required_keys if key not in data]
    require(not missing, f"Missing required keys: {missing}")

    require(data["schema_version"] == "2.0", "Unexpected schema_version")
    require(data["command"] == expected_command,
            f"Expected command '{expected_command}', got '{data['command']}'")
    require(isinstance(data["findings"], list), "'findings' must be a list")
    require(isinstance(data["summary"], dict), "'summary' must be a dict")
    require("narratives" in data, "Missing narratives")
    require(isinstance(data["narratives"], list), "'narratives' must be a list")

    for index, finding in enumerate(data["findings"]):
        required_finding_keys = [
            "finding_id",
            "rule_id",
            "kind",
            "severity",
            "title",
            "summary",
        ]
        missing = [key for key in required_finding_keys if key not in finding]
        require(
            not missing,
            f"Finding at index {index} missing required fields: {missing}",
        )

    if "lineage" in data:
        lineage = data["lineage"]

        require("summary" in lineage, "Lineage missing summary")
        require("observations" in lineage, "Lineage missing observations")
        require("edges" in lineage, "Lineage missing edges")
        require(isinstance(lineage["observations"], list),
                "lineage.observations must be a list")
        require(isinstance(lineage["edges"], list),
                "lineage.edges must be a list")

        observation_seqs = {
            observation["seq"]
            for observation in lineage["observations"]
        }

        require(0 not in observation_seqs, "Lineage contains zero observation seq")

        for finding in data["findings"]:
            for seq in finding.get("evidence_observation_seqs", []):
                require(
                    seq in observation_seqs,
                    f"Finding references missing observation seq={seq}",
                )

        for narrative in data["narratives"]:
            for statement in narrative.get("statements", []):
                for seq in statement.get("evidence_observation_seqs", []):
                    require(
                        seq in observation_seqs,
                        f"Narrative references missing observation seq={seq}",
                    )

    print("JSON validation passed.")


if __name__ == "__main__":
    main()
