#!/usr/bin/env python3
# JSON validation for `runtimexray mem` with controlled cmdline evidence.

import json
import subprocess
import sys
import time


def require(condition, message):
    if not condition:
        print(message)
        sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print("Usage: json_validation_mem.py <runtimexray_binary>")
        sys.exit(1)

    runtimexray_bin = sys.argv[1]
    secret = "password=json_test_secret"

    process = subprocess.Popen(
        ["/bin/sh", "-c", "sleep 5", secret],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    try:
        time.sleep(0.5)

        result = subprocess.run(
            [
                runtimexray_bin,
                "mem",
                "--json",
                "/dev/stdout",
                "--report",
                "/dev/null",
                str(process.pid),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        require(
            result.returncode == 0,
            f"Mem command failed with exit code {result.returncode}\n"
            f"stderr:\n{result.stderr}",
        )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            print(f"Invalid JSON: {exc}")
            sys.exit(1)

        required = [
            "schema_version",
            "tool",
            "command",
            "target",
            "findings",
            "summary",
            "lineage",
        ]
        require(all(key in data for key in required), "Missing required fields")
        require(data["schema_version"] == "2.0", "Unexpected schema version")
        require(data["command"] == "mem", "Expected command 'mem'")
        require(isinstance(data["findings"], list), "'findings' must be a list")

        observations = data["lineage"].get("observations", [])
        cmdline = [
            observation
            for observation in observations
            if observation.get("type") == "data"
            and observation.get("data_type") == "cmdline"
            and str(observation.get("fingerprint", "")).startswith("hmac-sha256:")
        ]

        require(cmdline, "No scanner-derived cmdline Data observation found")

        matched = False

        for observation in cmdline:
            seq = observation.get("seq")
            fingerprint = observation.get("fingerprint")

            for finding in data["findings"]:
                attributes = finding.get("attributes", {})

                if (
                    finding.get("kind") == "sensitive_data_presence"
                    and attributes.get("location") == "cmdline"
                    and attributes.get("fingerprint") == fingerprint
                    and seq in finding.get("evidence_observation_seqs", [])
                ):
                    matched = True
                    break

            if matched:
                break

        require(
            matched,
            "No sensitive_data_presence finding references the cmdline observation",
        )

        print("JSON mem validation passed.")
    finally:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    main()
