# Integration Examples

RuntimeXRay supports machine‑readable JSON output for easy integration into CI/CD pipelines, monitoring systems, and custom tooling.

## JSON Report

Use `--json FILE` (with any subcommand) to write the JSON report to a file. Human‑readable text still goes to stdout (unless you also use `--report`).

```bash
# JSON report plus the default text report on stdout
runtimexray trace --json report.json /bin/ls

# Text report + JSON report
runtimexray trace --report report.txt --json report.json /bin/ls
```

If you want JSON to be printed to stdout, suppress the human-readable report explicitly. Runtime logs remain on stderr.

```bash
runtimexray trace --report /dev/null --json /dev/stdout /bin/ls > report.json 2> debug.log
```

## Python Parsing Example

```python
import json
import subprocess

# Run trace with JSON output to stdout (stderr goes to debug.log)
result = subprocess.run(
    ["runtimexray", "trace", "--report", "/dev/null", "--json", "/dev/stdout", "/bin/ls"],
    capture_output=True,  # captures both stdout and stderr
    text=True
)

    # stdout contains only JSON because the text report is suppressed
report = json.loads(result.stdout)

for finding in report["findings"]:
    if finding["severity"] in ["Critical", "High"]:
        print(f"High severity: {finding['description']}")
        print(f"Evidence: {finding['evidence']}")
```

## Logging and Debugging

Runtime logs are written to stderr (or a file with `--log-file`). Use `--log-level debug` for verbose diagnostic output.

```bash
runtimexray trace --json report.json --log-level debug --log-file debug.log /bin/ls
```

You can then inspect `debug.log` to troubleshoot.

## CI/CD Integration

In a CI pipeline, you can:

- Generate a JSON report and parse it to fail the build if critical findings appear.
- Keep the human‑readable report as an artifact.

```yaml
# GitHub Actions snippet
- name: Scan binary
  run: |
    runtimexray analyze --json report.json --log-level error ./myapp
    jq -e '.findings | any(.severity == "Critical")' report.json
```

## Custom Analyzers

You can extend RuntimeXRay with custom analyzers (see [Extending Analyzers](extending_detectors.md)). All findings from custom analyzers are included in the same JSON report.

## Summary

- Human‑readable report: `--report FILE` (default: stdout).
- JSON report: `--json FILE` (use `/dev/stdout` to print to stdout).
- Runtime logs: `--log-file FILE` (default: stderr).
- Verbose syscall traces: `--log-level debug`.
- Secret values are redacted by default. Do not enable `--show-secrets` in normal CI; use it only for deliberate local debugging.
- **Removed:** `--verbose`, `--output-format`, `--quiet` – their functionality is now covered by the above.
