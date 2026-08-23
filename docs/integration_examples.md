# Integration Examples

## Parsing JSON Output

RuntimeXRay can output results in JSON format. Use `--output-format json` with any subcommand.

Example with `mem`:

```bash
runtimexray mem --output-format json 1234 > report.json
```

Then parse with Python:

```python
import json, subprocess

result = subprocess.run(
    ["runtimexray", "mem", "--output-format", "json", "1234"],
    capture_output=True, text=True
)
if result.returncode != 0:
    print("Error:", result.stderr)
    exit(1)

report = json.loads(result.stdout)
for finding in report["findings"]:
    if finding["severity"] in ["Critical", "High"]:
        print(f"High severity: {finding['description']}")
```