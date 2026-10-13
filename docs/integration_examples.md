# RuntimeXRay Integration Examples

RuntimeXRay provides structured JSON output for integration with:

- CI/CD pipelines;
- security gates;
- automated report processing;
- regression comparison;
- custom tooling;
- evidence visualization.

The current JSON schema version is:

```text
2.0
```

RuntimeXRay separates:

```text
Human-readable report
JSON report
Runtime logs
```

so machine-readable output can be consumed without mixing diagnostic messages into the JSON stream.

---

# Basic JSON output

Use:

```bash
runtimexray analyze \
  --json report.json \
  /bin/ls
```

This writes JSON to:

```text
report.json
```

The normal text report is still written to stdout.

---

# Write both text and JSON reports

```bash
runtimexray analyze \
  --report report.txt \
  --json report.json \
  /bin/ls
```

This produces:

```text
report.txt
report.json
```

Runtime logs remain separate on stderr unless `--log-file` is used.

---

# JSON-only stdout

For shell pipelines, suppress the normal text report and direct JSON to stdout:

```bash
runtimexray analyze \
  --report /dev/null \
  --json /dev/stdout \
  /bin/ls
```

Redirect it to a file:

```bash
runtimexray analyze \
  --report /dev/null \
  --json /dev/stdout \
  /bin/ls \
  > report.json
```

Keep logs separate:

```bash
runtimexray analyze \
  --report /dev/null \
  --json /dev/stdout \
  --log-file runtime.log \
  /bin/ls \
  > report.json
```

---

# Top-level JSON structure

A RuntimeXRay JSON report currently contains fields such as:

```json
{
  "schema_version": "2.0",
  "tool": "RuntimeXRay",
  "tool_version": "...",
  "command": "analyze",
  "target": "/bin/ls",
  "started_at": "2026-10-13T12:00:00Z",
  "duration_ms": 12,
  "findings": [],
  "narratives": [],
  "summary": {},
  "lineage": {}
}
```

The exact content depends on the command and collected evidence.

---

# Common top-level fields

## `schema_version`

Current value:

```text
2.0
```

Consumers should check this field before assuming a particular schema.

---

## `tool`

Tool identity.

---

## `tool_version`

RuntimeXRay version reported by the build.

---

## `command`

One of:

```text
analyze
trace
mem
```

---

## `target`

The analyzed binary, command, or PID representation used by the command.

---

## `started_at`

UTC timestamp in ISO-8601 form.

Example:

```text
2026-10-13T12:00:00Z
```

---

## `duration_ms`

Analysis duration in milliseconds.

---

## `findings`

Array of structured security Findings.

---

## `narratives`

Evidence-backed human-readable story structures generated from Findings and lineage evidence.

---

## `summary`

Aggregated finding counts.

---

## `lineage`

The collected `LineageGraph`, when present.

It contains:

```text
observations
edges
summary
```

---

# Finding structure

A Finding currently contains fields such as:

```json
{
  "finding_id": 1,
  "rule_id": "builtin.sensitive_file_access",
  "kind": "sensitive_resource_access",
  "severity": "Critical",
  "title": "Sensitive file opened",
  "summary": "Process successfully opened a known sensitive filesystem path.",
  "attributes": {
    "path": "/etc/shadow",
    "outcome": "opened",
    "errno": 0
  },
  "evidence_observation_seqs": [
    17
  ],
  "evidence_edges": [],
  "supporting_finding_ids": [],
  "cwe_ids": []
}
```

Consumers should use the structured fields rather than parsing human-readable report text.

---

# Important Finding fields

## `finding_id`

Stable identity of the Finding inside this analysis.

Composite Findings may reference earlier Findings through this value.

---

## `rule_id`

Identifies the detection rule implementation.

Example:

```text
builtin.sensitive_file_access
```

---

## `kind`

Semantic type of the Finding.

Example:

```text
sensitive_resource_access
```

For automation, `kind` is usually more useful than matching the user-facing title.

---

## `severity`

One of:

```text
Critical
High
Medium
Low
Info
```

---

## `title`

Short human-readable name.

---

## `summary`

Concise explanation of what RuntimeXRay concluded.

---

## `attributes`

Rule-specific structured data.

Examples can include:

```text
path
outcome
errno
fingerprint
secret_type
source_file
socket_destination
confidence
resource_ids
process_instance_ids
```

Do not assume every Finding contains the same attributes.

---

## `evidence_observation_seqs`

Observation sequence IDs supporting the Finding.

These values reference:

```text
lineage.observations[].seq
```

They are stable per-analysis identities.

They are not graph vector indices.

---

## `evidence_edges`

Explicit graph relationships supporting a Finding.

Example:

```json
{
  "from_seq": 21,
  "to_seq": 29,
  "relation": "dataflow"
}
```

---

## `supporting_finding_ids`

Composite Findings can reference Primary Findings.

Example:

```json
"supporting_finding_ids": [
  3,
  4,
  5
]
```

---

## `cwe_ids`

Optional CWE references.

Do not assume that every Finding has a CWE.

---

# Summary structure

RuntimeXRay generates counts by severity and semantic kind.

Example:

```json
{
  "summary": {
    "total": 4,
    "by_severity": {
      "Critical": 1,
      "High": 2,
      "Medium": 1
    },
    "by_kind": {
      "sensitive_resource_access": 1,
      "sensitive_data_presence": 2,
      "sensitive_data_flow": 1
    }
  }
}
```

Missing severity or kind categories should normally be interpreted as zero rather than assumed to exist.

---

# Lineage observations

The lineage graph contains observations of three types:

```text
event
data
static
```

Every observation has:

```text
seq
type
pid
tid
tgid
process_instance_id
exec_generation
```

with additional fields depending on its type.

---

# Event observation example

```json
{
  "seq": 12,
  "type": "event",
  "pid": 4201,
  "tid": 4201,
  "tgid": 4201,
  "process_instance_id": 1,
  "exec_generation": 0,
  "syscall": "openat",
  "return_value": 4,
  "is_entry": false,
  "args": [
    0,
    0,
    0,
    0,
    0,
    0
  ],
  "source": "/tmp/credentials.txt"
}
```

Event observations may additionally contain:

```text
program
fingerprint
secret_type
resource_id
resource_type
resource_role
```

depending on the event.

---

# Data observation example

```json
{
  "seq": 25,
  "type": "data",
  "pid": 4201,
  "tid": 4201,
  "tgid": 4201,
  "process_instance_id": 1,
  "exec_generation": 0,
  "data_type": "memory",
  "fingerprint": "hmac-sha256:...",
  "secret_type": "password",
  "address": 140000000000000,
  "size": 24,
  "source": "memory",
  "data_snippet": null
}
```

By default:

```text
data_snippet = null
```

when the underlying snippet may contain the raw secret.

Raw data is shown only when `--show-secrets` is explicitly enabled.

---

# Static observation example

```json
{
  "seq": 3,
  "type": "static",
  "pid": -1,
  "tid": -1,
  "tgid": -1,
  "process_instance_id": 0,
  "exec_generation": 0,
  "field": "RELRO",
  "value": "Full",
  "category": "hardening"
}
```

Static observations may also contain:

```text
description
recommendation
cwe
```

where available.

---

# Lineage edges

Graph relationships appear under:

```text
lineage.edges
```

Example:

```json
{
  "from_seq": 21,
  "to_seq": 29,
  "relation": "dataflow",
  "time_delta_us": 134
}
```

Supported relation names currently include:

```text
chronological
causality
dataflow
calls
observed_in
static_associated
```

Optional:

```text
details
```

may provide additional context.

---

# Important identity rule

External integrations should use:

```text
seq
```

rather than array position.

For example, do **not** assume:

```python
observations[5]
```

means observation ID 5.

Instead:

```python
observation["seq"]
```

is the stable identity used by Findings and edges.

---

# Narrative structure

Narratives are separate from canonical Findings.

A narrative may look like:

```json
{
  "finding_index": 2,
  "title": "Sensitive value observed across a cross-process pipe chain",
  "fingerprint": "hmac-sha256:...",
  "sessions": [
    {
      "process_instance_id": 1,
      "exec_generation": 0,
      "program": "/path/to/program"
    }
  ],
  "statements": [
    {
      "text": "Sensitive value crossed a pipe boundary.",
      "evidence_observation_seqs": [
        21,
        29
      ]
    }
  ]
}
```

Narratives are intended for explanation.

Automation should generally prefer structured Findings and lineage evidence for policy decisions.

---

# Trace-specific metadata

A `trace` report currently includes additional fields such as:

```text
backend
timeout_seconds
timed_out
child_output
```

Example:

```json
{
  "