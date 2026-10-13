# RuntimeXRay Architecture

RuntimeXRay is an evidence-driven security analysis system for compiled Linux applications.

Its architecture separates four responsibilities:

```text
Collection
    ↓
Evidence graph
    ↓
Detection
    ↓
Explanation and reporting
```

This separation is intentional.

Collectors record facts.

Detection rules derive security conclusions from those facts.

Narrative generation explains the conclusions.

Reporters serialize the result.

RuntimeXRay currently supports:

- Linux ELF binaries
- x86_64
- ARM64
- static binary inspection
- ptrace runtime tracing
- eBPF runtime tracing
- process-memory scanning
- graph-based security detection
- text and JSON reporting

---

# 1. High-level architecture

The current processing pipeline is:

```text
                        ┌──────────────────────┐
                        │   Compiled binary    │
                        └──────────┬───────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                    ▼                             ▼
             Static collection             Runtime execution
                    │                             │
                    │                  ┌──────────┴──────────┐
                    │                  │                     │
                    │                  ▼                     ▼
                    │              ptrace backend       eBPF backend
                    │                  │                     │
                    │                  └──────────┬──────────┘
                    │                             │
                    │                             ▼
                    │                      Runtime events
                    │                             │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                           ┌───────────────┐
                           │ LineageGraph  │
                           │               │
                           │ Observations  │
                           │ Edges         │
                           └───────┬───────┘
                                   │
                                   ▼
                      ┌────────────────────────┐
                      │ DetectionRuleRegistry  │
                      └───────────┬────────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │ DetectionEngine │
                         │                 │
                         │ Primary stage   │
                         │ Composite stage │
                         └────────┬────────┘
                                  │
                                  ▼
                              Findings
                                  │
                                  ▼
                         NarrativeBuilder
                                  │
                                  ▼
                     ┌──────────────────────┐
                     │ Text / JSON reports  │
                     └──────────────────────┘
```

Memory scanning participates in this architecture in two ways:

1. through the standalone `mem` command;
2. as an optional evidence source during `trace --scan-memory`.

---

# 2. CLI layer

RuntimeXRay exposes one executable:

```text
runtimexray
```

with three main subcommands:

```text
runtimexray analyze
runtimexray trace
runtimexray mem
```

The commands share common reporting and logging options.

Common options include:

```text
--report FILE
--json FILE
--log-level LEVEL
--log-file FILE
--min-severity LEVEL
--show-secrets
```

The default minimum severity is:

```text
Medium
```

Supported severities are:

```text
Critical
High
Medium
Low
Info
```

The CLI layer is responsible for:

- parsing command-specific arguments;
- applying common options;
- invoking evidence collection;
- running detection;
- filtering findings;
- invoking reporting.

The CLI should not contain security-detection logic itself.

---

# 3. Evidence collection

RuntimeXRay collects observations from three major sources:

```text
Static binary
Runtime tracing
Process memory
```

The important architectural rule is:

> Collection records observations. Collection does not decide whether those observations are security findings.

Security conclusions belong to detection rules.

---

# 4. Static collection

The `analyze` command parses the ELF binary and converts static properties into `Observation` objects.

Examples include:

- ELF class;
- endianness;
- architecture;
- ELF type;
- entry point;
- NX state;
- PIE state;
- RELRO state;
- stack-canary presence;
- imported symbols.

Static observations use:

```text
ObservationType::Static
```

and populate fields such as:

```text
static_field
static_value
static_category
static_description
static_recommendation
cwe_id
```

This means static and runtime information share the same graph representation.

Static analysis does not produce a separate reporting pipeline.

It feeds the same `DetectionEngine` used by runtime evidence.

---

# 5. Dynamic tracing

The `trace` command launches a target using one of two backends:

```text
ptrace
eBPF
```

Both backends produce normalized runtime events that eventually become graph observations.

The goal is to keep backend-specific mechanics below the lineage and detection layers.

---

# 6. Trace backend interface

Tracing backends implement the `ITraceBackend` abstraction.

Backend responsibilities include:

- starting or observing target execution;
- receiving syscall events;
- exposing process and thread identity;
- exposing syscall arguments and return values;
- reporting fork / clone / exec lifecycle events;
- capturing supported userspace data;
- providing memory reads where required by higher layers.

Higher layers should not need to know whether an event originated from ptrace or eBPF unless backend identity itself is relevant.

---

# 7. ptrace backend

The ptrace backend is the default backend.

It supports:

- x86_64;
- ARM64;
- syscall entry and exit;
- fork;
- vfork;
- clone;
- exec;
- thread lifecycle;
- process exit;
- userspace-memory reads;
- child-process following.

The target is launched under tracing with `PTRACE_TRACEME`.

RuntimeXRay enables ptrace options such as:

```text
PTRACE_O_TRACEFORK
PTRACE_O_TRACEVFORK
PTRACE_O_TRACECLONE
PTRACE_O_TRACEEXEC
PTRACE_O_TRACEEXIT
PTRACE_O_TRACESYSGOOD
```

The backend normalizes architecture-specific registers into `SyscallEvent`.

For example:

```text
syscall number
arguments
return value
pid
tid
tgid
event type
```

Architecture-specific register decoding is kept inside the ptrace implementation.

---

# 8. eBPF backend

The eBPF backend uses Linux `raw_syscalls` tracepoints.

The kernel-side BPF program captures supported event data and sends events to userspace through a ring buffer.

The backend currently supports:

- x86_64;
- ARM64;
- syscall events;
- process/thread creation tracking;
- fork-following logic;
- selected path capture;
- selected socket-address capture;
- bounded payload capture.

Relevant userspace data is captured at tracepoint time where supported.

This reduces races caused by attempting to read a syscall buffer later, after the application may already have changed it.

The eBPF backend has deliberate capture limits.

Current examples include:

```text
MAX_PATH      = 256
MAX_PAYLOAD   = 256
MAX_SOCKADDR  = 128
```

`writev` capture currently inspects only the first iovec.

The backend therefore must not be interpreted as arbitrary full-buffer tracing.

The eBPF backend requires:

- kernel eBPF support;
- tracefs access;
- BPF subsystem access;
- sufficient privileges, normally root.

---

# 9. Syscall normalization

RuntimeXRay converts architecture-specific syscall numbers into semantic syscall names.

Examples:

```text
open
openat
read
write
writev
connect
sendto
fork
clone
execve
exit
exit_group
```

Detection logic should use semantic syscall names rather than architecture-specific numbers whenever possible.

This is especially important because syscall numbers differ between x86_64 and ARM64.

---

# 10. LineageGraph

The central evidence structure is:

```cpp
LineageGraph
```

It contains:

```text
observations
edges
summary
```

The graph represents facts collected during one RuntimeXRay analysis.

---

# 11. Observations

An `Observation` represents one observed fact.

Current observation types are:

```cpp
enum class ObservationType {
    Event,
    Data,
    Static
};
```

---

## Event observations

`Event` observations represent runtime behavior.

Examples:

```text
process instance
syscall
fork
exec
read
write
connect
exit
```

Important fields include:

```text
seq
pid
tid
tgid
process_instance_id
exec_generation
program_name
syscall_name
arg0 ... arg5
return_value
start_time
end_time
duration
```

---

## Data observations

`Data` observations represent observed values or sensitive-data evidence.

Examples include:

```text
memory
cmdline
environment
stdout
other sensitive buffers
```

Important fields include:

```text
data_type
fingerprint
secret_type
address
size
source
```

Sensitive values may also carry redacted presentation data.

Raw secret disclosure is controlled by reporting options.

---

## Static observations

`Static` observations represent properties discovered from binary inspection.

Examples:

```text
NX
PIE
RELRO
stack canary
dangerous imported API
```

---

# 12. Stable observation identity

Each observation receives a stable per-analysis sequence number:

```text
Observation::seq
```

Sequence numbers are used when findings reference evidence.

Findings never rely on graph vector indices as stable public identities.

This distinction is important because vector indices are an internal implementation detail.

---

# 13. Process identity

Linux PID values alone are not enough to model long-running traces correctly because PID/TGID values may be reused.

RuntimeXRay therefore assigns a local process lifetime identity:

```text
process_instance_id
```

A process instance represents one observed lifetime of one Linux thread group.

If Linux later reuses the same TGID, RuntimeXRay creates a new process instance.

---

# 14. Exec generations

A process may replace its executable image through `exec`.

RuntimeXRay tracks:

```text
exec_generation
```

inside one process instance.

Conceptually:

```text
process_instance_id = 7
    exec_generation = 0
        original image

    exec_generation = 1
        first successful exec

    exec_generation = 2
        second successful exec
```

This prevents pre-exec and post-exec activity from being incorrectly treated as one unchanged executable image.

---

# 15. Thread identity

RuntimeXRay distinguishes:

```text
tid
tgid
```

A process node represents a Linux thread group.

Individual syscall events retain the TID that generated them.

This allows RuntimeXRay to model:

- worker threads;
- thread creation;
- thread exit;
- process leader exit;
- successful exec from a non-leader thread.

---

# 16. Process nodes

Process lifetime is represented by special Event observations where:

```text
syscall_name == "process"
```

These nodes represent process instances rather than real syscalls.

Other syscall observations are linked to their process node.

---

# 17. Edges

A `LineageEdge` represents an explicit relationship between two observations.

Current relation types are:

```cpp
Chronological
Causality
DataFlow
Calls
ObservedIn
StaticAssociated
```

---

## Calls

Example:

```text
Process instance
      │
      └── Calls ──> read()
```

This connects process identity to syscall activity.

---

## Chronological

Example:

```text
read()
  │
  └── Chronological ──> write()
```

This represents observed event ordering.

Chronological ordering is not automatically equivalent to causality.

---

## Causality

Example:

```text
parent process
      │
      └── Causality ──> child process
```

Used for relationships such as process creation.

---

## DataFlow

A `DataFlow` edge is stronger.

It represents explicit evidence that data crossed a modeled runtime resource.

Current important support includes pipe dataflow.

Example:

```text
Process A write(pipe)
        │
        └── DataFlow ──> Process B read(pipe)
```

RuntimeXRay does not create DataFlow edges merely because two observations contain identical strings.

The relationship must be justified by modeled resource evidence.

---

# 18. Resource identity

RuntimeXRay assigns local runtime resource identities:

```text
resource_id
resource_type
resource_role
```

For a pipe:

```text
read fd 4
    resource_id = 7
    resource_type = pipe
    resource_role = read

write fd 5
    resource_id = 7
    resource_type = pipe
    resource_role = write
```

Both descriptors refer to the same modeled resource.

This allows RuntimeXRay to reason about data movement independently of raw FD numbers.

---

# 19. File-descriptor state

RuntimeXRay tracks selected FD relationships across:

- `pipe`;
- `pipe2`;
- `dup`;
- `dup2`;
- `dup3`;
- `fcntl` duplication;
- `close`;
- `open`;
- `openat`;
- fork inheritance;
- exec inheritance;
- `FD_CLOEXEC`.

This state allows later observations to be associated with the correct runtime resource.

FD number alone is not treated as permanent resource identity.

---

# 20. Pipe DataFlow

For pipe operations, RuntimeXRay can associate a write and read when the evidence supports the relationship.

A supported link requires compatible information such as:

- same pipe `resource_id`;
- write side vs read side;
- matching sensitive-value fingerprint;
- valid temporal relationship;
- successful transfer.

A generated edge looks conceptually like:

```text
write observation
       │
       │ DataFlow
       ▼
read observation
```

This is stronger than simple temporal proximity.

---

# 21. Memory scanning

Memory scanning is implemented independently from syscall tracing.

The standalone command:

```text
runtimexray mem
```

can inspect:

```text
/proc/<pid>/cmdline
/proc/<pid>/environ
readable process mappings
```

Memory observations are added as `Data` observations.

During tracing, memory scanning can also be enabled using:

```text
--scan-memory
```

This allows a sensitive value seen in syscall evidence to be independently observed in process memory.

---

# 22. Secret fingerprints

RuntimeXRay uses a per-run HMAC-SHA256 fingerprint for exact sensitive-value identity.

Conceptually:

```text
secret
   │
   ▼
per-run HMAC-SHA256
   │
   ▼
fingerprint
```

The random HMAC key is different for each RuntimeXRay execution.

This design provides two useful properties:

1. identical sensitive values within one run produce the same fingerprint;
2. the raw secret does not need to appear in normal reports.

Fingerprints are intended for correlation inside one analysis.

They are not persistent global identifiers.

---

# 23. Detection architecture

Evidence collection and security detection are deliberately separate.

The graph answers:

> What was observed?

Detection rules answer:

> What security-relevant condition can be concluded from those observations?

The current detection architecture consists of:

```text
DetectionRuleRegistry
DetectionEngine
IDetectionRule
DetectionContext
Finding
```

---

# 24. IDetectionRule

All detection logic implements:

```cpp
IDetectionRule
```

Each rule provides:

```text
id()
description()
stage()
detect()
```

A rule returns complete `Finding` objects.

There is no intermediate analyzer-specific finding format.

---

# 25. Detection stages

RuntimeXRay currently supports two detection stages:

```cpp
DetectionStage::Primary
DetectionStage::Composite
```

---

## Primary stage

Primary rules derive findings directly from graph evidence.

Conceptually:

```text
LineageGraph
     │
     ▼
Primary rule
     │
     ▼
Finding
```

Examples include:

- hardening state;
- dangerous imported API;
- sensitive-file access;
- suspicious network service connection;
- sensitive-data presence.

---

## Composite stage

Composite rules can consume:

```text
LineageGraph
+
frozen Primary-stage Findings
```

Conceptually:

```text
LineageGraph
      +
Primary Findings
      │
      ▼
Composite rule
      │
      ▼
Higher-level Finding
```

Composite rules allow higher-level security conclusions without duplicating lower-level classification logic.

---

# 26. Stage isolation

Rules in the same stage do not consume each other's output.

Every rule in one stage receives the same frozen input context.

This prevents rule registration or execution order from changing detection semantics.

The sequence is:

```text
run all Primary rules
        │
        ▼
freeze Primary findings
        │
        ▼
run all Composite rules
```

Composite rules cannot see findings produced by other Composite rules during the same stage.

---

# 27. DetectionRuleRegistry

`DetectionRuleRegistry` owns registered rules.

Responsibilities include:

- rule registration;
- rule replacement by stable ID;
- rule removal;
- enable / disable state;
- deterministic rule listing;
- stage filtering.

Rules are sorted by stable rule ID before execution.

This keeps Finding assignment deterministic.

---

# 28. DetectionEngine

`DetectionEngine` orchestrates rule execution.

Responsibilities include:

- constructing read-only `DetectionContext`;
- executing Primary rules;
- freezing Primary results;
- executing Composite rules;
- assigning `finding_id`;
- preserving stage order.

The engine also stamps the producing rule ID onto each Finding.

Rules do not assign their own `finding_id`.

---

# 29. Current built-in rules

Current Primary rules include:

```text
HardeningRule
DangerousApiRule
SensitiveFileAccessRule
NetworkRule
SensitiveDataPresenceRule
```

Current Composite rules include:

```text
SensitiveDataFlowRule
SensitiveValueCrossProcessPipeChainRule
```

Their stable rule IDs are:

```text
builtin.hardening
builtin.dangerous_api
builtin.sensitive_file_access
builtin.network
builtin.sensitive_data_presence
builtin.sensitive_data_flow
builtin.sensitive_value_cross_process_pipe_chain
```

---

# 30. Finding model

A `Finding` is the canonical security conclusion produced by a rule.

Important fields include:

```text
finding_id
rule_id
kind
severity
title
summary
evidence_observation_seqs
evidence_edges
supporting_finding_ids
cwe_ids
attributes
```

---

## finding_id

`finding_id` is unique inside one RuntimeXRay analysis.

It is assigned by `DetectionEngine`.

It is primarily used when one Finding depends on another.

---

## rule_id

`rule_id` identifies the implementation that produced the Finding.

Example:

```text
builtin.sensitive_file_access
```

Consumers should not normally use `rule_id` as the semantic type of a result.

---

## kind

`kind` describes the semantic security condition.

Examples include:

```text
sensitive_resource_access
sensitive_data_presence
sensitive_data_flow
suspicious_network_connection
```

Composite rules should prefer semantic `kind` matching where compatible third-party rules may participate.

---

# 31. Finding evidence

Findings reference graph evidence through stable observation sequence IDs:

```text
evidence_observation_seqs
```

Flow findings can additionally record explicit evidence relationships:

```text
evidence_edges
```

An edge reference contains:

```text
from_seq
to_seq
relation
```

This allows a report consumer to verify which graph evidence supported the conclusion.

---

# 32. Supporting findings

Composite findings may reference Primary findings:

```text
supporting_finding_ids
```

This creates a semantic dependency chain:

```text
Primary Finding A
Primary Finding B
        │
        └───────┐
                ▼
        Composite Finding
```

This is different from graph evidence.

Graph evidence records observed facts.

Supporting findings record derived security conclusions used by a higher-level rule.

---

# 33. Sensitive-data presence

`SensitiveDataPresenceRule` converts sensitive `Data` observations into findings.

A typical result includes attributes such as:

```text
secret_type
location
fingerprint
length
```

and references the source observation using:

```text
evidence_observation_seqs
```

---

# 34. File → memory → socket correlation

`SensitiveDataFlowRule` implements the first strict end-to-end sensitive-object correlation.

The supported evidence shape is:

```text
file
  │
  ▼
read / receive
  │
  ▼
same exact fingerprint
  │
  ▼
independent memory observation
  │
  ▼
write / send
  │
  ▼
socket destination
```

The correlation requires the same per-run fingerprint on:

1. a successful input event;
2. a scanner-derived process-memory observation;
3. an output event.

The memory observation must be independent.

RuntimeXRay does not invent the memory leg from the syscall buffer.

Therefore:

```text
--scan-memory
```

is required for this correlation.

---

# 35. Cross-process pipe-chain detection

`SensitiveValueCrossProcessPipeChainRule` detects a sensitive value moving through multiple explicit process boundaries.

The rule considers explicit pipe `DataFlow` edges.

A simplified example:

```text
Process A
    │
    │ write(pipe 1)
    ▼
Process B
    │
    │ read(pipe 1)
    │
    │ write(pipe 2)
    ▼
Process C
```

The rule groups compatible transfer boundaries by sensitive-value fingerprint and verifies:

- explicit pipe DataFlow edges;
- distinct process instances;
- compatible transfer ordering;
- matching fingerprint;
- at least two cross-process pipe boundaries.

The final Finding records evidence edges and supporting sensitive-data-presence findings where available.

This rule does not treat identical fingerprints in unrelated observations as proof of data transfer.

---

# 36. Narrative generation

Detection rules produce canonical Findings.

Human-readable explanation is a separate layer.

`NarrativeBuilder` consumes:

```text
LineageGraph
Findings
```

and creates `NarrativeStory` structures.

This keeps:

```text
security conclusion
```

separate from:

```text
presentation and explanation
```

A rule should not need to generate a full prose report.

---

# 37. Reporting

RuntimeXRay currently supports:

- human-readable text;
- structured JSON.

Reporting receives:

```text
ReportContext
Findings
optional LineageGraph
Narratives
ReportingOptions
```

The same result can therefore be represented in different output formats without rerunning security detection.

---

# 38. JSON report

JSON reports contain structured sections such as:

```text
schema_version
tool
tool_version
command
target
started_at
duration_ms
findings
summary
narratives
lineage
```

Trace reports may additionally contain fields such as:

```text
backend
timeout_seconds
timed_out
child_output
```

Memory reports may contain scan-specific metadata.

The JSON schema is intended to support CI and programmatic analysis.

---

# 39. Output separation

RuntimeXRay separates:

```text
Findings
Runtime logs
Syscall diagnostics
```

Human-readable findings go to:

```text
stdout
```

by default, or to:

```text
--report FILE
```

JSON goes to:

```text
--json FILE
```

Logs go to:

```text
stderr
```

or:

```text
--log-file FILE
```

Detailed syscall diagnostics are emitted through the logger at Debug level.

They are not part of the Finding report.

---

# 40. Secret redaction

Secret values are hidden by default.

The reporting layer receives:

```text
ReportingOptions::show_secrets
```

Raw secret disclosure requires explicit:

```text
--show-secrets
```

When RuntimeXRay writes raw-secret reports to files it attempts to restrict file permissions to:

```text
0600
```

The normal architecture assumes that fingerprints, metadata, and evidence references are sufficient for correlation without printing raw credentials.

---

# 41. Security boundaries

RuntimeXRay is an observation tool.

It is not a sandbox.

The analyzed target executes with the privileges and external access available in its environment.

Therefore the architecture assumes use in:

- controlled development systems;
- disposable test environments;
- dedicated analysis hosts;
- containers or VMs where appropriate.

Running an untrusted binary directly under RuntimeXRay does not make that binary safe.

---

# 42. Backend limitations

ptrace and eBPF provide different visibility and behavior.

The system should not pretend that they are identical.

Examples:

## ptrace

Advantages:

- detailed syscall entry/exit interaction;
- direct target-memory access;
- mature process-control semantics.

Limitations:

- intrusive;
- changes timing;
- visible to anti-debugging techniques;
- can introduce significant overhead.

## eBPF

Advantages:

- kernel-side observation;
- less intrusive process interaction;
- capture can occur close to the syscall event.

Limitations:

- requires kernel support and privileges;
- capture buffers are bounded;
- verifier constraints affect implementation;
- kernel configuration may disable required features;
- current `writev` payload capture covers only the first iovec.

Higher-level detection must respect these differences.

---

# 43. Extensibility

The current extension model is detection-rule based.

A new rule can implement:

```cpp
IDetectionRule
```

and register with:

```cpp
DetectionRuleRegistry
```

The current repository does not yet provide dynamic external `.so` loading.

Adding a custom rule currently requires integration with the build.

Future work may provide dynamic plugin loading without rebuilding RuntimeXRay.

---

# 44. Testing architecture

RuntimeXRay uses CTest.

The current core suite contains 56 tests when:

```text
ptrace tests enabled
eBPF runtime tests skipped
```

GitHub Actions runs the core suite natively on:

- x86_64;
- ARM64.

A separate CI matrix builds and runs eBPF runtime tests on:

- x86_64;
- ARM64.

The dedicated eBPF set currently contains 16 tests per architecture.

Skipped eBPF runtime tests are treated as CI failures in that job.

The purpose is to distinguish:

```text
backend compiled
```

from:

```text
backend actually executed
```

---

# 45. Architectural principles

RuntimeXRay follows several core principles.

## Evidence before conclusion

No finding should claim more than the collected evidence supports.

---

## Collection is not detection

Collectors record facts.

Detection rules interpret those facts.

---

## Detection is not presentation

Rules produce structured Findings.

Narrative and reporting layers explain them.

---

## Stable identities matter

Graph vector positions are not public identities.

Use:

```text
Observation::seq
Finding::finding_id
process_instance_id
resource_id
```

for stable relationships inside one analysis.

---

## Same value does not automatically mean data flow

Equal fingerprints are useful correlation evidence.

They are not by themselves proof that one observation caused another.

Explicit resource relationships such as pipe DataFlow provide stronger evidence.

---

## Backend-specific syscall numbers stay below semantic layers

Detection should operate on:

```text
clone
read
write
connect
```

rather than hard-coded architecture-specific numbers.

---

## Redaction by default

Sensitive values should not be exposed merely because RuntimeXRay detected them.

---

## Deterministic detection

Rule registration order must not change detection semantics or Finding identities.

---

# 46. Current evolution direction

RuntimeXRay is evolving toward richer evidence correlation.

Near-term architectural work includes:

- additional memory checkpoints;
- broader sensitive-value lineage;
- memory-copy relationships;
- lifetime observations;
- additional resource types;
- richer cross-process propagation;
- static/runtime correlation;
- network-boundary policies;
- stronger narrative generation;
- external detection-rule loading;
- report comparison between builds and releases.

The architecture should remain evidence-first as these capabilities are added.

A future feature should not bypass the graph and detection model merely because it is easier to implement directly inside the CLI or reporter.

---

# 47. Related documentation

- [README.md](README.md) — project overview and quick start
- [ROADMAP.md](ROADMAP.md) — development priorities
- [THREAT_MODEL.md](THREAT_MODEL.md) — assumptions and security limitations
- [FAQ.md](FAQ.md) — common questions
- [docs/security_checks.md](docs/security_checks.md) — detection details
- [docs/integration_examples.md](docs/integration_examples.md) — machine-readable output examples
- [SECURITY.md](SECURITY.md) — vulnerability reporting