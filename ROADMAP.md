# RuntimeXRay Roadmap

RuntimeXRay is evolving from binary inspection and syscall tracing toward a broader **evidence-correlation platform for compiled applications**.

The project direction is evidence-first:

> **Collect facts → build relationships → derive findings → explain only what the evidence supports.**

This roadmap separates:

- what already exists;
- what should be completed next;
- what belongs to later technical work;
- what remains long-term vision.

---

# ✅ Implemented

## Unified CLI

RuntimeXRay provides one executable:

```text
runtimexray
```

with three main subcommands:

```text
runtimexray analyze
runtimexray trace
runtimexray mem
```

Common options include:

```text
--report FILE
--json FILE
--log-level LEVEL
--log-file FILE
--min-severity LEVEL
--show-secrets
```

Supported severities:

```text
Critical
High
Medium
Low
Info
```

The default minimum severity is:

```text
Medium
```

---

# Static ELF analysis

Implemented static capabilities include:

- ELF 32-bit and 64-bit parsing;
- architecture detection;
- endianness detection;
- ELF type;
- entry point;
- NX / executable-stack detection;
- PIE detection;
- RELRO:
  - Disabled
  - Partial
  - Full
- stack-canary detection;
- imported dangerous or legacy API detection;
- CWE references where justified;
- severity filtering;
- text and JSON reporting.

Static properties are converted into graph observations and processed by the same detection architecture used for runtime evidence.

---

# Dynamic tracing

RuntimeXRay supports two tracing backends:

```text
ptrace
eBPF
```

Both support x86_64 and ARM64.

Implemented runtime capabilities include:

- syscall observation;
- syscall entry/exit handling;
- process identity;
- thread identity;
- fork;
- vfork;
- clone;
- exec;
- process-instance lifetime;
- exec generations;
- file-path capture;
- file-access outcomes;
- network endpoint capture;
- selected syscall payload inspection;
- timeout support;
- fork-following control;
- text and JSON reports.

---

# ptrace backend

Implemented ptrace capabilities include:

- x86_64 register handling;
- ARM64 register handling;
- syscall normalization;
- process/thread following;
- `PTRACE_O_TRACEFORK`;
- `PTRACE_O_TRACEVFORK`;
- `PTRACE_O_TRACECLONE`;
- `PTRACE_O_TRACEEXEC`;
- `PTRACE_O_TRACEEXIT`;
- target-memory reads.

ptrace is currently the default backend.

---

# eBPF backend

Implemented eBPF capabilities include:

- `raw_syscalls` tracepoints;
- x86_64;
- ARM64;
- ring-buffer event delivery;
- architecture-specific syscall handling;
- PID/process filtering;
- fork/clone following;
- selected path capture;
- socket-address capture;
- bounded payload capture.

Current kernel-side capture limits include:

```text
MAX_PATH      = 256
MAX_PAYLOAD   = 256
MAX_SOCKADDR  = 128
```

`writev` currently captures only the first iovec.

---

# Memory scanning

Implemented memory-analysis capabilities include:

- `/proc/<pid>/maps` parsing;
- readable memory-region discovery;
- `/proc/<pid>/cmdline`;
- `/proc/<pid>/environ`;
- readable memory-page scanning;
- password-like value detection;
- API-key/token/secret-like detection;
- private-key markers;
- page-count reporting;
- `--max-pages`;
- `--max-pages 0` for cmdline/environ-only mode;
- text and JSON reporting.

Memory scanning can also participate in runtime tracing using:

```text
--scan-memory
```

---

# LineageGraph

RuntimeXRay has a unified graph model containing:

```text
Observations
Edges
```

Observation types:

```text
Event
Data
Static
```

Current relationship types:

```text
Chronological
Causality
DataFlow
Calls
ObservedIn
StaticAssociated
```

---

# Stable runtime identities

Implemented identities include:

```text
Observation::seq
process_instance_id
exec_generation
resource_id
Finding::finding_id
```

These reduce reliance on unstable values such as graph vector indices or raw PID reuse.

---

# Process and thread lifecycle

RuntimeXRay currently models:

- Linux TGID/process identity;
- TID/thread identity;
- process lifetime;
- thread exit;
- leader-thread exit;
- fork-created processes;
- clone-created threads;
- exec transitions;
- exec from non-leader threads;
- PID/TGID reuse through separate process instances.

---

# Runtime resource tracking

Implemented FD/resource tracking includes:

- `open`;
- `openat`;
- `close`;
- `pipe`;
- `pipe2`;
- `dup`;
- `dup2`;
- `dup3`;
- selected `fcntl` duplication;
- fork inheritance;
- exec inheritance;
- `FD_CLOEXEC`.

Resource modeling uses:

```text
resource_id
resource_type
resource_role
```

rather than treating an FD number as a permanent identity.

---

# Pipe DataFlow

RuntimeXRay can construct explicit pipe DataFlow relationships.

A supported relationship may connect:

```text
process A write(pipe)
        │
        ▼
process B read(pipe)
```

using:

- shared pipe resource identity;
- write/read roles;
- matching sensitive-value fingerprint;
- transfer timing;
- successful I/O.

This is stronger than correlating events merely because the same value appears in several places.

---

# Sensitive-value fingerprinting

RuntimeXRay uses per-run HMAC-SHA256 fingerprints.

This allows the same exact sensitive value to be correlated during one analysis without printing the secret.

Raw values are redacted by default.

---

# Detection engine

The current security-detection architecture is:

```text
LineageGraph
     │
     ▼
DetectionRuleRegistry
     │
     ▼
DetectionEngine
     │
     ├── Primary stage
     │
     └── Composite stage
     │
     ▼
Findings
```

Rules implement:

```text
IDetectionRule
```

and consume a read-only:

```text
DetectionContext
```

---

# Detection stages

Implemented stages:

```text
Primary
Composite
```

Primary rules derive Findings directly from graph evidence.

Composite rules can additionally consume the frozen Primary-stage Finding set.

Rules in the same stage cannot consume each other's output.

---

# Built-in detection rules

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

Stable built-in rule IDs include:

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

# Structured Findings

A Finding currently supports:

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

This allows Findings to remain structured and traceable to their supporting graph evidence.

---

# Narrative generation

RuntimeXRay separates detection from explanation.

Implemented flow:

```text
Finding
+
LineageGraph
     │
     ▼
NarrativeBuilder
     │
     ▼
NarrativeStory
```

This keeps canonical security conclusions independent from human-readable presentation.

---

# File → read → memory → send/socket correlation

RuntimeXRay already implements its first strict sensitive-data correlation path.

Supported shape:

```text
source file
    │
    ▼
read / receive
    │
    ▼
exact sensitive-value fingerprint
    │
    ▼
independent process-memory observation
    │
    ▼
write / send
    │
    ▼
socket destination
```

The memory observation must come from the independent memory scanner.

The correlation is not emitted merely because the same value appears in syscall buffers.

---

# Cross-process pipe-chain correlation

RuntimeXRay also supports sensitive-value correlation across multiple explicit cross-process pipe boundaries.

Example:

```text
Process A
    │
    ▼
pipe 1
    │
    ▼
Process B
    │
    ▼
pipe 2
    │
    ▼
Process C
```

The rule requires evidence such as:

- explicit pipe DataFlow edges;
- matching exact fingerprint;
- distinct process instances;
- compatible transfer order;
- at least two cross-process boundaries.

This is not general-purpose taint tracking, but it is a real evidence-backed cross-process lineage capability.

---

# Reporting

Implemented report formats:

```text
text
JSON
```

RuntimeXRay keeps:

```text
findings
runtime logs
syscall diagnostics
```

separate.

Secret values are redacted by default.

---

# CI and test coverage

The current core test suite contains:

```text
56 tests
```

when ptrace tests are enabled and eBPF runtime tests are excluded.

GitHub Actions runs the core suite natively on:

```text
x86_64
ARM64
```

Dedicated eBPF jobs execute:

```text
16 runtime/integration tests
```

on each architecture:

```text
x86_64
ARM64
```

Skipped eBPF runtime tests are treated as CI failures.

---

# 🚀 Near-term priorities

The next phase should focus on increasing **customer-visible evidence value**, not on adding unrelated infrastructure.

---

## 1. Strengthen the sensitive-object evidence chain

Build on the existing:

```text
file → read → memory → send/socket
```

correlation.

Near-term improvements:

- more reliable memory checkpoints;
- additional supported input syscalls;
- additional supported output syscalls;
- richer source metadata;
- richer destination metadata;
- better correlation diagnostics;
- clearer evidence presentation;
- stronger negative tests proving that incomplete chains are not reported.

The objective is to make the existing evidence chain robust before attempting universal dataflow.

---

## 2. Sensitive-value lifetime checkpoints

Add multiple observations of the same sensitive value over time.

Initial goal:

```text
first observed
      │
      ▼
still present
      │
      ▼
still present
      │
      ▼
no longer observed
```

This should initially be presented as **observation checkpoints**, not exact allocation/free lifetime.

Later work can build stronger lifetime conclusions when evidence supports them.

---

## 3. Memory-copy correlation

Investigate supported ways to detect that the same sensitive value appears in multiple memory locations.

Initial focus:

- exact-value copies;
- distinct memory addresses;
- process-local correlation;
- bounded scan checkpoints;
- evidence-backed copy relationships where possible.

Avoid claiming causal copy operations unless actual transfer evidence exists.

---

## 4. Expand resource lineage

Current strong support is focused on files and pipes.

Next resource types to investigate:

- sockets;
- socket pairs;
- redirected stdio;
- additional FD inheritance paths;
- Unix domain sockets;
- selected IPC mechanisms.

The goal is to make resource identity a reusable foundation for stronger DataFlow evidence.

---

## 5. Improve cross-process lineage

Build on current pipe-chain support.

Potential next steps:

- longer process chains;
- multiple branch paths;
- mixed fork/exec topologies;
- session-aware lineage;
- resource transitions through exec;
- richer process-program identity in reports.

---

## 6. Real-world evidence demonstrations

Create reproducible demonstrations showing what RuntimeXRay proves.

Each demonstration should include:

```text
target
scenario
command
observations
finding
evidence graph
limitations
```

Preferred examples should be small enough to reproduce but realistic enough to show customer value.

Avoid demonstrations that depend only on synthetic grep-style matches.

---

## 7. Public benchmark

Build a repeatable benchmark against real open-source binaries.

Possible measurements:

- static findings;
- runtime findings;
- secret observations;
- lineage depth;
- number of evidence-backed correlations;
- ptrace overhead;
- eBPF overhead;
- false-positive examples;
- differences between releases.

The benchmark should measure RuntimeXRay behavior, not merely count warnings.

---

## 8. Release comparison

Add support for comparing two RuntimeXRay reports.

Example questions:

```text
What new findings appeared?
What findings disappeared?
What new files were accessed?
What new destinations were contacted?
Did a secret begin reaching a new sink?
Did hardening regress?
```

This can create strong CI/CD value.

---

## 9. Policy layer

Introduce optional policy on top of evidence.

Examples:

```text
application must not access /etc/shadow
application may only connect to *.company.internal
secret type X must never reach a socket
new Critical findings fail CI
```

Important architectural rule:

> Policy should consume evidence/findings; it should not replace evidence collection.

---

## 10. Safe first release

Prepare a clearly scoped initial release.

Required areas:

- stable versioning;
- build instructions;
- dependency documentation;
- supported-kernel expectations;
- supported architectures;
- privilege requirements;
- threat model;
- secret-redaction guarantees;
- reproducible CI;
- installation guidance;
- release artifacts;
- explicit Linux/ELF scope.

---

# 🔭 Later technical work

## General sensitive-value lineage

Move beyond the currently supported exact-value paths.

Potential areas:

- additional memory copies;
- selected transformations;
- serialization;
- encoding;
- decoding;
- encryption/decryption boundaries;
- additional sinks;
- additional sources.

This should remain evidence-backed.

Do not label matching transformed values as proven lineage without sufficient evidence.

---

# Function-level tracing

Investigate function-level evidence using technologies such as:

- uprobes;
- return probes;
- symbol-aware tracing;
- selected library instrumentation.

Potential use cases:

```text
secret observed
    │
    ▼
crypto API
    │
    ▼
network output
```

This is not implemented yet.

Function-level tracing must remain optional and targeted to avoid turning RuntimeXRay into an unrestricted profiler.

---

# Additional IPC models

Potential future resource support:

- Unix domain sockets;
- socketpair;
- shared memory;
- eventfd;
- memfd;
- message queues;
- selected mmap-backed flows.

Each IPC type should have explicit resource identity and evidence semantics.

---

# Memory-analysis improvements

Potential future work:

- mapping classification;
- anonymous/private/shared distinction;
- RWX mapping detection;
- targeted memory checkpoints;
- secret-location deduplication;
- copy clustering;
- stale-secret detection;
- better secret context;
- entropy-based detection;
- bounded scan prioritization.

---

# Secret detection

Future secret-detection improvements may include:

- high-entropy candidate detection;
- structured credential formats;
- cloud credentials;
- JWT/token formats;
- cryptographic key material;
- user-configurable patterns.

Pattern matching should remain separate from conclusions about exploitability.

---

# Network-boundary analysis

Future network analysis should move beyond fixed sensitive ports.

Potential capabilities:

- allowlists;
- denylists;
- organization-defined network boundaries;
- public vs private destination classification;
- Unix socket policy;
- expected service identity;
- destination changes between releases.

RuntimeXRay should not call a destination "unexpected" until an expectation model exists.

---

# Static/runtime correlation

Combine static and runtime evidence into stronger Findings.

Examples:

```text
dangerous API imported
       +
related runtime behavior observed
       ↓
stronger evidence-backed finding
```

Possible areas:

- imported API + observed execution;
- hardening weakness + exposed runtime behavior;
- binary capability + actual external interaction.

---

# Better narratives

Narrative generation can evolve to explain:

- source;
- process;
- resource;
- transfer;
- sink;
- supporting findings;
- evidence confidence;
- limitations.

Narrative output should never introduce facts absent from Findings or the graph.

---

# HTML reporting

Add HTML output based on the same structured report.

Potential features:

- severity summary;
- process tree;
- evidence timeline;
- graph visualization;
- Finding detail pages;
- source-to-sink chains;
- expandable observation evidence.

HTML should be a presentation layer only.

Detection logic must remain independent.

---

# External detection-rule loading

The current rule model supports compile-time integration through:

```text
IDetectionRule
DetectionRuleRegistry
```

Future work may allow external rule loading from shared libraries.

Possible design requirements:

- stable plugin ABI/API;
- rule identity;
- version compatibility;
- explicit loading;
- trust documentation;
- failure isolation;
- deterministic execution.

Dynamic rule loading is not implemented today.

---

# AI-assisted explanations

Optional AI integration may eventually explain existing evidence and Findings.

The model should remain:

```text
Evidence
   ↓
Detection
   ↓
Findings
   ↓
Narrative
   ↓
Optional AI explanation
```

AI must not become the evidence source.

Requirements should include:

- explicit opt-in;
- redacted input by default;
- no raw-secret upload by default;
- clear provenance;
- no invented Findings;
- no invented confidence.

---

# Anti-analysis awareness

Future ptrace/eBPF work may identify signs of:

- debugger detection;
- `TracerPid` checks;
- self-ptrace;
- timing-based anti-debugging;
- suspicious signal behavior.

The goal should initially be visibility:

> "The target appears to detect tracing."

not an arms race to bypass every anti-analysis technique.

---

# Running-process attach

Potential future support:

```text
runtimexray trace --pid <pid>
```

would allow analysis without launching the process through RuntimeXRay.

This requires careful design for:

- process identity;
- already-existing threads;
- existing FD state;
- missing historical context;
- memory state;
- eBPF filtering;
- ptrace attachment semantics.

An attached process can never provide evidence about events that occurred before attachment.

---

# Additional binary formats

Longer-term static-analysis targets may include:

- PE / Windows;
- Mach-O / macOS.

The graph/detection architecture should remain reusable.

Platform-specific collectors should normalize evidence before detection.

---

# Packaging

Future packaging work may include:

- Debian/Ubuntu packages;
- release tarballs;
- signed release artifacts;
- container image;
- reproducible builds;
- air-gapped installation;
- offline dependency strategy.

---

# 📈 Long-term vision

RuntimeXRay should evolve into a tool that can answer questions such as:

> Where did this sensitive value come from?

> Which process handled it?

> Which runtime resources carried it?

> Where else was it observed?

> Did it cross a process boundary?

> Did it reach a network sink?

> Is this behavior new compared with the previous release?

> Which exact observations support that conclusion?

The long-term product should combine:

```text
binary evidence
runtime evidence
memory evidence
resource lineage
process lineage
security detection
release comparison
policy
```

without losing the project's core principle:

> **Every strong claim should be backed by inspectable evidence.**

---

# Not current goals

The project should avoid expanding into unrelated areas before the evidence model is mature.

RuntimeXRay is not currently intended to become:

- antivirus software;
- EDR;
- a malware sandbox;
- a full debugger;
- a full reverse-engineering suite;
- a generic observability platform;
- a generic eBPF toolkit;
- a source-code SAST engine;
- a universal taint-tracking framework.

These systems may provide useful inspiration or integration points, but RuntimeXRay's value should remain focused.

---

# Development priority rule

When choosing between:

```text
small cosmetic improvement
```

and:

```text
new evidence-backed customer capability
```

the project should prefer the second unless correctness, security, or maintainability requires the first.

A useful feature should answer a concrete security question better than RuntimeXRay could answer it before.

---

# Success criterion

RuntimeXRay succeeds when a user can look at a Finding and ask:

> **Why are you telling me this?**

and RuntimeXRay can point to the exact observations and relationships that justify the answer.

That is the product direction.