# RuntimeXRay

[![Build and Test](https://github.com/pmgr77/runtime-xray/actions/workflows/build.yml/badge.svg)](https://github.com/pmgr77/runtime-xray/actions/workflows/build.yml)

> **Don't tell me my application is insecure — show me why.**  
> **See what an attacker can learn from your application at runtime.**

RuntimeXRay is an **evidence-driven security analysis tool for compiled applications**.

It combines static binary analysis with runtime observation and process-memory inspection to produce security findings backed by evidence observed in the actual compiled application.

The goal is not merely to report that something *might* be dangerous.

The goal is to answer:

> **What happened, where did it happen, and what evidence proves it?**

---

## Why RuntimeXRay?

Software is being produced faster and in larger quantities than ever before.

AI-assisted development, third-party components, legacy code, generated code, binary-only dependencies, and rapidly changing environments make it increasingly difficult to know exactly what ended up inside a deployed application — and what that application actually does while running.

### 🤖 “The AI wrote it. But what did it actually build?”

AI can produce working code in seconds. Tests may pass and the application may ship.

**The problem:** source code describes intended behavior. The compiled program is what actually runs.

RuntimeXRay examines the resulting binary and its execution.

---

### 📦 “You didn’t write that library. Do you really know what it does?”

Modern applications depend on third-party and legacy components that may be difficult or impossible to audit completely.

**The problem:** documentation and source-level analysis tell only part of the story.

RuntimeXRay observes what the resulting process actually accesses, retains, writes, sends, and exposes.

---

### 🧩 “Who still understands this entire application?”

Large applications accumulate years of code, dependencies, configuration paths, generated components, and operational assumptions.

Security decisions increasingly rely on statements such as:

> “That code probably never runs.”

> “That credential should already be gone from memory.”

> “That library should not send anything outside.”

RuntimeXRay is designed to replace assumptions with observable evidence where possible.

---

### ⚡ “Can security review keep up with the release cycle?”

Traditional static analysis can identify potential weaknesses.

Runtime analysis can answer a different question:

> **What actually happened during this execution?**

RuntimeXRay combines both views.

---

## Evidence over warnings

Traditional binary security tools may report findings such as:

```text
Stack canary: disabled
Dangerous API: strcpy
PIE: disabled
```

Those findings are useful, but RuntimeXRay is designed to go further.

It builds a common evidence graph containing static properties, runtime events, process relationships, resources, and sensitive-data observations.

Detection rules then derive security findings from that evidence.

This makes it possible to move from isolated warnings toward statements such as:

```text
Sensitive object observed from file to socket

source_file=/tmp/.../cred.txt
read_syscall=read
memory_observation=0x7f...
send_syscall=sendto
socket_destination=127.0.0.1:45903
confidence=exact-fingerprint-match
```

The important distinction is:

> RuntimeXRay reports **observed evidence**, not inferred intent.

A connection to a network destination does not automatically mean exfiltration.

A sensitive file access does not automatically mean compromise.

A dangerous API import does not prove that the API was used unsafely.

RuntimeXRay records what it can support with evidence and keeps stronger conclusions separate.

---

# What RuntimeXRay can do today

RuntimeXRay currently targets **Linux ELF applications on x86_64 and ARM64**.

It provides three main analysis modes:

```text
runtimexray analyze
runtimexray trace
runtimexray mem
```

---

## Static analysis — `runtimexray analyze`

RuntimeXRay parses ELF binaries and converts static properties into observations that are evaluated by the same detection engine used for runtime evidence.

Currently implemented checks include:

- ELF 32-bit and 64-bit parsing
- Architecture and endianness detection
- ELF type and entry point
- NX / executable-stack detection
- PIE detection
- RELRO detection:
  - Disabled
  - Partial
  - Full
- Stack-canary detection
- Imported dangerous or legacy API detection
- CWE references where justified
- Severity filtering
- Text reports
- JSON reports

Examples:

```bash
./runtimexray analyze /bin/ls
```

Show informational findings too:

```bash
./runtimexray analyze --min-severity Info /bin/ls
```

Write reports to files:

```bash
./runtimexray analyze \
  --report report.txt \
  --json report.json \
  /bin/ls
```

---

## Dynamic tracing — `runtimexray trace`

RuntimeXRay can launch a target under one of two tracing backends:

- **ptrace**
- **eBPF**

Both feed observations into the same lineage and detection model.

Currently implemented runtime capabilities include:

- syscall observation
- process and thread tracking
- fork / clone / vfork following
- exec tracking
- process-instance lifetime tracking
- file-path capture for relevant filesystem operations
- file-access outcome tracking
- network endpoint observation
- sensitive-buffer inspection on supported I/O operations
- runtime resource tracking for file descriptors
- pipe identity and DataFlow relationships
- FD inheritance across fork and exec
- FD aliasing through dup/fcntl families
- sensitive-value fingerprints
- optional process-memory scanning during tracing
- timeout support
- text and JSON reports

Basic trace:

```bash
./runtimexray trace /bin/ls
```

Trace with a timeout:

```bash
./runtimexray trace --timeout 5 /bin/ls
```

Do not follow child processes:

```bash
./runtimexray trace --no-follow-forks /path/to/application
```

Write JSON:

```bash
./runtimexray trace \
  --json trace.json \
  /bin/cat /etc/passwd
```

Show detailed syscall diagnostics:

```bash
./runtimexray trace \
  --log-level debug \
  /bin/ls
```

---

## ptrace backend

`ptrace` is the default tracing backend.

It supports x86_64 and ARM64 and provides RuntimeXRay with detailed syscall and process-lifecycle information.

Example:

```bash
./runtimexray trace \
  --backend ptrace \
  /path/to/application
```

The ptrace backend launches the analyzed target under tracing.

RuntimeXRay is **not a sandbox**. The target still executes with the privileges and environmental access given to it.

---

## eBPF backend

The eBPF backend uses Linux `raw_syscalls` tracepoints and a ring buffer to deliver events to RuntimeXRay.

Relevant userspace data is captured in the kernel-side tracing path where supported, reducing races associated with reading process memory later from userspace.

Example:

```bash
sudo ./runtimexray trace \
  --backend ebpf \
  --timeout 5 \
  /bin/ls
```

The eBPF backend currently requires:

- Linux with eBPF support
- BPF subsystem access
- tracefs access
- sufficient privileges, normally root

It supports x86_64 and ARM64.

eBPF has different capture limits from ptrace. It should not be assumed to observe arbitrary amounts of syscall buffer data.

---

# Memory scanning — `runtimexray mem`

RuntimeXRay can inspect a running process for sensitive values.

Current sources include:

- `/proc/<pid>/cmdline`
- `/proc/<pid>/environ`
- readable process-memory mappings

Current secret detection includes patterns such as:

- password-like values
- API-key-like values
- secret/token-like values
- private-key markers

Example:

```bash
./runtimexray mem <pid>
```

Limit memory scanning:

```bash
./runtimexray mem \
  --max-pages 500 \
  <pid>
```

Skip page scanning and inspect only command line and environment:

```bash
./runtimexray mem \
  --max-pages 0 \
  <pid>
```

Write JSON:

```bash
./runtimexray mem \
  --json mem.json \
  <pid>
```

Access to another process may require elevated privileges depending on Linux security settings such as Yama `ptrace_scope`.

---

# Sensitive-object correlation

RuntimeXRay already implements evidence correlation beyond isolated findings.

## File → read → memory → send/socket

With:

```bash
./runtimexray trace \
  --scan-memory \
  /path/to/application
```

RuntimeXRay can correlate the same detected sensitive object across:

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

The memory observation must come from an independent memory scan.

RuntimeXRay does not infer the memory leg merely because the same data was seen in a syscall buffer.

The correlation therefore requires the sensitive value to be observed independently in process memory.

The current confidence mechanism uses a per-run HMAC fingerprint of the exact detected value.

The raw secret remains redacted by default.

---

## Cross-process pipe-chain correlation

RuntimeXRay can also correlate a sensitive value across explicit pipe DataFlow relationships involving multiple processes.

Conceptually:

```text
Process A
   │
   │ write(pipe)
   ▼
Process B
   │
   │ read(pipe)
   │
   │ write(another pipe)
   ▼
Process C
```

RuntimeXRay tracks pipe resources and explicit DataFlow edges.

A higher-level detection rule can identify a sensitive value traversing multiple cross-process pipe boundaries when the evidence supports the chain.

The rule requires:

- explicit pipe DataFlow relationships
- matching sensitive-value fingerprints
- distinct process instances
- temporally compatible transfers

This is stronger than simply finding the same string in several unrelated observations.

---

# Evidence model

RuntimeXRay stores collected information in a `LineageGraph`.

The graph contains:

- **Observations**
- **Edges**

Observation types currently include:

```text
Event
Data
Static
```

Examples:

```text
Event  → syscall, fork, exec, process activity
Data   → memory secret, environment value, observed sensitive data
Static → ELF hardening property, imported API
```

Relationships include:

```text
Chronological
Causality
DataFlow
Calls
ObservedIn
StaticAssociated
```

The graph is evidence.

Security conclusions are produced separately by detection rules.

---

# Detection architecture

RuntimeXRay uses graph-based detection rules.

The current pipeline is:

```text
            Static ELF collection
                    │
                    │
Process ── ptrace/eBPF
                    │
Memory scanning ────┤
                    ▼
               LineageGraph
          Observations + Edges
                    │
                    ▼
         DetectionRuleRegistry
                    │
                    ▼
            DetectionEngine
          Primary → Composite
                    │
                    ▼
                 Findings
                    │
                    ▼
            NarrativeBuilder
                    │
                    ▼
           Text / JSON reports
```

---

## Primary rules

Primary rules derive findings directly from graph evidence.

Current built-in primary rules include:

- `HardeningRule`
- `DangerousApiRule`
- `SensitiveFileAccessRule`
- `NetworkRule`
- `SensitiveDataPresenceRule`

---

## Composite rules

Composite rules can use:

- the completed `LineageGraph`
- the frozen set of findings produced by the Primary stage

Current built-in composite rules include:

- `SensitiveDataFlowRule`
- `SensitiveValueCrossProcessPipeChainRule`

Rules in the same stage do not consume one another's output.

This keeps detection results independent of rule registration order.

---

## Findings

A `Finding` is the canonical security conclusion produced by a detection rule.

Findings contain structured information including:

- `finding_id`
- `rule_id`
- `kind`
- `severity`
- `title`
- `summary`
- evidence observation references
- evidence edges
- supporting finding IDs
- optional CWE IDs
- rule-specific structured attributes

Findings reference the graph instead of duplicating all evidence inside themselves.

---

# Secret handling

Secret values are redacted by default.

RuntimeXRay uses a per-run HMAC-SHA256 fingerprint for exact-value correlation.

This allows observations of the same sensitive value to be compared without placing the raw secret into normal reports.

To deliberately reveal raw values during local debugging:

```bash
./runtimexray mem \
  --show-secrets \
  <pid>
```

or:

```bash
./runtimexray trace \
  --show-secrets \
  /path/to/application
```

Use `--show-secrets` carefully.

Reports written with raw secrets are created with restrictive permissions where RuntimeXRay controls the output file.

Do not enable raw secret disclosure in normal CI.

---

# Output and logging

RuntimeXRay keeps reporting and diagnostic logging separate.

## Findings

Human-readable findings go to stdout by default:

```bash
./runtimexray analyze /bin/ls
```

Write the text report to a file:

```bash
./runtimexray analyze \
  --report report.txt \
  /bin/ls
```

---

## JSON

Generate machine-readable JSON:

```bash
./runtimexray analyze \
  --json report.json \
  /bin/ls
```

Text output still goes to stdout unless redirected with `--report`.

For JSON-only stdout:

```bash
./runtimexray trace \
  --report /dev/null \
  --json /dev/stdout \
  /bin/ls
```

---

## Runtime logs

Logs go to stderr by default.

Choose a log level:

```bash
./runtimexray trace \
  --log-level debug \
  /bin/ls
```

Write logs separately:

```bash
./runtimexray trace \
  --json report.json \
  --log-level debug \
  --log-file debug.log \
  /bin/ls
```

Supported levels:

```text
error
warn
info
debug
trace
```

---

# Common CLI options

All three commands support the common reporting options:

```text
--report FILE
--json FILE
--log-level LEVEL
--log-file FILE
--min-severity LEVEL
--show-secrets
```

Finding severities are:

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

Use:

```bash
--min-severity Info
```

to include all findings.

---

# Building RuntimeXRay

RuntimeXRay uses CMake and C++17.

## Basic build without eBPF

If you want the simplest build first:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  cmake \
  git \
  python3 \
  libssl-dev
```

Clone and build:

```bash
git clone https://github.com/pmgr77/runtime-xray.git
cd runtime-xray

cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_EBPF_BACKEND=OFF

cmake --build build -j"$(nproc)"
```

Binary:

```text
build/runtimexray
```

---

## Build with eBPF support

Install the additional dependencies:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  cmake \
  git \
  python3 \
  libssl-dev \
  clang \
  libbpf-dev \
  libelf-dev \
  zlib1g-dev \
  xxd
```

Build:

```bash
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_EBPF_BACKEND=ON

cmake --build build -j"$(nproc)"
```

`BUILD_EBPF_BACKEND` is enabled by default, so environments without the eBPF build dependencies should explicitly disable it.

---

# Running the tests

Normal Release test suite:

```bash
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_EBPF_BACKEND=ON \
  -DSKIP_EBPF_TESTS=ON

cmake --build build -j"$(nproc)"

ctest \
  --test-dir build \
  --output-on-failure
```

The current core suite contains **56 tests** when ptrace tests are enabled and eBPF runtime tests are excluded.

GitHub Actions runs the core suite natively on:

- x86_64
- ARM64

The CI also contains dedicated eBPF runtime jobs.

Each eBPF job executes **16 eBPF integration/runtime tests** on:

- x86_64
- ARM64

The eBPF jobs treat skipped runtime tests as CI failures.

This is deliberate: a green eBPF job is intended to mean that the backend actually executed.

---

# Current scope and limitations

RuntimeXRay is under active development.

It is currently intended for authorized analysis in controlled environments.

Important limitations include:

- Linux ELF only
- x86_64 and ARM64 only
- dynamic analysis observes only executed paths
- RuntimeXRay is not a formal verifier
- RuntimeXRay does not prove exploitability
- RuntimeXRay does not provide process isolation
- memory scanning can affect performance
- ptrace can affect timing and process behavior
- eBPF availability depends on kernel configuration and privileges
- syscall payload capture is intentionally bounded
- transformed sensitive values are not generally tracked yet
- arbitrary value propagation is not implemented
- memory lifetime analysis is not implemented yet
- function-level tracing is not implemented yet
- anti-debugging and anti-tracing behavior can reduce visibility
- custom detection rules currently require integration and rebuilding; dynamic external plugin loading is not implemented yet

See [THREAT_MODEL.md](THREAT_MODEL.md) for the detailed security assumptions and limitations.

---

# Current status

## ✅ Available

- ELF static analysis
- NX / PIE / RELRO / stack-canary checks
- dangerous and legacy imported API detection
- ptrace tracing on x86_64 and ARM64
- eBPF tracing on x86_64 and ARM64
- process/thread/fork/exec lineage
- file-access observations
- network endpoint observations
- sensitive-value detection
- process-memory scanning
- FD resource tracking
- pipe DataFlow relationships
- exact sensitive-value HMAC correlation
- file → read → memory → send/socket correlation
- explicit cross-process pipe-chain correlation
- Primary and Composite detection rules
- structured Findings
- evidence-backed narratives
- text reporting
- JSON reporting
- secret redaction by default
- native x86_64 and ARM64 CI
- dedicated eBPF runtime CI

---

## 🧪 Experimental

- sensitive-object correlation
- cross-process value propagation through explicit pipe chains
- memory scanning under large workloads
- broader narrative generation
- eBPF backend behavior across different kernel configurations

These features are implemented and tested, but the supported correlation model is intentionally narrower than general-purpose data-flow or taint tracking.

---

## 📋 Planned

- broader sensitive-value lineage
- memory-copy correlation
- value transformations
- lifetime checkpoints
- additional sinks and sources
- richer cross-process propagation
- network-boundary policies
- static/runtime evidence correlation
- HTML reports
- external/dynamic detection-rule loading
- optional evidence-grounded AI explanations
- PE support
- Mach-O support
- public benchmarks
- improved local and air-gapped packaging
- release-to-release behavioral comparison

---

# Evidence-first AI

RuntimeXRay may eventually use LLMs to explain existing findings in human-readable language.

AI is intended to be an **explanation layer**, not the source of evidence.

The intended model is:

```text
Application
     │
     ▼
Observed evidence
     │
     ▼
Detection rules
     │
     ▼
Findings
     │
     ▼
Narratives
     │
     ▼
Optional AI explanation
```

An AI component must not invent observations, findings, relationships, or confidence.

Raw secrets must not be sent to an external AI service by default.

The current RuntimeXRay core does not require an AI service or API key.

---

# Project architecture

The project is intentionally divided into separate responsibilities:

```text
Collection
    ↓
LineageGraph
    ↓
Detection
    ↓
Findings
    ↓
Narrative
    ↓
Reporting
```

This separation is important.

Collectors record facts.

Detection rules produce security conclusions.

Narrative generation explains those conclusions.

Reporters serialize the result.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed design.

---

# Roadmap

RuntimeXRay is evolving from binary inspection and syscall tracing toward a broader evidence-correlation platform.

Near-term priorities include:

- extending the existing sensitive-object evidence chain
- improving memory checkpoints
- strengthening resource and cross-process lineage
- demonstrating evidence chains on representative real applications
- release comparison and CI workflows
- preparing a safe public release

See [ROADMAP.md](ROADMAP.md).

---

# Documentation

- [Architecture](ARCHITECTURE.md)
- [Threat Model](THREAT_MODEL.md)
- [Roadmap](ROADMAP.md)
- [Security Checks](docs/security_checks.md)
- [FAQ](FAQ.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Governance](GOVERNANCE.md)

Additional integration and extension documentation is being updated to match the current graph-based detection architecture.

---

# Contributing

Contributions are welcome.

Areas of particular interest include:

- C++17
- Linux internals
- ELF analysis
- ptrace
- eBPF
- process and thread lifecycle analysis
- memory analysis
- data-flow correlation
- graph-based security analysis
- security research
- networking
- testing across architectures

Before contributing, see:

[CONTRIBUTING.md](CONTRIBUTING.md)

---

# Security

If you discover a vulnerability in RuntimeXRay itself, please **do not open a public issue**.

Report it responsibly to:

- **security@runtimexray.com** — security vulnerabilities
- **hello@runtimexray.com** — general questions

See:

[SECURITY.md](SECURITY.md)

---

# License

RuntimeXRay is licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE).