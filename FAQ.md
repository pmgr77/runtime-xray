# Frequently Asked Questions

## What is RuntimeXRay?

RuntimeXRay is an **evidence-driven security analysis tool for compiled Linux applications**.

It combines:

- static ELF inspection;
- runtime syscall tracing;
- process and thread lineage;
- process-memory scanning;
- resource tracking;
- graph-based security detection;
- structured findings backed by evidence.

The current target platforms are:

- Linux
- x86_64
- ARM64
- ELF binaries

RuntimeXRay is designed for authorized analysis in controlled environments.

It is not a sandbox, antivirus engine, or formal verifier.

---

## What problem does RuntimeXRay solve?

Modern applications are increasingly difficult to understand completely.

They may contain:

- AI-generated code;
- legacy code;
- third-party libraries;
- binary-only dependencies;
- dynamically selected code paths;
- configuration-dependent behavior.

Source code tells you what the program *could* do.

RuntimeXRay tries to show what the compiled application **actually contains** and what it **actually does during an observed execution**.

Its core principle is:

> **Don't tell me my application is insecure — show me why.**

---

## How is RuntimeXRay different from antivirus?

| Antivirus | RuntimeXRay |
|---|---|
| Looks for malware or malicious behavior | Looks for security-relevant properties and runtime evidence in an analyzed application |
| Usually runs continuously | Runs on demand against an authorized target |
| Often produces a malware/safe-style verdict | Produces structured findings backed by observations |
| Focuses on protecting the host | Focuses on understanding the analyzed application |
| Uses signatures, heuristics, reputation, behavior models | Uses ELF inspection, runtime tracing, memory scanning, lineage, and detection rules |

RuntimeXRay does **not** attempt to answer:

```text
clean
infected
malware
safe
```

Instead, it answers narrower questions such as:

- Is PIE enabled?
- Was a sensitive file accessed?
- Was a connection attempted to a security-sensitive service?
- Was a secret-like value observed in memory?
- Was the same exact sensitive value observed at multiple runtime boundaries?
- Did an explicit pipe DataFlow relationship carry the same sensitive value across processes?

---

## Is RuntimeXRay a vulnerability scanner?

Partly, but not in the traditional sense.

RuntimeXRay can identify security-relevant conditions such as:

- missing hardening;
- dangerous imported APIs;
- sensitive-resource access;
- suspicious service connections;
- sensitive-data presence;
- supported sensitive-data flows.

However, a RuntimeXRay Finding does not automatically mean:

- the condition is exploitable;
- the condition is remotely reachable;
- an attacker controls the required input;
- compromise occurred.

RuntimeXRay emphasizes **evidence and traceability** over generic vulnerability labels.

---

## How is RuntimeXRay different from `checksec`?

`checksec` is primarily focused on binary hardening properties.

RuntimeXRay includes similar static checks such as:

- NX;
- PIE;
- RELRO;
- stack canary;

but also adds runtime capabilities:

- ptrace tracing;
- eBPF tracing;
- file access observations;
- network endpoint observations;
- sensitive-value detection;
- memory scanning;
- process/thread lineage;
- FD/resource tracking;
- pipe DataFlow;
- graph-based detection;
- evidence-backed correlation.

A useful mental model is:

> **binary security inspection + runtime observation + memory evidence + lineage**

rather than just a hardening checker.

---

## How does RuntimeXRay help with AI-generated code?

AI-assisted development increases a basic trust problem:

> You may know what the generated source was supposed to do, but do you know what the resulting binary actually does?

RuntimeXRay analyzes the compiled result.

It can help answer questions such as:

- Which security hardening features made it into the binary?
- Which selected dangerous or legacy APIs are imported?
- Which files were actually accessed during this run?
- Which network services were contacted?
- Which sensitive values were observed?
- Did a sensitive value cross a supported runtime boundary?
- Did behavior change between executions or releases?

RuntimeXRay complements source-level AI analysis.

It does not replace source review.

---

## If I have source code, why do I need runtime analysis?

Source code and runtime evidence answer different questions.

Source analysis can reason about possible code paths.

Runtime analysis observes the path that actually executed.

Runtime evidence can reveal things that depend on:

- configuration;
- environment;
- runtime input;
- process topology;
- actual file access;
- actual network behavior;
- dynamic memory state;
- third-party binary behavior.

For example:

```text
Source-level reasoning:
"This code path might send a credential."

Runtime evidence:
"The same exact sensitive value was observed during input,
independently in process memory, and later in an output operation
associated with a socket destination."
```

The second statement is narrower, but it is grounded in observed execution.

---

## Does RuntimeXRay prove that an application is secure?

No.

A clean RuntimeXRay run does not prove that an application is secure.

Dynamic analysis observes only executed paths.

A behavior may be missed because:

- the relevant path was not executed;
- a secret existed outside the capture window;
- a syscall or IPC mechanism is not modeled;
- data was transformed;
- memory access was restricted;
- the backend has a capture limit;
- anti-analysis behavior changed execution.

RuntimeXRay reduces uncertainty.

It does not eliminate it.

---

## Does RuntimeXRay prove exploitability?

No.

A Finding represents a security-relevant conclusion supported by evidence.

For example:

```text
Dangerous API imported
```

does not prove:

```text
Attacker can exploit this binary remotely
```

Likewise:

```text
Sensitive file accessed
```

does not prove:

```text
Credential theft occurred
```

Exploitability remains a separate assessment.

---

## What is data lineage in RuntimeXRay?

RuntimeXRay uses a `LineageGraph` to represent observed relationships.

The graph can contain:

```text
Event observations
Data observations
Static observations
```

and relationships such as:

```text
Calls
Chronological
Causality
DataFlow
ObservedIn
StaticAssociated
```

The goal is to connect evidence rather than report every observation as an unrelated warning.

---

## Does RuntimeXRay already support data lineage?

Yes, in specific evidence-backed forms.

It does **not** yet provide general-purpose taint tracking.

Current supported lineage includes process/resource relationships and specific sensitive-value correlations.

Two important examples are already implemented.

---

## What is the file → memory → socket correlation?

With:

```bash
runtimexray trace --scan-memory /path/to/application
```

RuntimeXRay can correlate a supported sensitive value across:

```text
source file
    ↓
read / receive
    ↓
exact sensitive-value fingerprint
    ↓
independent memory observation
    ↓
write / send
    ↓
socket destination
```

The memory observation must come from an independent memory scan.

RuntimeXRay does not simply assume that a value remained in memory because it was observed in a syscall buffer.

The correlation uses a per-run HMAC fingerprint of the exact sensitive value.

---

## Does that prove exfiltration?

No.

It proves a narrower statement:

> The same exact sensitive value was observed across the supported input, memory, and output evidence points.

It does not prove:

- malicious intent;
- attacker ownership of the destination;
- successful remote receipt;
- exploitation;
- policy violation.

Those require additional context.

---

## What is the cross-process pipe-chain correlation?

RuntimeXRay tracks explicit pipe resources and DataFlow relationships.

It can detect a supported pattern such as:

```text
Process A
    ↓
pipe
    ↓
Process B
    ↓
pipe
    ↓
Process C
```

when the same exact sensitive-value fingerprint is carried across multiple explicit cross-process pipe boundaries.

The rule requires real modeled pipe DataFlow edges.

It does not infer transfer merely because the same string appears in several processes.

---

## Does RuntimeXRay track arbitrary memory copies?

Not yet.

RuntimeXRay currently does not provide universal taint tracking.

It does not reliably reconstruct every:

- `memcpy`;
- register transfer;
- transformation;
- encode/decode step;
- encryption/decryption step;
- arbitrary IPC path.

Broader value-level lineage is planned.

---

## Can RuntimeXRay tell me exactly how long a secret stayed in memory?

Not currently.

RuntimeXRay may observe the same value at multiple scan checkpoints, but that does not automatically prove exact allocation and destruction times.

For example, RuntimeXRay should not currently claim:

```text
"The key lived in memory for exactly 4.7 seconds."
```

unless dedicated lifetime evidence is added in the future.

Memory lifetime tracking is planned.

---

## Can RuntimeXRay see internal library or function calls?

Not generally.

RuntimeXRay currently focuses mainly on:

- syscalls;
- process lifecycle;
- memory observations;
- static binary information.

It does not currently provide arbitrary function-level tracing such as:

```text
SSL_CTX_use_PrivateKey
EVP_EncryptInit
custom_application_function
```

Function-level tracing using mechanisms such as uprobes may be added later.

---

## What does the memory scanner inspect?

The standalone command:

```bash
runtimexray mem <pid>
```

can inspect:

```text
/proc/<pid>/cmdline
/proc/<pid>/environ
readable memory mappings
```

It searches for supported sensitive patterns such as:

- password-like values;
- token/secret-like values;
- API-key-like values;
- private-key markers.

---

## Can memory scanning miss secrets?

Yes.

Possible reasons include:

- the value exists only briefly;
- the process exits;
- access is denied;
- the value is encoded or transformed;
- the format is unknown;
- the scan is limited by `--max-pages`;
- the page changed during scanning;
- the secret exists outside readable mappings.

Memory scanning is evidence collection, not a complete memory-forensics guarantee.

---

## What does `--max-pages` do?

It limits how many readable memory pages RuntimeXRay scans.

Example:

```bash
runtimexray mem --max-pages 500 <pid>
```

Use:

```bash
runtimexray mem --max-pages 0 <pid>
```

to skip normal page scanning and inspect only:

- command line;
- environment.

A low limit may miss secrets later in the process address space.

---

## Are secrets printed in reports?

Not by default.

RuntimeXRay redacts sensitive values.

It uses a per-run HMAC-SHA256 fingerprint so repeated observations of the same exact value can still be correlated.

To deliberately reveal raw values:

```bash
runtimexray mem --show-secrets <pid>
```

or:

```bash
runtimexray trace --show-secrets /path/to/application
```

This should be used only for deliberate local debugging.

Do not enable raw-secret output in normal CI.

---

## Why use HMAC instead of a normal SHA-256 hash?

A plain hash of a low-entropy secret can sometimes be guessed offline by hashing candidate values.

RuntimeXRay instead uses a random per-run HMAC key.

Conceptually:

```text
secret
  ↓
HMAC-SHA256 with random per-run key
  ↓
fingerprint
```

This preserves exact-value correlation inside one run without creating a stable reusable hash of the secret.

Fingerprints are intentionally not stable across different RuntimeXRay runs.

---

## What does the ptrace backend do?

ptrace is the default runtime backend.

It supports:

- x86_64;
- ARM64;
- syscall entry/exit;
- fork;
- vfork;
- clone;
- exec;
- process/thread lifecycle;
- selected target-memory reads.

Example:

```bash
runtimexray trace --backend ptrace /bin/ls
```

ptrace is intrusive and can affect target timing.

A hostile program may also detect that it is being traced.

---

## What does the eBPF backend do?

The eBPF backend uses Linux `raw_syscalls` tracepoints and sends events to userspace through a ring buffer.

Example:

```bash
sudo runtimexray trace --backend ebpf /bin/ls
```

It currently supports x86_64 and ARM64.

Relevant userspace data is captured in the kernel-side tracing path where supported.

This reduces some races associated with reading buffers later.

---

## Is eBPF tracing complete?

No.

Payload capture is bounded.

Current kernel-side limits include:

```text
MAX_PATH      = 256
MAX_PAYLOAD   = 256
MAX_SOCKADDR  = 128
```

Current `writev` handling captures only the first iovec.

So eBPF should not be interpreted as recording arbitrary complete syscall payloads.

---

## Does eBPF require root?

Currently, normally yes.

The backend requires access to:

- the BPF subsystem;
- tracefs;
- required tracepoints;
- kernel capabilities.

Actual availability depends on the host kernel and security configuration.

---

## Which backend is better: ptrace or eBPF?

They have different tradeoffs.

### ptrace

Advantages:

- detailed syscall entry/exit control;
- direct process-memory access;
- mature process tracing semantics.

Disadvantages:

- intrusive;
- higher overhead;
- affects timing;
- detectable by anti-debugging techniques.

### eBPF

Advantages:

- kernel-side observation;
- less direct interference with the target;
- useful for runtime event collection.

Disadvantages:

- requires kernel support and privileges;
- payload capture is bounded;
- behavior depends on kernel configuration;
- verifier constraints affect implementation.

RuntimeXRay normalizes both backends into the same higher-level evidence model where possible.

---

## Does `--no-follow-forks` mean RuntimeXRay knows nothing about child processes?

No.

Even when child tracing is disabled, the parent `fork/clone` event can reveal that a child process was created.

RuntimeXRay may therefore know that the child exists.

The important difference is:

```text
--follow-forks
    child syscall events are traced

--no-follow-forks
    child syscall events are not traced
```

Process existence and process tracing are not the same thing.

---

## How does RuntimeXRay identify processes?

RuntimeXRay does not rely only on raw PID/TGID.

Linux may reuse process IDs.

RuntimeXRay therefore assigns a local:

```text
process_instance_id
```

to each observed process lifetime.

It also tracks:

```text
exec_generation
```

to distinguish different executable images inside the same process lifetime after successful `exec`.

---

## Why track file-descriptor resources?

FD numbers are temporary.

For example:

```text
fd 4
```

may refer to one resource now and a completely different resource later.

RuntimeXRay therefore tracks logical resources using:

```text
resource_id
resource_type
resource_role
```

This allows it to reason about:

- pipe ends;
- dup operations;
- fork inheritance;
- exec inheritance;
- `FD_CLOEXEC`;
- data movement.

---

## What does a Finding contain?

A current RuntimeXRay Finding may include:

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

A Finding is a structured security conclusion.

It references graph evidence instead of duplicating everything inside the Finding itself.

---

## Does every Finding include remediation advice?

No.

Some findings may include recommendation data in their attributes, but remediation is not a mandatory field for every Finding.

RuntimeXRay should not pretend that every security observation has one universally correct fix.

---

## Does every Finding include a CWE?

No.

CWEs are attached only where the detection rule considers the relationship justified.

A CWE reference does not automatically mean RuntimeXRay proved an exploitable instance of that weakness.

---

## What is the difference between `rule_id` and `kind`?

`rule_id` identifies the rule implementation.

Example:

```text
builtin.sensitive_file_access
```

`kind` identifies the semantic type of the Finding.

Example:

```text
sensitive_resource_access
```

Consumers should usually use `kind` for semantic processing.

A different compatible rule could theoretically produce the same semantic kind.

---

## What are Primary and Composite detection rules?

RuntimeXRay currently runs detection in two stages.

### Primary

Primary rules analyze the `LineageGraph` directly.

Examples include:

- hardening;
- dangerous APIs;
- sensitive file access;
- network findings;
- sensitive-data presence.

### Composite

Composite rules receive:

```text
LineageGraph
+
frozen Primary Findings
```

and can produce higher-level conclusions.

Examples include:

- sensitive-data flow;
- cross-process pipe-chain correlation.

Rules in the same stage do not consume each other's output.

---

## Can I add custom detection logic?

Yes, at source/build level.

The current extension point is:

```text
IDetectionRule
```

with registration through:

```text
DetectionRuleRegistry
```

A custom rule can implement the same interface as built-in rules.

Dynamic `.so` plugin loading is **not implemented yet**.

For now, external rules require integration and rebuilding.

---

## Does RuntimeXRay use AI?

Not currently as part of the core analysis path.

The core works completely without an AI API key.

A future AI layer may explain existing evidence and Findings.

The intended model is:

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

AI should never become the source of evidence.

---

## Would RuntimeXRay send secrets to an AI provider?

That should not happen by default.

Any future external AI integration should require explicit opt-in and should use redacted evidence by default.

Raw secrets should not silently leave the local analysis environment.

---

## Can I run RuntimeXRay on production servers?

The current primary use case is a **controlled analysis environment**.

Examples:

- development workstation;
- security lab;
- CI runner;
- VM;
- dedicated test system.

ptrace and memory scanning can affect performance and timing.

eBPF is less intrusive in some respects, but RuntimeXRay still does not currently claim production-safe behavior across arbitrary workloads.

---

## Is RuntimeXRay a sandbox?

No.

This is important.

If the analyzed program can:

- access the filesystem;
- use the network;
- spawn processes;
- modify system state;

RuntimeXRay does not automatically prevent it.

Use an appropriate VM, container, sandbox, or dedicated analysis machine when running untrusted binaries.

---

## Can RuntimeXRay analyze a process that is already running?

The current main trace workflow launches the target through RuntimeXRay.

General running-process attach is planned for future work.

The standalone `mem` command can inspect an existing process when permissions allow.

---

## Does RuntimeXRay support Windows or macOS?

Not yet.

Current scope:

```text
Linux + ELF
```

Planned future binary formats include:

- PE / Windows;
- Mach-O / macOS.

---

## How many tests does RuntimeXRay have?

The current core suite contains:

```text
56 tests
```

when ptrace tests are enabled and eBPF runtime tests are excluded.

GitHub Actions runs that core suite natively on:

- x86_64;
- ARM64.

There is also a dedicated eBPF runtime suite containing:

```text
16 tests
```

per architecture.

Those tests execute on:

- x86_64;
- ARM64.

Skipped eBPF runtime tests cause the eBPF CI job to fail.

---

## Why does RuntimeXRay use native ARM64 CI?

Runtime features such as ptrace and process-memory inspection should be tested on the actual architecture.

User-mode emulation can behave differently for low-level kernel interfaces.

RuntimeXRay therefore uses native ARM64 GitHub runners for ARM64 testing.

---

## What does a green CI run prove?

It provides evidence that the tested build and runtime scenarios passed on the CI environments.

It does not prove correctness on:

- every Linux kernel;
- every distribution;
- every CPU;
- every container runtime;
- every target application.

Low-level tracing behavior depends on the host environment.

---

## Can RuntimeXRay replace IDA or Ghidra?

No.

IDA and Ghidra are interactive reverse-engineering platforms.

RuntimeXRay is designed to automatically collect and correlate security-relevant evidence from a compiled application.

They solve different problems.

A reverse engineer may use RuntimeXRay as a first-pass evidence collector, then investigate interesting findings in IDA or Ghidra.

---

## Can RuntimeXRay replace `strace`?

No.

`strace` is an excellent syscall tracing tool.

RuntimeXRay uses syscall evidence as one input but adds higher-level concepts such as:

- process-instance identity;
- resource identity;
- sensitive-data observations;
- HMAC fingerprints;
- DataFlow edges;
- detection rules;
- Findings;
- narratives;
- static binary evidence;
- memory evidence.

`strace` primarily answers:

> Which syscalls happened?

RuntimeXRay aims to answer:

> Which security-relevant relationships can be supported by the observed evidence?

---

## Why not just grep the syscall log?

Because presence is not the same as relationship.

For example, finding:

```text
password=...
```

somewhere in a log and finding:

```text
sendto(...)
```

somewhere else does not prove that the password was sent.

RuntimeXRay tries to require stronger correlation evidence such as:

- exact-value fingerprint;
- resource identity;
- explicit DataFlow;
- process identity;
- observation sequence;
- supporting findings.

The goal is to reduce unsupported conclusions.

---

## What does "evidence-first" mean?

It means RuntimeXRay should prefer:

> "A process connected to 10.0.0.5:22."

over:

> "The application contacted a malicious server."

unless there is evidence supporting the stronger claim.

Likewise:

> "The same exact sensitive value was observed at these three runtime boundaries."

is preferable to:

> "The application exfiltrated a password."

unless the latter can actually be proven.

---

## Where should I start?

Build without eBPF first:

```bash
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_EBPF_BACKEND=OFF

cmake --build build -j"$(nproc)"
```

Try static analysis:

```bash
./build/runtimexray analyze --min-severity Info /bin/ls
```

Then try tracing:

```bash
./build/runtimexray trace /bin/ls
```

Then memory analysis against a process you are authorized to inspect:

```bash
./build/runtimexray mem <pid>
```

See [README.md](README.md) for the full quick start.

---

## How do I report a normal bug?

Open a GitHub issue with:

- exact command;
- expected behavior;
- actual behavior;
- RuntimeXRay commit/version;
- Linux distribution;
- kernel version;
- architecture;
- backend;
- whether RuntimeXRay was run as root;
- relevant logs.

Do not include real credentials or secret values.

---

## How do I report a security vulnerability in RuntimeXRay?

Do **not** open a public issue.

Report vulnerabilities to:

**security@runtimexray.com**

See [SECURITY.md](SECURITY.md).

---

## Where can I learn more?

- [README](README.md)
- [Architecture](ARCHITECTURE.md)
- [Threat Model](THREAT_MODEL.md)
- [Roadmap](ROADMAP.md)
- [Security Checks](docs/security_checks.md)
- [Integration Examples](docs/integration_examples.md)
- [Contributing](CONTRIBUTING.md)