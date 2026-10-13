# RuntimeXRay Threat Model

RuntimeXRay is an evidence-driven security analysis tool for compiled Linux applications.

Its purpose is to answer questions such as:

> **What security-relevant facts can be observed from this binary and from this execution?**

RuntimeXRay is not a sandbox, antivirus engine, exploit detector, or formal verifier.

It analyzes authorized targets in controlled environments and produces findings backed by collected evidence.

---

# 1. Scope

RuntimeXRay currently targets:

- Linux
- ELF binaries
- x86_64
- ARM64

It combines:

- static ELF analysis
- ptrace-based runtime tracing
- eBPF-based runtime tracing
- process-memory scanning
- event/process/resource lineage
- graph-based detection rules
- evidence-backed findings and narratives

---

# 2. Security objective

The main security objective is:

> **Reduce uncertainty about what a compiled application actually contains and what it actually does during an observed execution.**

RuntimeXRay attempts to make security conclusions traceable back to concrete evidence.

Examples include:

- a binary lacks PIE;
- an imported API is security-sensitive;
- a process attempted to access a sensitive file;
- a process connected to a security-sensitive service;
- a sensitive value was observed in memory;
- the same exact sensitive value was observed across multiple runtime boundaries;
- data crossed an explicit pipe relationship between processes.

RuntimeXRay deliberately avoids treating all observations as proof of compromise.

---

# 3. Evidence model

RuntimeXRay stores observations in a `LineageGraph`.

The graph contains:

```text
Observations
Edges
```

Observation types include:

```text
Event
Data
Static
```

Examples:

```text
Static → NX, PIE, RELRO, imported API
Event  → read, write, connect, fork, exec
Data   → memory secret, cmdline value, environment value
```

Edges represent supported relationships such as:

```text
Calls
Chronological
Causality
DataFlow
ObservedIn
StaticAssociated
```

The graph represents collected facts.

Detection rules derive Findings from those facts.

---

# 4. What RuntimeXRay can currently detect

## Static analysis

The `analyze` command currently supports:

- ELF class detection
- architecture detection
- endianness detection
- ELF type
- entry point
- NX / executable stack
- PIE
- RELRO:
  - Disabled
  - Partial
  - Full
- stack-canary presence
- selected dangerous or legacy imported APIs
- CWE references where supported
- severity filtering
- text and JSON reports

These checks describe properties of the compiled artifact.

They do not prove that a vulnerability is exploitable.

---

# 5. Imported API detection

RuntimeXRay detects selected imported APIs that may deserve security review.

Examples include categories such as:

- unsafe string operations
- shell execution
- insecure temporary-file APIs
- weak randomness
- weak cryptographic algorithms
- deprecated TLS APIs
- unsafe or legacy parsing/conversion APIs
- legacy network-resolution APIs

An imported symbol is evidence that the binary references that API.

It does **not** prove:

- that the API is actually executed;
- that untrusted input reaches it;
- that the call is exploitable;
- that a corresponding CWE is definitely present at runtime.

The finding represents a review signal, not proof of exploitation.

---

# 6. Dynamic tracing

The `trace` command supports two runtime backends:

```text
ptrace
eBPF
```

Current dynamic observation capabilities include:

- syscall activity
- process and thread identity
- fork / clone / vfork
- exec transitions
- process-instance lifetime
- file-path observations
- file-access outcomes
- network endpoint observations
- selected syscall buffer inspection
- FD/resource relationships
- pipe relationships
- sensitive-value fingerprints
- optional memory scanning during tracing
- timeout handling

---

# 7. ptrace visibility

The ptrace backend supports x86_64 and ARM64.

It can observe syscall entry/exit and process lifecycle events.

It can also read selected userspace memory from the traced process.

Security limitations include:

- ptrace is intrusive;
- execution timing changes;
- anti-debugging techniques may detect tracing;
- some targets may behave differently under tracing;
- tracing overhead can be significant;
- visibility depends on the events RuntimeXRay actually handles.

RuntimeXRay does not currently claim resistance to anti-debugging.

---

# 8. eBPF visibility

The eBPF backend uses Linux `raw_syscalls` tracepoints.

It captures supported event data in kernel context and sends it to userspace through a ring buffer.

This can reduce some races associated with reading syscall buffers later.

However, eBPF visibility is intentionally bounded.

Current limits include:

```text
MAX_PATH      = 256 bytes
MAX_PAYLOAD   = 256 bytes
MAX_SOCKADDR  = 128 bytes
```

Current `writev` handling inspects only the first iovec.

Therefore:

> RuntimeXRay does not guarantee that the complete contents of every syscall buffer are observed.

A secret located outside the captured range may be missed.

---

# 9. File observations

RuntimeXRay can observe selected filesystem operations such as:

```text
open
openat
```

and associate paths and outcomes with the corresponding syscall observation.

Detection rules may classify some paths as security-sensitive.

Examples include:

- credential files
- private keys
- system authentication files
- other configured sensitive resources

A file-access finding means:

> The observed process attempted or completed an operation involving a path classified as security-sensitive.

It does not automatically mean:

- the content was stolen;
- the process was malicious;
- sensitive data was successfully read;
- the access violated policy.

Outcome information should be considered separately.

---

# 10. Network observations

RuntimeXRay can observe selected network operations and decode supported endpoints.

The current `NetworkRule` flags connections to selected security-sensitive service ports.

Examples currently include:

```text
22
3389
445
1433
3306
```

A finding means:

> The process attempted a connection to a service port classified by the rule as security-sensitive.

It does not prove:

- that the destination was malicious;
- that data was exfiltrated;
- that authentication succeeded;
- that the connection itself is unsafe.

The current implementation is service-port based, not organizational policy based.

RuntimeXRay does not yet know whether an endpoint is "expected" or "unexpected" for a particular application unless such policy is added externally in the future.

---

# 11. Sensitive-value detection

RuntimeXRay detects selected secret-like patterns.

Current examples include values resembling:

- passwords
- API keys
- tokens
- secrets
- private-key markers

Detection is pattern-based.

Therefore it can produce:

- false positives;
- false negatives.

Unknown formats, obfuscated values, encoded values, transformed values, or secrets outside capture windows may be missed.

RuntimeXRay does not currently provide universal secret discovery.

---

# 12. Memory scanning

The `mem` command can inspect:

```text
/proc/<pid>/cmdline
/proc/<pid>/environ
readable process mappings
```

RuntimeXRay scans readable memory pages for supported sensitive patterns.

Important limitations:

- permissions may prevent memory access;
- Linux Yama `ptrace_scope` may restrict access;
- a process may exit during scanning;
- mappings may change while scanning;
- secrets may appear only briefly;
- secrets may exist outside the configured scan window;
- transformed or encoded secrets may not match known patterns;
- memory scanning is not atomic.

The `--max-pages` option can intentionally limit scanning.

A low value may miss data in later regions.

`--max-pages 0` skips page scanning entirely and scans only command line and environment.

---

# 13. Secret fingerprinting

RuntimeXRay uses per-run HMAC-SHA256 fingerprints for exact sensitive-value correlation.

Conceptually:

```text
secret value
     │
     ▼
per-run HMAC-SHA256
     │
     ▼
fingerprint
```

The fingerprint allows RuntimeXRay to recognize repeated observations of the same exact value during one analysis.

This design does not provide:

- fuzzy matching;
- transformed-value tracking;
- cross-run identity;
- cryptographic proof that two different representations derive from the same original secret.

Fingerprints are correlation identifiers, not persistent hashes intended for external databases.

---

# 14. Secret redaction

Secrets are redacted by default.

Raw secret disclosure requires:

```text
--show-secrets
```

RuntimeXRay is designed so that most correlation can be performed using metadata and fingerprints instead of raw values.

Users should assume that enabling raw-secret output creates sensitive artifacts.

Do not enable `--show-secrets` in normal CI.

---

# 15. Sensitive-data presence findings

`SensitiveDataPresenceRule` converts supported sensitive `Data` observations into security findings.

A typical finding can reference:

- secret type;
- location;
- fingerprint;
- size/length;
- memory address where relevant;
- source observation.

Such a finding proves only that RuntimeXRay observed a value matching its sensitive-data criteria at that location.

It does not prove:

- that an attacker obtained the value;
- that the value is valid;
- that the credential was used;
- that the credential grants meaningful privileges.

---

# 16. File → memory → socket correlation

RuntimeXRay currently implements a strict sensitive-data correlation path.

The supported chain is conceptually:

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

This correlation is intentionally conservative.

It requires the same exact sensitive-value fingerprint to be observed across supported stages.

The process-memory observation must be produced independently by the memory scanner.

The memory leg is not inferred merely because the same value was observed in a syscall buffer.

This correlation can therefore support a statement such as:

> The same exact sensitive value was observed when read from a file, independently observed in process memory, and later observed in an output operation associated with a socket destination.

It does **not** prove:

- malicious intent;
- credential theft;
- attacker-controlled destination;
- successful remote receipt;
- exploitation.

---

# 17. Cross-process pipe-chain correlation

RuntimeXRay also supports sensitive-value correlation across explicit pipe DataFlow edges.

A simplified flow may look like:

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

`SensitiveValueCrossProcessPipeChainRule` requires evidence such as:

- explicit pipe resource identity;
- explicit DataFlow edges;
- matching sensitive-value fingerprint;
- multiple distinct process instances;
- temporally compatible transfers.

The rule does not infer a cross-process transfer merely because the same fingerprint appears in several processes.

Explicit modeled resource relationships are required.

This substantially reduces false correlation between unrelated observations.

---

# 18. What RuntimeXRay does not yet provide

RuntimeXRay does not currently provide general-purpose taint tracking.

In particular, it does not yet reliably track:

- arbitrary memory copies;
- transformed values;
- encryption/decryption relationships;
- hashes of sensitive values;
- structured serialization/deserialization;
- function-level propagation;
- register-level propagation;
- arbitrary IPC mechanisms;
- lifetime of every sensitive object;
- every copy of a sensitive object.

A current correlation path should not be presented as universal data-flow tracking.

---

# 19. No general memory lifetime tracking

RuntimeXRay may observe a value in memory at one or more scan checkpoints.

It does not currently prove:

```text
"the secret lived in memory for exactly 4.7 seconds"
```

unless future dedicated lifetime-tracking evidence supports such a statement.

Repeated observations can show that the value was present at multiple observation times.

They do not automatically establish exact creation and destruction timestamps.

---

# 20. No function-level tracing

RuntimeXRay currently focuses on syscall and process-level evidence.

It does not currently trace arbitrary function calls such as:

```text
SSL_CTX_use_PrivateKey
EVP_EncryptInit
memcpy
custom business functions
```

unless the effect is visible through supported evidence sources.

Function-level tracing such as uprobes may be added later.

Therefore documentation and findings must not claim that RuntimeXRay observed an arbitrary internal function call unless such evidence actually exists.

---

# 21. No exploitability proof

A RuntimeXRay Finding represents a security-relevant conclusion supported by observations.

A Finding is not automatically proof that:

- exploitation is possible;
- exploitation is practical;
- the issue is remotely reachable;
- an attacker controls the necessary input;
- the behavior violates application intent;
- the finding is a vulnerability.

Exploitability assessment remains a separate task.

---

# 22. No complete execution-path coverage

Dynamic analysis observes only what executes.

Unexecuted code paths are invisible to runtime collection.

A clean runtime trace therefore does not prove that the binary contains no dangerous behavior.

Coverage depends on:

- workload;
- input;
- configuration;
- environment;
- timing;
- feature flags;
- external services;
- process lifetime.

Static analysis helps cover some properties independent of execution, but it also does not provide complete semantic coverage.

---

# 23. No malware verdict

RuntimeXRay is not antivirus software.

It does not provide:

```text
clean
infected
malware
safe
```

verdicts.

A suspicious network connection or sensitive-data observation is evidence that may deserve investigation.

It is not automatically evidence of malware.

---

# 24. No isolation

RuntimeXRay does not isolate the target.

If a target can:

- access files;
- connect to the network;
- modify system state;
- spawn processes;
- consume resources;

it may still do so while being analyzed.

Users should analyze untrusted binaries only inside an appropriate sandbox, VM, container, or dedicated test system.

RuntimeXRay itself does not create that security boundary.

---

# 25. Host privilege model

Some RuntimeXRay features require elevated privileges.

Examples include:

- tracing another process;
- eBPF loading;
- tracefs access;
- reading protected process memory.

Running RuntimeXRay as root increases both visibility and potential impact.

A malicious target executed as root remains dangerous.

Root should be used only in controlled environments.

---

# 26. eBPF trust and kernel dependency

The eBPF backend depends on kernel behavior and configuration.

Possible restrictions include:

- disabled unprivileged BPF;
- missing tracefs;
- missing required tracepoints;
- lockdown policies;
- capability restrictions;
- distribution-specific hardening;
- verifier behavior;
- kernel-version differences.

A successful build does not prove that eBPF runtime tracing will work on every Linux host.

RuntimeXRay therefore maintains dedicated eBPF runtime CI in addition to compile-time coverage.

---

# 27. ptrace evasion

A target may attempt to detect or interfere with ptrace.

Examples include:

- checking `TracerPid`;
- calling ptrace itself;
- timing checks;
- abnormal signal handling;
- debugger-detection techniques.

RuntimeXRay does not currently claim to defeat these techniques.

A hostile target may alter its behavior when traced.

---

# 28. Concurrency and timing

Runtime analysis of concurrent applications is inherently timing-sensitive.

Events from:

- multiple threads;
- multiple processes;
- blocking I/O;
- pipes;
- asynchronous execution;

may be observed in an order that differs from simplistic sequential assumptions.

RuntimeXRay explicitly distinguishes:

```text
Chronological
Causality
DataFlow
```

because temporal adjacency alone is not sufficient proof of causality or data transfer.

Detection rules should prefer explicit modeled relationships when available.

---

# 29. Process and PID reuse

Linux may reuse PID/TGID values.

RuntimeXRay therefore assigns:

```text
process_instance_id
```

to represent one observed process lifetime.

Consumers should not treat raw PID alone as a permanent process identity across an analysis.

---

# 30. Exec transitions

A successful `exec` changes the executable image inside an existing process lifetime.

RuntimeXRay tracks:

```text
exec_generation
```

to distinguish pre-exec and post-exec activity.

However, RuntimeXRay does not claim complete reconstruction of every userspace state transition across exec.

---

# 31. File-descriptor modeling

RuntimeXRay currently models selected FD behavior such as:

- open/openat;
- close;
- pipe/pipe2;
- dup/dup2/dup3;
- selected fcntl operations;
- fork inheritance;
- exec inheritance;
- FD_CLOEXEC.

This enables explicit resource relationships.

The model is not yet a complete representation of every possible Linux descriptor operation or IPC mechanism.

Unsupported FD transformations may reduce correlation accuracy.

---

# 32. Pipe DataFlow limitations

Pipe DataFlow currently uses modeled resource identity and sensitive-value fingerprint evidence.

Exact byte-stream accounting is not yet available.

If several identical sensitive values are written through the same pipe in overlapping periods, RuntimeXRay may need to choose the best-supported matching write rather than proving byte-for-byte stream origin.

Current logic is intentionally conservative but is not a full stream-reconstruction engine.

---

# 33. Reporting limitations

RuntimeXRay reports structured Findings and evidence references.

Not every Finding includes a remediation.

Not every Finding includes a CWE.

Not every Finding includes a complete human security explanation.

Narrative generation is separate from detection and may evolve independently.

Consumers should use structured fields such as:

```text
kind
severity
title
summary
attributes
evidence_observation_seqs
evidence_edges
supporting_finding_ids
```

rather than assuming every Finding has one fixed prose format.

---

# 34. CWE usage

RuntimeXRay may associate CWE identifiers with findings where the detection rule considers the mapping justified.

A CWE association should be interpreted as:

> The observed property is related to this weakness category.

It should not automatically be interpreted as:

> RuntimeXRay proved that a fully exploitable instance of this CWE exists.

---

# 35. Detection-rule trust

RuntimeXRay's built-in detection rules execute inside the RuntimeXRay process.

Future or locally integrated custom rules would have the same trust implications.

A rule can affect:

- findings;
- performance;
- memory use;
- correctness;
- stability.

The current project does not provide sandboxing for detection rules.

Dynamic external plugin loading is not currently implemented.

---

# 36. AI trust boundary

AI explanation is planned, not required by the RuntimeXRay core.

The intended trust model is:

```text
Observed evidence
      │
      ▼
Detection
      │
      ▼
Findings
      │
      ▼
Optional AI explanation
```

An AI system must not become the authoritative evidence source.

An AI explanation must not invent:

- observations;
- evidence relationships;
- findings;
- confidence;
- exploitation claims.

Raw sensitive values must not be sent to external AI services by default.

The current RuntimeXRay core works without an AI API key.

---

# 37. Controlled-environment assumption

RuntimeXRay currently assumes analysis is performed in a controlled environment.

Examples include:

- developer workstation;
- test VM;
- dedicated security lab;
- CI runner;
- disposable container where appropriate.

Production use is not currently the primary design target.

Tracing and memory scanning may affect latency, timing, memory access, and application behavior.

---

# 38. Authorization assumption

RuntimeXRay is intended for binaries and systems that the user is authorized to analyze.

The project does not provide mechanisms for obtaining unauthorized access to third-party systems.

Users are responsible for ensuring that their analysis is permitted.

---

# 39. Current trust boundaries

A simplified trust model is:

```text
         potentially untrusted target
                    │
                    ▼
         RuntimeXRay collectors
                    │
                    ▼
              LineageGraph
                    │
                    ▼
            Detection rules
                    │
                    ▼
                Findings
                    │
                    ▼
               Reporter
                    │
                    ▼
              User / CI
```

Additional sensitive boundary:

```text
process memory
      │
      ▼
secret detector
      │
      ▼
HMAC fingerprint
      │
      ▼
redacted report
```

Raw values should cross into report output only when explicitly requested.

---

# 40. Failure modes

RuntimeXRay may fail in several ways.

## False negative

A real security-relevant behavior exists but is not observed.

Possible reasons:

- path not executed;
- payload beyond capture limit;
- unsupported syscall;
- unsupported IPC mechanism;
- secret pattern not recognized;
- process exited before scan;
- memory access denied;
- transformed value;
- backend limitation.

---

## False positive

An observation is classified as security-relevant even though it is benign.

Examples:

- legitimate SSH connection flagged because port 22 is classified as sensitive;
- benign use of `strcpy` imported by a binary;
- test credential matching a secret pattern;
- access to a sensitive-looking path in a safe context.

RuntimeXRay findings require security interpretation.

---

## Incorrect correlation

Two observations may appear related but not actually represent one transfer.

RuntimeXRay reduces this risk through:

- exact HMAC fingerprints;
- resource identity;
- explicit DataFlow edges;
- process-instance identity;
- detection rules with strict requirements.

However, RuntimeXRay does not claim perfect causal reconstruction.

---

# 41. Security properties RuntimeXRay tries to preserve

The project aims to preserve several invariants.

## Evidence traceability

A security finding should reference the observations that support it.

---

## Redaction by default

Sensitive values should not be printed unless explicitly requested.

---

## Separation of fact and conclusion

Collectors should not silently invent security conclusions.

Detection rules should not fabricate observations.

---

## Separation of conclusion and explanation

Findings are canonical structured results.

Narratives and future AI explanations are presentation layers.

---

## Architecture independence above the backend

Higher detection layers should reason using semantic syscall names and normalized evidence rather than hard-coded x86_64 or ARM64 syscall numbers.

---

## Deterministic detection

Detection results should not depend on rule-registration order.

---

# 42. CI and test assumptions

RuntimeXRay uses a Release-mode CTest suite.

The current core suite contains 56 tests with ptrace enabled and eBPF runtime tests excluded.

GitHub Actions runs the core suite natively on:

- x86_64;
- ARM64.

A dedicated CI matrix runs 16 eBPF runtime tests on each architecture.

The eBPF CI jobs fail if runtime tests are skipped.

This improves confidence that:

```text
compiled successfully
```

is not confused with:

```text
runtime backend actually works
```

CI coverage still does not prove correctness on every kernel, distribution, hardware platform, workload, or target binary.

---

# 43. Out-of-scope guarantees

RuntimeXRay does not guarantee:

- absence of vulnerabilities;
- malware-free software;
- complete runtime visibility;
- complete secret discovery;
- arbitrary taint tracking;
- exploitability assessment;
- complete process-memory reconstruction;
- full syscall payload capture;
- resistance to hostile anti-analysis;
- production-safe overhead;
- sandbox isolation;
- policy compliance without an explicit policy model;
- correctness of arbitrary third-party detection rules.

---

# 44. Planned threat-model expansions

Future features may change this threat model.

Planned areas include:

- broader sensitive-value lineage;
- memory-copy correlation;
- lifetime checkpoints;
- function-level tracing;
- additional IPC/resource models;
- network-boundary policy;
- static/runtime correlation;
- external detection-rule loading;
- richer transformations;
- release-to-release behavioral comparison.

Each new capability should document:

1. what evidence it collects;
2. what conclusions it can justify;
3. what it cannot justify;
4. what privileges it requires;
5. what false-positive and false-negative modes remain.

---

# 45. Core principle

RuntimeXRay should prefer a narrower claim backed by evidence over a stronger claim based on assumption.

The project principle is:

> **Don't tell me my application is insecure — show me why.**

That principle also constrains RuntimeXRay itself.

If the evidence cannot support a claim, RuntimeXRay should not make it.