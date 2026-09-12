# Architecture

RuntimeXRay is a modular tool that analyzes the security posture of compiled applications by combining static analysis, dynamic tracing, and memory scanning.

## High‑level components

- **CLI** (`runtimexray`) – unified command dispatcher with subcommands:
  - `analyze` – static ELF parsing and hardening checks
  - `trace` – dynamic tracing using **ptrace** or **eBPF** backends
  - `mem` – process memory scanning (cmdline, environ, readable pages)

  All subcommands share common options:
  - `--report FILE` – human‑readable report to file (default: stdout)
  - `--json FILE` – JSON report to file
  - `--log-level LEVEL` – set log level (error, warn, info, debug, trace)
  - `--log-file FILE` – write logs to file (default: stderr)
  - `--min-severity LEVEL` – filter findings
  - `--show-secrets` – explicitly disclose secret values; redacted by default


- **Collectors** – gather raw evidence without performing analysis:
  - *Static*: ELF parser, binary hardening property extraction.
  - *Dynamic*: **Tachikoma** (ptrace) and **EbpfBackend** (eBPF), syscall interception, file/network/write evidence capture, fork/thread following.
  - *Memory*: `/proc` parser, memory chunk reader, cmdline/environ reader.

- **Evidence** – typed structures produced by collectors:
  - `SymbolEvidence`
  - `FileAccessEvidence`
  - `NetworkEvidence`
  - `MemoryChunkEvidence`
  - `HardeningEvidence`

- **Analyzer Registry** – central singleton that stores and runs analyzers.  
  Every `Evidence` object is sent through the registry, and all active analyzers can process it.

- **Analyzers** – pluggable modules implementing the `IAnalyzer` interface.  
  Built‑in analyzers include:
  - HardeningAnalyzer
  - DangerousApiAnalyzer
  - SensitiveFileAnalyzer
  - NetworkAnalyzer
  - PasswordMemoryAnalyzer
  - PrivateKeyMemoryAnalyzer
  
  Users can register custom analyzers without modifying core code.

- **Findings** – structured results produced by analyzers (`FindingList`).

  Memory-secret findings retain the exact value internally for analysis and
  reporting. The analyzer computes a per-run HMAC fingerprint. Reporters redact
  the value by default; disclosure is an explicit option for local debugging.

- **Logger** – thread‑safe, level‑based runtime logging (timestamps, levels). Logs to stderr or file (`--log-file`). Used by all modules for diagnostics and syscall traces (when `--log-level debug`).

- **Reporter** – abstract `FindingReporter` with `TextFindingReporter` and `JsonFindingReporter` implementations. Renders findings to stdout or files (`--report`, `--json`). The old static `Reporter` class is now a utility for formatting.

- **AI Analyst** – optional layer that uses LLMs to generate human‑readable explanations for findings. AI only interprets collected evidence, never invents it. Planned for future, not yet integrated.

## Data flow

Binary / Process  
→ Collectors (Static, Dynamic, Memory)  
→ Evidence  
→ Analyzer Registry  
→ Analyzers (built-in + custom)
→ Event/process lineage
→ Exact sensitive-object fingerprint correlation
→ Findings  
→ Optional AI explanation (planned)  
→ Reporter (Text or JSON) → stdout or file

All subcommands use the same global options and central finding filtering, ensuring consistent behaviour across `runtimexray analyze`, `trace`, and `mem`.

## Sensitive-object correlation

The first end-to-end runtime correlation path is implemented in `trace`.

For a fully observed object, RuntimeXRay can connect:

```text
file path
   ↓
read / recv event
   ↓
exact sensitive-object HMAC fingerprint
   ↓
independent scanner-derived process-memory observation
   ↓
write / send event carrying the same fingerprint
   ↓
resolved socket destination
```

The current correlation is intentionally strict. A correlated
`file -> read -> memory -> send -> socket` finding is emitted only when the
same fingerprint is present on:

1. a successful read-family event,
2. a `Data` observation produced by the independent memory scanner and tagged
   `memory`, and
3. a write/send-family event.

The memory leg is not inferred from the syscall buffer. `--scan-memory` is
therefore required for this correlation. If the memory scanner does not
independently observe the sensitive object, the flow is considered incomplete
and no correlated finding is emitted.

The fingerprint is a per-run HMAC of the exact detected secret. This allows
RuntimeXRay to connect observations without printing the secret. Reporters
redact secret values by default; `--show-secrets` is an explicit local-debugging
override.

This mechanism proves an observed data path. It does not by itself prove
malicious intent, exfiltration, or that a destination is unexpected.

Broader lineage remains future work, including transformed values, lifetime
tracking, additional checkpoints and sinks, and richer cross-process
propagation.

## Output separation

RuntimeXRay keeps three independent streams:

- **Findings** – human‑readable (stdout or `--report FILE`) and machine‑readable (`--json FILE`).
- **Runtime logs** – diagnostics, warnings, errors, syscall traces (with `--log-level debug`) – sent to stderr or `--log-file FILE`.
- **Syscall traces** – logged via `Logger` at `Debug` level; they never appear in the findings report.

This design ensures that JSON output remains valid and that logs can be captured separately for debugging.

## Backend architecture

- **ptrace** – classic tracing using `ptrace` syscall interception. Supports fork/thread following via `PTRACE_O_TRACEFORK`, `TRACEVFORK`, `TRACECLONE`. Works on x86_64 and ARM64.

- **eBPF** – low‑overhead tracing using `raw_syscalls` tracepoints. The BPF program captures relevant userspace bytes at tracepoint time and submits them through a ring buffer, avoiding a later userspace read race. It supports fork/thread following by dynamically updating the PID filter map. Requires root and kernel with eBPF support.

Both backends implement the `ITraceBackend` interface and are selected via `--backend ptrace|ebpf`.

## Testing

Comprehensive CTest suite (47+ tests) covering static analysis, dynamic tracing (both backends), memory scanning, fork/thread following, JSON validation, and analyzer registry. Runs on x86_64 and ARM64 via GitHub Actions.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) – this file
- [README.md](README.md) – overview and quick start
- [ROADMAP.md](ROADMAP.md) – planned features
- [THREAT_MODEL.md](THREAT_MODEL.md) – security assumptions and limitations
- [docs/security_checks.md](docs/security_checks.md) – detailed check descriptions
- [docs/extending_detectors.md](docs/extending_detectors.md) – custom analyzer integration
