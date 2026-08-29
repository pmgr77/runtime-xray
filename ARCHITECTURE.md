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

- **Logger** – thread‑safe, level‑based runtime logging (timestamps, levels). Logs to stderr or file (`--log-file`). Used by all modules for diagnostics and syscall traces (when `--log-level debug`).

- **Reporter** – abstract `FindingReporter` with `TextFindingReporter` and `JsonFindingReporter` implementations. Renders findings to stdout or files (`--report`, `--json`). The old static `Reporter` class is now a utility for formatting.

- **AI Analyst** – optional layer that uses LLMs to generate human‑readable explanations for findings. AI only interprets collected evidence, never invents it. Planned for future, not yet integrated.

## Data flow

Binary / Process  
→ Collectors (Static, Dynamic, Memory)  
→ Evidence  
→ Analyzer Registry  
→ Analyzers (built‑in + custom)  
→ Findings  
→ Optional AI explanation (planned)  
→ Reporter (Text or JSON) → stdout or file

All subcommands use the same global options and central finding filtering, ensuring consistent behaviour across `runtimexray analyze`, `trace`, and `mem`.

## Output separation

RuntimeXRay keeps three independent streams:

- **Findings** – human‑readable (stdout or `--report FILE`) and machine‑readable (`--json FILE`).
- **Runtime logs** – diagnostics, warnings, errors, syscall traces (with `--log-level debug`) – sent to stderr or `--log-file FILE`.
- **Syscall traces** – logged via `Logger` at `Debug` level; they never appear in the findings report.

This design ensures that JSON output remains valid and that logs can be captured separately for debugging.

## Backend architecture

- **ptrace** – classic tracing using `ptrace` syscall interception. Supports fork/thread following via `PTRACE_O_TRACEFORK`, `TRACEVFORK`, `TRACECLONE`. Works on x86_64 and ARM64.

- **eBPF** – low‑overhead tracing using `raw_syscalls` tracepoints. Embeds a BPF program (compiled at build time) that filters events by PID and submits them via a ring buffer. Supports fork/thread following by dynamically updating the PID filter map. Requires root and kernel with eBPF support.

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