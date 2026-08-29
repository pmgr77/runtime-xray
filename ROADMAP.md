# RuntimeXRay Roadmap

This document outlines the planned development of RuntimeXRay.  
It focuses on technical milestones and is subject to change.

## ✅ Already Implemented

- **Unified CLI** (`runtimexray`) with subcommands:
  - `analyze` – static ELF analysis
  - `trace` – dynamic ptrace‑based or eBPF tracing
  - `mem` – process memory scanning

- **Common CLI options** shared across all subcommands:
  - `--report FILE` – write human‑readable report to file (default: stdout)
  - `--json FILE` – write JSON report to file
  - `--log-level LEVEL` – set log level (error, warn, info, debug, trace)
  - `--log-file FILE` – write runtime logs to file (default: stderr)
  - `--min-severity <level>` – (Critical, High, Medium, Low, Info)

  *Removed:* `--verbose`, `--output-format`, `--quiet` (replaced by the above).

- **ELF parsing**: Detect ELF class (32/64-bit), endianness, type, machine, entry point.

- **Security checks**:
  - NX (No eXecute) via `PT_GNU_STACK`
  - PIE (Position-Independent Executable) via `e_type`
  - RELRO (Partial/Full) via `PT_GNU_RELRO` and `DT_BIND_NOW`/`DT_FLAGS`
  - Stack Canary via `__stack_chk_fail` symbol presence

- **Memory-mapped file wrapper** (`MappedFile`) with RAII and move semantics.

- **Dangerous API detection** via imported symbols, with CWE references, severity levels, and recommendations.

- **Severity filtering** for findings (`--min-severity`).

- **Dynamic analysis** (`runtimexray trace`):
  - `ptrace`-based tracing on x86_64 and ARM64
  - eBPF backend (`--backend ebpf`) using libbpf, embedded bytecode
  - syscall name mapping and filtering of interesting events
  - file path reading for `open`/`openat`
  - network address parsing for `connect`/`sendto`
  - `write` buffer reading (first 4 KB)
  - child stdout/stderr capture and scanning for sensitive keywords
  - timeout support (`--timeout <seconds>`)
  - fork/thread following (`--follow-forks` / `--no-follow-forks`)
  - dynamic findings: sensitive file access, suspicious network connections, sensitive data writes
  - JSON report via `--json FILE`
  - Text report via `--report FILE`
  - Runtime logs via `--log-level` / `--log-file`

- **Memory scanning** (`runtimexray mem`):
  - parsing `/proc/<pid>/maps` for readable regions
  - reading `/proc/<pid>/cmdline` and `/proc/<pid>/environ`
  - scanning memory pages for password‑like strings, private key markers, and other sensitive patterns
  - `--max-pages` option to limit the number of scanned pages
  - page count reporting in output
  - `--max-pages 0` mode to skip page scanning and only check cmdline/environ
  - JSON report via `--json FILE`
  - Text report via `--report FILE`

- **Open analyzer interface**:
  - `IAnalyzer` base class for custom analyzers
  - `Evidence` variant types (`SymbolEvidence`, `FileAccessEvidence`, `NetworkEvidence`, `MemoryChunkEvidence`, `HardeningEvidence`)
  - `AnalyzerRegistry` singleton for registering, disabling, enabling, and unregistering analyzers
  - Built‑in analyzers:
    - `HardeningAnalyzer`
    - `DangerousApiAnalyzer`
    - `SensitiveFileAnalyzer`
    - `NetworkAnalyzer`
    - `PasswordMemoryAnalyzer`
    - `PrivateKeyMemoryAnalyzer`

- **Logger and Reporter**:
  - `Logger` class with thread‑safe, level‑based logging to stderr or file.
  - `FindingReporter` abstraction with `TextFindingReporter` and `JsonFindingReporter`.
  - `Reporter::to_text` and `Reporter::to_json` unified report generation.
  - Metadata fields in JSON: `schema_version`, `tool`, `command`, `target`, `started_at`, `duration_ms`, plus extra fields for `trace` (backend, timeout_seconds, timed_out, child_output) and `mem` (pages_scanned, max_pages).
  - Summary section with counts by severity and type.
  - Integrated in all three subcommands.

- **Centralized finding filtering** (`filter_findings`) respecting `min_severity`.

- **Comprehensive CTest suite**:
  - 47+ tests covering static checks, dynamic tracing (ptrace and eBPF), memory scanning, JSON output, analyzer registry, fork/thread tracing, and integration tests.
  - Runs on x86_64 and ARM64 via GitHub Actions.

- **CI/CD**: GitHub Actions workflows for build and test on x86_64 and ARM64.

- **Documentation**: `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `ROADMAP.md`, `docs/security_checks.md`, `docs/extending_detectors.md`, `docs/integration_examples.md`, `FAQ.md`, etc.

## 🚀 Upcoming Features

- **Full dynamic analysis**:
  - Complete process memory scanning / sensitive-data discovery (already partially implemented)
  - Data lineage: track sensitive data from source through transformations to sinks
  - Network-boundary detection
  - Correlation of static and runtime evidence into a unified report

- **Secret detection**:
  - Find hardcoded keys, credentials, and other secrets in binaries and runtime memory.
  - High-entropy data detection for keys and encrypted blobs.

- **Reporting**: Generate HTML reports in addition to text and JSON.

- **Dynamic plugin loading**: Load custom analyzers from shared libraries (`.so`) without recompiling the core.

- **AI explanations**: Optional integration with LLMs (e.g., DeepSeek) to produce human-readable evidence summaries.

- **Counter-measures against evasive binaries**:
  - Use `PTRACE_SEIZE` and `PTRACE_O_TRACEFORK` for less intrusive tracing (already partially done)
  - Detect anti-debugging/anti-tracing behaviour (e.g., `TracerPid` checks, self-ptrace)
  - Enhance eBPF backend: support attaching to running processes and function‑level tracing (uprobes)

- **Memory scanning further improvements**:
  - Flag RWX anonymous memory
  - Integrate with `trace` for runtime memory inspection (e.g., `--scan-memory`)
  - Track sensitive data lifetime in memory
  - Reduce false positives with advanced context analysis

- **Additional binary formats**: PE (Windows), Mach‑O (macOS)

## 📈 Long-Term Vision

- Cross-platform support for Windows (PE) and macOS (Mach‑O).
- Public benchmark against popular open-source projects.
- Community contributions and plugin ecosystem.
- Optional commercial/enterprise offering while keeping core open source (private planning).

*This roadmap reflects technical goals and may evolve based on user feedback and maintainer decisions.*