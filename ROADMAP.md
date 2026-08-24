# RuntimeXRay Roadmap

This document outlines the planned development of RuntimeXRay.  
It focuses on technical milestones and is subject to change.

## ✅ Already Implemented

- **Unified CLI** (`runtimexray`) with subcommands:
  - `analyze` – static ELF analysis
  - `trace` – dynamic ptrace‑based tracing
  - `mem` – process memory scanning

- **Common CLI options** shared across all subcommands:
  - `--verbose`
  - `--min-severity <level>` (Critical, High, Medium, Low, Info)
  - `--output-format text|json`

- **ELF parsing**: Detect ELF class (32/64-bit), endianness, type, machine, entry point.

- **Security checks**:
  - NX (No eXecute) via `PT_GNU_STACK`
  - PIE (Position-Independent Executable) via `e_type`
  - RELRO (Partial/Full) via `PT_GNU_RELRO` and `DT_BIND_NOW`/`DT_FLAGS`
  - Stack Canary via `__stack_chk_fail` symbol presence

- **Memory-mapped file wrapper** (`MappedFile`) with RAII and move semantics.

- **Dangerous API detection** via imported symbols, with CWE references, severity levels, and recommendations.

- **Severity filtering** for findings (`--min-severity`, `--verbose`).

- **Dynamic analysis** (`runtimexray trace`):
  - `ptrace`-based tracing on x86_64 and ARM64
  - syscall name mapping and filtering of interesting events
  - file path reading for `open`/`openat`
  - network address parsing for `connect`/`sendto`
  - `write` buffer reading (first 4 KB)
  - child stdout/stderr capture and scanning for sensitive keywords
  - timeout support (`--timeout <seconds>`)
  - dynamic findings: sensitive file access, suspicious network connections, sensitive data writes
  - JSON output

- **Memory scanning** (`runtimexray mem`):
  - parsing `/proc/<pid>/maps` for readable regions
  - reading `/proc/<pid>/cmdline` and `/proc/<pid>/environ`
  - scanning memory pages for password‑like strings, private key markers, and other sensitive patterns
  - `--max-pages` option to limit the number of scanned pages
  - page count reporting in output
  - `--max-pages 0` mode to skip page scanning and only check cmdline/environ
  - JSON output

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

- **JSON reporter**:
  - `Reporter` class with text and JSON output (via `nlohmann/json`)
  - metadata fields: `schema_version`, `tool`, `command`, `target`, `started_at`, `duration_ms`
  - `summary` section with counts by severity and type
  - integrated in all three subcommands

- **Centralized finding filtering** (`filter_findings`) respecting `min_severity` and `verbose`.

- **Comprehensive CTest suite**:
  - 40+ tests covering static checks, dynamic tracing, memory scanning, JSON output, analyzer registry, and integration tests
  - runs on x86_64 and ARM64 via GitHub Actions

- **CI/CD**: GitHub Actions workflows for build and test on x86_64 and ARM64.

- **Documentation**: `docs/security_checks.md` explains each check; README includes quick start and architecture; `docs/extending_detectors.md` describes custom analyzer integration.

## 🚀 Upcoming Features

- **Full dynamic analysis**:
  - Complete process memory scanning / sensitive-data discovery
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
  - Use `PTRACE_SEIZE` and `PTRACE_O_TRACEFORK` for less intrusive tracing
  - Detect anti-debugging/anti-tracing behaviour (e.g., `TracerPid` checks, self-ptrace)
  - Explore eBPF as a harder-to-evade tracing backend

- **Memory scanning further improvements**:
  - Flag RWX anonymous memory
  - Integrate with `xray-trace` for runtime memory inspection
  - Track sensitive data lifetime in memory
  - Reduce false positives with advanced context analysis

- **Additional binary formats**: PE (Windows), Mach‑O (macOS)

## 📈 Long-Term Vision

- Cross-platform support for Windows (PE) and macOS (Mach‑O).
- Public benchmark against popular open-source projects.
- Community contributions and plugin ecosystem.
- Optional commercial/enterprise offering while keeping core open source (private planning).

*This roadmap reflects technical goals and may evolve based on user feedback and maintainer decisions.*