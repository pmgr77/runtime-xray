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
  - `--min-severity <level>`
  - `--output-format <format>` (reserved for future use)
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
- **Memory scanning** (`runtimexray mem`):
  - parsing `/proc/<pid>/maps` for readable regions
  - reading `/proc/<pid>/cmdline` and `/proc/<pid>/environ`
  - scanning memory pages for password‑like strings, private key markers, and other sensitive patterns
  - `--max-pages` option to limit the number of scanned pages
  - page count reporting in output
  - `--max-pages 0` mode to skip page scanning and only check cmdline/environ
- **Secret detectors**:
  - `PasswordDetector` for key‑value pairs (`password=`, `api_key:`, etc.) with word‑boundary awareness
  - `PrivateKeyDetector` for PEM markers (`BEGIN RSA PRIVATE KEY`, etc.)
- **Comprehensive CTest suite**: 33 tests covering static checks, dynamic helpers, memory scanning, and integration tests.
- **CI/CD**: GitHub Actions workflows for build and test on x86_64 and ARM64.
- **Documentation**: `docs/security_checks.md` explains each check; README includes quick start and architecture.

## 🚀 Upcoming Features

- **Full dynamic analysis**:
  - Complete process memory scanning / sensitive-data discovery
  - Data lineage: track sensitive data from source through transformations to sinks
  - Network-boundary detection
  - Correlation of static and runtime evidence into a unified report
- **Secret detection**:
  - Find hardcoded keys, credentials, and other secrets in binaries and runtime memory.
  - High‑entropy data detection for keys and encrypted blobs.
- **Reporting**: Generate JSON and HTML reports, not just console output.
- **Extensible analyzer architecture**: Plugins for new checks and additional binary formats (PE, Mach‑O).
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

## 📈 Long-Term Vision

- Cross-platform support for Windows (PE) and macOS (Mach‑O).
- Public benchmark against popular open-source projects.
- Community contributions and plugin ecosystem.
- Optional commercial/enterprise offering while keeping core open source (private planning).

*This roadmap reflects technical goals and may evolve based on user feedback and maintainer decisions.*