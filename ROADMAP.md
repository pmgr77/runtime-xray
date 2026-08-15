# RuntimeXRay Roadmap

This document outlines the planned development of RuntimeXRay.  
It focuses on technical milestones and is subject to change.

## ✅ Already Implemented

- **ELF parsing**: Detect ELF class (32/64-bit), endianness, type, machine, entry point.
- **Security checks**:
  - NX (No eXecute) via `PT_GNU_STACK`
  - PIE (Position-Independent Executable) via `e_type`
  - RELRO (Partial/Full) via `PT_GNU_RELRO` and `DT_BIND_NOW`/`DT_FLAGS`
  - Stack Canary via `__stack_chk_fail` symbol presence
- **Memory-mapped file wrapper** (`MappedFile`) with RAII and move semantics.
- **Regression tests** for the above checks using CTest and specially compiled probe binaries.
- **Documentation**: `docs/security_checks.md` explains each check.

## 🚀 Upcoming Features

- **Dangerous API detection**: Identify obsolete or insecure functions (weak crypto, unsafe libc functions) via symbol tables.
- **Dynamic analysis**: Use `ptrace`, `/proc` memory scanning, and syscall interception to observe runtime behavior.
- **Data lineage**: Track sensitive data from source through transformations to sinks.
- **Secret detection**: Find hardcoded keys, credentials, and other secrets in binaries and memory.
- **Reporting**: Generate JSON and HTML reports, not just console output.
- **CI/CD integration**: GitHub Actions and GitLab CI templates to run RuntimeXRay automatically.
- **Extensible analyzer architecture**: Plugins for new checks and formats (PE, Mach‑O).
- **AI explanations**: Optional integration with LLMs (e.g., DeepSeek) to produce human-readable evidence summaries.

## 📈 Long-Term Vision

- Cross-platform support for Windows (PE) and macOS (Mach‑O).
- Public benchmark against popular open-source projects.
- Community contributions and plugin ecosystem.

*This roadmap reflects technical goals and may evolve based on user feedback and maintainer decisions.*