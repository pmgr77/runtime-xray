# RuntimeXRay

[![Build and Test](https://github.com/pmgr77/runtime-xray/actions/workflows/build.yml/badge.svg)](https://github.com/pmgr77/runtime-xray/actions/workflows/build.yml)

> **Don't tell me my application is insecure — show me why.**  
> **See what an attacker can learn from your application at runtime.**

RuntimeXRay is an **evidence‑driven security analysis tool for compiled applications**.

It combines static binary analysis with runtime observation to build security findings from evidence that can actually be observed in the compiled application — not from assumptions, but from facts.

---

## Why RuntimeXRay?

Software is being produced faster and in larger quantities than ever before.  
AI‑assisted development, third‑party components, legacy code and rapidly changing dependencies make it increasingly difficult to know exactly what ends up inside a deployed application — and what that application actually exposes while running.

### 🤖 “The AI wrote it. But what did it actually build?”

AI can produce working code in seconds. Tests may pass and the application may ship.

**The problem:** You know what the code was supposed to do. Do you know what the resulting binary actually exposes at runtime?

### 📦 “You didn’t write that library. Do you really know what it does?”

Modern applications depend on third‑party and legacy components that may be difficult or impossible to fully audit.

**The problem:** Documentation and source‑level analysis tell only part of the story. What does the running process actually access, retain, expose or communicate?

### 🧩 “Who still understands this entire application?”

Large applications accumulate years of code, dependencies and configuration paths.

**The problem:** Security decisions increasingly rely on assumptions about what the application does.

### ⚡ “Can security review keep up with the release cycle?”

Software changes faster than security teams can manually inspect every change.

**The problem:** Traditional analysis can identify potential weaknesses. Runtime evidence can show what actually happened.

---

### 🔍 Evidence over warnings

Traditional security scanners often report findings such as:

```text
Stack canary: disabled
Dangerous API: strcpy
PIE: disabled
```

RuntimeXRay is designed to go further: connect security findings to **observable evidence** and, as runtime analysis evolves, show how potentially sensitive data and behavior move through the application.

Instead of only saying:

> "This application may be insecure."

the goal is to answer:

> **"What happened, where did it happen, and what evidence proves it?"**

---

## What does RuntimeXRay actually show?

Suppose a compiled application:

- contains a security‑sensitive API,
- reads configuration containing credentials,
- accesses sensitive files,
- connects to an unexpected network endpoint, or
- leaves secrets in process memory.

RuntimeXRay is designed to turn these observations into concrete evidence that can be investigated and correlated with the security finding.

> *A full demonstration is coming soon. We are currently preparing a sample application that will show how RuntimeXRay collects evidence and produces a finding.*

---

## Current Status

RuntimeXRay is in active development.
The following capabilities are available today, experimental, or planned.

### ✅ Available today

#### Unified CLI

Single binary `runtimexray` with subcommands:

- `analyze` – static ELF hardening checks and dangerous API detection
- `trace` – dynamic ptrace‑based syscall tracing and evidence capture
- `mem` – process memory scanning for secrets

All subcommands support common options:

- `--verbose`
- `--min-severity <level>` (Critical, High, Medium, Low, Info)
- `--output-format text|json`

#### Static analysis (`runtimexray analyze`)

- ELF 32‑bit and 64‑bit parsing
- Architecture and endianness detection
- ELF type and entry‑point inspection
- NX / executable‑stack detection
- PIE detection
- RELRO (Partial/Full) detection
- Stack canary detection
- Dangerous API/import detection with CWE references
- Severity filtering
- JSON output

#### Dynamic tracing (`runtimexray trace`)

- Linux `ptrace`‑based syscall tracing on x86_64 and ARM64
- Syscall name mapping and filtering of interesting events
- File path reading for `open` / `openat`
- Network address parsing for `connect` / `sendto`
- `write` buffer reading (first 4 KB)
- Child stdout/stderr capture and scanning for sensitive keywords
- Timeout support (`--timeout <seconds>`)
- Dynamic findings: sensitive file access, suspicious network connections, sensitive data writes
- JSON output

#### Memory scanning (`runtimexray mem`)

- Reads `/proc/<pid>/cmdline` and `/proc/<pid>/environ`
- Scans readable memory pages for:
  - password‑like strings
  - private key markers (PEM)
  - other sensitive patterns
- `--max-pages <N>` option to limit the number of scanned pages
- `--max-pages 0` skips page scanning and only checks cmdline/environ
- Reports number of scanned pages
- JSON output

#### Extensible analyzers

- `AnalyzerRegistry` allows custom analyzers to be registered, disabled, enabled, or removed without modifying core code.
- Analyzers consume `Evidence` objects (`SymbolEvidence`, `FileAccessEvidence`, `NetworkEvidence`, `MemoryChunkEvidence`, `HardeningEvidence`) and produce `FindingList`.
- Built‑in analyzers include hardening, dangerous API, sensitive file, network, password memory, and private key memory.
- Documentation: `docs/extending_detectors.md`.

#### Tests

- Comprehensive CTest suite (40+ tests)
- Regression and integration tests for static checks, dynamic tracing, memory scanning, JSON output, and analyzer registry
- Runs on x86_64 and ARM64 via GitHub Actions

### 🧪 Experimental

- **Runtime correlation** – combining static and dynamic findings in a unified view is being designed.
- **Memory scanning under load** – performance tuning and heuristic improvements.

### 📋 Planned

- **Data lineage** – track sensitive data from source through transformations to sinks
- **Network‑boundary detection** – identify unexpected outbound communication
- **eBPF backend** – low‑overhead tracing using `libbpf`, harder to evade than `ptrace`
- **AI explanations** – optional LLM integration to explain findings, always evidence‑first
- **Additional binary formats** – PE (Windows), Mach‑O (macOS)
- **Public benchmark** – run against popular open‑source projects
- **Web service** – upload a binary and receive a report

---

## Quick Start

### Build

```bash
git clone https://github.com/pmgr77/runtime-xray.git
cd runtime-xray

mkdir build
cd build

cmake ..
cmake --build .
```

### Analyze an ELF binary

```bash
./runtimexray analyze /bin/ls
```

Use `--verbose` to see all findings, including informational hardening checks:

```bash
./runtimexray analyze --verbose /bin/ls
```

JSON output:

```bash
./runtimexray analyze --output-format json /bin/ls
```

### Trace a process dynamically

```bash
./runtimexray trace --timeout 5 /usr/bin/curl https://example.com
```

Use `--verbose` to show all system calls:

```bash
./runtimexray trace --verbose /bin/ls
```

JSON output:

```bash
./runtimexray trace --timeout 5 --output-format json /bin/cat /etc/passwd
```

### Scan process memory for secrets

```bash
./runtimexray mem <pid>
```

Limit pages:

```bash
./runtimexray mem --max-pages 500 <pid>
./runtimexray mem --max-pages 0 <pid>   # only cmdline and environment
```

JSON output:

```bash
./runtimexray mem --output-format json <pid>
```

---

## Evidence-First AI

RuntimeXRay is designed to optionally use LLMs to explain security findings in human‑readable language.

AI is an **explanation layer, not the source of truth**.

The intended model:

```text
Application
     ↓
Observed evidence
     ↓
Security analysis
     ↓
Findings
     ↓
Optional AI explanation
```

The AI should explain evidence collected by RuntimeXRay — **not invent evidence or findings**.

Even in an era where AI may help create software, the evidence must come from the application itself.

---

## Architecture

RuntimeXRay is being developed around a layered analysis architecture:

```text
                  ┌─────────────────────┐
                  │   Compiled Binary   │
                  └──────────┬──────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
      ┌───────────────┐             ┌───────────────┐
      │ Static        │             │ Dynamic       │
      │ Collector     │             │ Collector     │
      │               │             │               │
      │ ELF metadata  │             │ ptrace        │
      │ Hardening     │             │ syscalls      │
      │ Imports       │             │ memory        │
      └───────┬───────┘             └───────┬───────┘
              │                             │
              └──────────────┬──────────────┘
                             ▼
                    ┌─────────────────┐
                    │ Evidence /      │
                    │ Analyzer        │
                    │ Registry        │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │ Security        │
                    │ Findings        │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │ Reporting /     │
                    │ AI Explanation  │
                    └─────────────────┘
```

The architecture is intentionally modular so that additional binary formats, collectors, analyzers, security rules, and reporting mechanisms can be added independently.

See [ARCHITECTURE.md](ARCHITECTURE.md) for more details.

---

## Roadmap

The project is evolving from static binary inspection toward **evidence‑based runtime security analysis**.

Planned areas include:

* Data lineage
* Network‑boundary detection
* Static/runtime evidence correlation
* HTML reporting
* Additional binary formats such as PE and Mach‑O
* General plugin architecture for custom analyzers
* Optional AI‑assisted analysis and explanations
* eBPF backend
* Public benchmark
* Web service

See the [Roadmap](ROADMAP.md) for the current priorities.

---

## Documentation

* [Security Checks](docs/security_checks.md) — details of the currently implemented security checks
* [Architecture](ARCHITECTURE.md) — system architecture and design
* [Threat Model](THREAT_MODEL.md) — security assumptions and threat model
* [Roadmap](ROADMAP.md) — planned development
* [Contributing](CONTRIBUTING.md) — how to contribute
* [Security](SECURITY.md) — reporting security issues
* [Extending Detectors](docs/extending_detectors.md) — add custom analyzers
* [Integration Examples](docs/integration_examples.md) — parse JSON output

---

## Contributing

RuntimeXRay is an open‑source project and contributions are welcome.

Areas that are particularly interesting include:

* ELF and binary analysis
* Linux process tracing
* `ptrace`
* memory analysis
* security research
* data‑flow analysis
* networking
* C++
* security tooling

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a contribution.

---

## Security

If you discover a security vulnerability in RuntimeXRay, please **do not open a public issue**.

Instead, report it responsibly to:

- **security@runtimexray.com** – for vulnerabilities in RuntimeXRay itself
- **hello@runtimexray.com** – for general security questions or non‑urgent inquiries

We follow coordinated disclosure and will respond as quickly as possible. For more details, see [SECURITY.md](SECURITY.md).

---

## License

RuntimeXRay is licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE) for the full license text.