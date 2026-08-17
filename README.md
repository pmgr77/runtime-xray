# RuntimeXRay

[![Build and Test](https://github.com/runtimexray/runtime-xray/actions/workflows/build.yml/badge.svg)](https://github.com/runtimexray/runtime-xray/actions/workflows/build.yml)

> **Don't tell me my application is insecure — show me why.**

RuntimeXRay is an **evidence-driven security analysis tool for compiled applications**.

It combines static binary analysis with runtime observation to build concrete security findings from what can actually be observed in an application — rather than relying only on generic warnings.

Today, RuntimeXRay analyzes ELF binaries for security hardening and potentially dangerous APIs. Runtime analysis is under active development, with the goal of correlating **binary metadata, runtime behavior, memory, system calls, files, and network activity** into actionable security evidence.

The long-term goal is simple:

> **Show what an application actually exposes, and what an attacker could learn from it.**

---

## Why RuntimeXRay?

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

### 🧩 Static + Dynamic Analysis

RuntimeXRay combines two complementary views of an application:

* **Static analysis** of the compiled binary
* **Dynamic analysis** of the running process

Static analysis provides information that can be determined directly from the binary, while runtime analysis can reveal behavior that cannot be established from the binary alone.

The runtime component, **Tachikoma**, uses Linux `ptrace`-based tracing and is currently under development.

Tachikoma — named after the autonomous spider-like “think tanks” from *Ghost in the Shell* — follows the target process and intercepts its system calls, allowing RuntimeXRay to observe runtime behaviour that static inspection alone cannot reveal.

---

### 🛡️ Works Without Source Code

RuntimeXRay is designed to analyze **compiled applications**, including stripped and third-party binaries.

This makes the approach useful for software where source code may not be available, including:

* third-party components
* legacy applications
* proprietary software
* vendor binaries
* security assessments of deployed applications

---

### 🧠 Evidence-First AI

RuntimeXRay is designed to optionally use LLMs to explain security findings in human-readable language.

AI is an **explanation layer, not the source of truth**.

The intended model is:

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

---

### 📈 From Findings to Data Lineage

A major goal of RuntimeXRay is to track sensitive information through an application's execution:

```text
Source
  ↓
Memory
  ↓
Processing
  ↓
API / syscall
  ↓
File / network / external boundary
  ↓
Destination
```

This will allow RuntimeXRay to move beyond isolated warnings and toward understanding **how sensitive information actually flows through a running application**.

---

## Current Status

RuntimeXRay is currently in active development.

### ✅ Available today

**ELF static analysis**

* ELF 32-bit and 64-bit parsing
* Architecture and endianness detection
* ELF type and entry-point inspection
* NX / executable-stack detection
* PIE detection
* RELRO detection
* Stack Canary detection
* Dangerous API/import detection
* CWE references and security recommendations
* Severity filtering
* Verbose reporting
* Regression tests using CTest

Dangerous API detection currently identifies imported functions that may indicate unsafe or obsolete practices, such as:

* `strcpy`
* `system`
* weak or obsolete cryptographic APIs
* other security-sensitive functions

These findings indicate **potential risk based on binary metadata**; an imported function is not necessarily executed at runtime.

### 🚧 Under active development

**Dynamic analysis**

* Linux `ptrace`-based syscall tracing
* Runtime process observation
* Memory inspection
* Sensitive-data discovery
* Data-flow / lineage analysis
* Network-boundary detection
* Correlation of static and runtime evidence

The core of dynamic analysis is **Tachikoma**, our `ptrace`-based tracer. It launches the target process under trace, intercepts system calls, and will eventually feed runtime evidence into the same finding pipeline used by static analysis.

See the [Roadmap](ROADMAP.md) for the planned development path.

---

## Quick Start

### Build

```bash
git clone https://github.com/runtimexray/runtime-xray.git
cd runtime-xray

mkdir build
cd build

cmake ..
cmake --build .
```

### Analyze an ELF binary

```bash
./xray /bin/ls
```

Example output:

```text
/bin/ls is an ELF file. Size: 142312 bytes
  Class: Elf64
  Data Encoding: LittleEndian
  Type: DYN (Shared object/PIE)
  Machine: x86_64
  Version: 1
  Entry point: 0x6d30

> Hardening checks:
    NX: Enabled
    PIE: Enabled
    RELRO: Full
    Canary: Enabled

> Dangerous API detection:
    Dangerous API: strncpy
      Reason: Potentially unsafe if null-termination is not ensured
```

The exact findings depend on the binary being analyzed.

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
      │ Analysis      │             │ Analysis      │
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
                    │ Correlation     │
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

The architecture is intentionally modular so that additional binary formats, runtime analyzers, security rules, and reporting mechanisms can be added independently.

See [ARCHITECTURE.md](ARCHITECTURE.md) for more details.

---

## Roadmap

The project is evolving from static binary inspection toward **evidence-based runtime security analysis**.

Planned areas include:

* Runtime memory scanning
* Sensitive-data and secret detection
* Syscall analysis and correlation
* Data lineage
* Network-boundary analysis
* Static/runtime evidence correlation
* JSON and HTML reporting
* Additional binary formats such as PE and Mach-O
* Plugin architecture
* Optional AI-assisted analysis and explanations
* CI/CD integration

See the [Roadmap](ROADMAP.md) for the current priorities.

---

## Documentation

* [Security Checks](docs/security_checks.md) — details of the currently implemented security checks
* [Architecture](ARCHITECTURE.md) — system architecture and design
* [Threat Model](THREAT_MODEL.md) — security assumptions and threat model
* [Roadmap](ROADMAP.md) — planned development
* [Contributing](CONTRIBUTING.md) — how to contribute
* [Security](SECURITY.md) — reporting security issues

---

## Contributing

RuntimeXRay is an open-source project and contributions are welcome.

Areas that are particularly interesting include:

* ELF and binary analysis
* Linux process tracing
* `ptrace`
* memory analysis
* security research
* data-flow analysis
* networking
* C++
* security tooling

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a contribution.

---

## License

RuntimeXRay is licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE) for the full license text.