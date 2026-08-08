# Architecture

RuntimeXRay is a modular tool that analyzes the security posture of compiled applications by combining static and dynamic analysis.

## High‑level components

- **CLI** (`xray`) – user interface, argument parsing, orchestration.
- **Collectors** – gather raw evidence:
  - *Static*: ELF/PE parser, binary hardening checks (checksec‑style).
  - *Dynamic*: process tracing (`ptrace`), memory scanning, syscall interception, `/proc` inspection.
- **Correlation Engine** – builds an event graph and tracks data lineage (source → transformation → sink).
- **Security Rules** – pluggable modules that analyze evidence and produce findings (hardcoded secrets, weak crypto, missing hardening, sensitive data exposure, etc.).
- **AI Analyst** – thin layer that formats evidence for Large Language Models to generate human‑readable explanations. AI only interprets collected facts, never invents them.
- **Reporter** – renders results as JSON, HTML, or plain text.

## Data flow

Binary → Static collector + Dynamic tracer → Evidence graph → Security rules → Findings → AI explanation (optional) → Report
