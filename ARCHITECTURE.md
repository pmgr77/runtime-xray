# Architecture

RuntimeXRay is a modular tool that analyzes the security posture of compiled applications by combining static analysis, dynamic tracing, and memory scanning.

## High‑level components

- **CLI** (`runtimexray`) – unified command dispatcher with subcommands:
  - `analyze` – static ELF parsing and hardening checks
  - `trace` – dynamic tracing using Tachikoma (ptrace)
  - `mem` – process memory scanning (cmdline, environ, readable pages)
- **Collectors** – gather raw evidence:
  - *Static*: ELF parser, binary hardening checks (checksec‑style).
  - *Dynamic*: ptrace tracer, syscall interception, process memory reader.
  - *Memory*: `/proc` parser, memory secret detectors.
- **Correlation Engine** – builds an event graph and tracks data lineage (source → transformation → sink).
- **Security Rules** – pluggable modules that analyze evidence and produce findings (hardcoded secrets, weak crypto, missing hardening, sensitive data exposure, etc.).
- **AI Analyst** – thin layer that formats evidence for Large Language Models to generate human‑readable explanations. AI only interprets collected facts, never invents them.
- **Reporter** – renders results as plain text, with JSON and HTML planned.

## Data flow

Binary / Process → Static collector + Dynamic tracer + Memory scanner → Evidence graph → Security rules → Findings → AI explanation (optional) → Report

All subcommands share global options (`--verbose`, `--min-severity`, `--output-format`) and central finding filtering, ensuring consistent behaviour across `runtimexray analyze`, `trace`, and `mem`.