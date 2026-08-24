# Architecture

RuntimeXRay is a modular tool that analyzes the security posture of compiled applications by combining static analysis, dynamic tracing, and memory scanning.

## High‑level components

- **CLI** (`runtimexray`) – unified command dispatcher with subcommands:
  - `analyze` – static ELF parsing and hardening checks
  - `trace` – dynamic tracing using Tachikoma (ptrace)
  - `mem` – process memory scanning (cmdline, environ, readable pages)

- **Collectors** – gather raw evidence without performing analysis:
  - *Static*: ELF parser, binary hardening property extraction.
  - *Dynamic*: ptrace tracer, syscall interception, file/network/write evidence capture.
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

- **AI Analyst** – optional layer that uses LLMs to generate human‑readable explanations for findings. AI only interprets collected evidence, never invents it.

- **Reporter** – renders results as plain text or JSON (HTML planned).

## Data flow

Binary / Process  
→ Collectors (Static, Dynamic, Memory)  
→ Evidence  
→ Analyzer Registry  
→ Analyzers (built‑in + custom)  
→ Findings  
→ Optional AI explanation  
→ Report

All subcommands share global options (`--verbose`, `--min-severity`, `--output-format`) and central finding filtering, ensuring consistent behaviour across `runtimexray analyze`, `trace`, and `mem`.