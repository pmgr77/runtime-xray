# Threat Model

RuntimeXRay answers the question: *"What could an attacker learn by observing this binary at runtime?"*

## What we can detect (current capabilities)

### Static analysis (`runtimexray analyze`)
- Missing binary hardening (NX, PIE, RELRO, stack canary)
- Imported dangerous/obsolete APIs (`strcpy`, `system`, weak crypto, etc.)
- Architecture, endianness, ELF type, entry point
- Severity‑filtered findings (via `--min-severity`)
- Human‑readable report (`--report FILE`) and JSON report (`--json FILE`)

### Dynamic analysis (`runtimexray trace`)
- Syscall tracing via `ptrace` (x86_64, ARM64) and **eBPF** (`--backend ebpf`)
- Sensitive file access (e.g., `/etc/shadow`, `~/.ssh/id_rsa`)
- Suspicious network connections to sensitive ports (22, 3389, 445, 1433, etc.)
- Writes containing potential credentials/secrets (`password=`, `api_key=`, `secret=`, etc.)
- Sensitive data in captured stdout/stderr of the traced process
- **Fork/thread following** (`--follow-forks` / `--no-follow-forks`) – both ptrace and eBPF backends
- Timeout support (`--timeout <seconds>`)
- Diagnostic logs via `--log-level` / `--log-file`
- Human‑readable report (`--report FILE`) and JSON report (`--json FILE`)

### Memory analysis (`runtimexray mem`)
- Secrets in command‑line arguments (`/proc/<pid>/cmdline`)
- Secrets in environment variables (`/proc/<pid>/environ`)
- Password‑like strings and private key markers in readable memory pages
- Number of scanned pages reported; page scanning can be limited with `--max-pages`
- Human‑readable report (`--report FILE`) and JSON report (`--json FILE`)

### Extensibility via Analyzers
- Users can register custom analyzers implementing `IAnalyzer`.
- Analyzers consume `Evidence` objects and produce `FindingList`.
- Built‑in analyzers cover hardening, dangerous APIs, sensitive files, network, and memory secrets.
- This allows third parties to add their own detection logic without modifying core code, but also means that a malicious or poorly written custom analyzer could influence results.

## Planned detection (future)
- Hardcoded secrets in binary sections
- Secrets lingering in process memory after use
- Weak cryptographic algorithms identified from runtime behaviour
- Data lineage: tracking sensitive data from source to sink
- High‑entropy data detection (for keys and encrypted blobs)
- Network‑boundary detection
- Runtime correlation of static and dynamic evidence

## What we cannot guarantee
- Detection of **all** possible vulnerabilities — RuntimeXRay is an observation tool, not a formal verifier.
- Exploitability of a finding — we provide evidence, the user must assess impact.
- Coverage of all execution paths — dynamic analysis only observes the executed trace.
- Analysis of heavily obfuscated or packed binaries without additional unpacking.
- Complete accuracy of dynamic findings — `ptrace`‑based tracing may be evaded by anti‑debugging techniques (countermeasures are planned); eBPF is less intrusive but may have kernel‑version or permission constraints.
- Reading of large data transfers — for performance and safety, `write` buffers are capped at 4 KB; larger writes are skipped.
- Memory scanning of arbitrary processes may require root privileges depending on `ptrace_scope`. Self‑scanning and child processes usually work without root.
- Memory scanning is limited by `--max-pages`; a low limit may miss secrets in later memory pages. Use `0` to skip page scanning entirely (only cmdline/environ are scanned).
- Detectors currently focus on known patterns (`password=`, private key markers). Unknown or heavily obfuscated secrets may not be detected.
- Custom analyzers are not sandboxed; they run with the same privileges as the RuntimeXRay process and could affect performance, stability, or correctness if not carefully written.
- The eBPF backend may not be available on older kernels or with restrictive kernel configurations; it requires root and access to `tracefs` and BPF subsystem.

## Assumptions
- The target binary runs on Linux x86_64 or ARM64.
- Analysis is performed in a controlled lab/sandbox; production analysis is out of scope for the MVP.
- The user has legal rights to analyze the binary.
- The runtime environment is not actively hostile to tracing (no anti‑debugging), although we recognise that real-world binaries may attempt to evade ptrace and are working on countermeasures.
- The target process is non-interactive during tracing; interactive or highly concurrent processes may produce incomplete traces.
- For memory scanning of other processes, the user may need elevated privileges (root or appropriate capabilities) on systems with Yama LSM enabled.
- Users who register custom analyzers are responsible for their correctness and security implications.
- The `--log-level debug` flag produces detailed diagnostic output (including syscall traces); this is intended for debugging and may produce large logs.

## Key improvements over the previous version
- Fork/thread following is now fully implemented (both backends).
- eBPF backend is available as an alternative to ptrace.
- CLI options have been simplified and separated (report vs logs).
- JSON and text reports are both supported via explicit flags.
- Diagnostic logging is now structured and level‑controlled.
- The threat model now reflects the current implementation status more accurately.