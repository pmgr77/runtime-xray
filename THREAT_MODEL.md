# Threat Model

RuntimeXRay answers the question: *"What could an attacker learn by observing this binary at runtime?"*

## What we can detect (current capabilities)

### Static analysis
- Missing binary hardening (NX, PIE, RELRO, stack canary)
- Imported dangerous/obsolete APIs (`strcpy`, `system`, weak crypto, etc.)
- Architecture, endianness, ELF type, entry point

### Dynamic analysis (early, via `xray-trace`)
- Sensitive file access (e.g., `/etc/shadow`, `~/.ssh/id_rsa`)
- Suspicious network connections to sensitive ports (22, 3389, 445, 1433, etc.)
- Writes containing potential credentials/secrets (`password=`, `api_key=`, `secret=`, etc.)
- Sensitive data in captured stdout/stderr of the traced process

## Planned detection (future)
- Hardcoded secrets in binary sections
- Secrets lingering in process memory after use
- Weak cryptographic algorithms identified from runtime behaviour
- Data lineage: tracking sensitive data from source to sink

## What we cannot guarantee
- Detection of **all** possible vulnerabilities — RuntimeXRay is an observation tool, not a formal verifier.
- Exploitability of a finding — we provide evidence, the user must assess impact.
- Coverage of all execution paths — dynamic analysis only observes the executed trace.
- Analysis of heavily obfuscated or packed binaries without additional unpacking.
- Complete accuracy of dynamic findings — current `ptrace`-based tracing may miss events if the target uses anti-debugging/anti-tracing techniques.
- Analysis of multi-process applications — initial version of Tachikoma follows only the traced child, not all descendants (fork/clone handling not fully implemented).
- Reading of large data transfers — for performance and safety, `write` buffers are capped at 4 KB; larger writes are skipped.

## Assumptions
- The target binary runs on Linux x86_64 or ARM64.
- Analysis is performed in a controlled lab/sandbox; production analysis is out of scope for the MVP.
- The user has legal rights to analyze the binary.
- The runtime environment is not actively hostile to tracing (no anti‑debugging), although we recognise that real-world binaries may attempt to evade ptrace and are working on countermeasures.
- The target process is non-interactive during tracing; interactive or highly concurrent processes may produce incomplete traces.