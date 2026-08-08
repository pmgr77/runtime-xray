# Threat Model

RuntimeXRay answers the question: *"What could an attacker learn by observing this binary at runtime?"*

## What we can detect (examples)
- Hardcoded secrets (API keys, private keys, certificates)
- Secrets lingering in process memory after use
- Weak cryptographic algorithms
- Missing binary hardening (NX, PIE, RELRO, stack canary)
- Sensitive data transmitted over the network
- Suspicious process behaviors

## What we cannot guarantee
- Detection of **all** possible vulnerabilities — RuntimeXRay is an observation tool, not a formal verifier.
- Exploitability of a finding — we provide evidence, the user must assess impact.
- Coverage of all execution paths — dynamic analysis only observes the executed trace.
- Analysis of heavily obfuscated or packed binaries without additional unpacking.

## Assumptions
- The target binary runs on Linux x86_64 or ARM64.
- Analysis is performed in a controlled lab/sandbox; production analysis is out of scope for the MVP.
- The user has legal rights to analyze the binary.
- The runtime environment is not actively hostile to tracing (no anti‑debugging).
