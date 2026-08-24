# Frequently Asked Questions

## What is RuntimeXRay?

RuntimeXRay is a security posture analyzer for **compiled applications**.  
It runs your binary in a controlled sandbox, collects both **static** (ELF structure, hardening flags) and **dynamic** (system call tracing, memory scanning) evidence, and produces a human-readable security report.  
AI‑generated explanations are optional and currently planned for future releases.

Think of it as “`checksec` on steroids + runtime tracing + memory scanning + evidence‑backed findings”.

---

## How is RuntimeXRay different from antivirus?

| Antivirus                          | RuntimeXRay                           |
|------------------------------------|---------------------------------------|
| Protects a running system from **external malware** | Helps **developers** find weaknesses in their **own software** |
| Detects known malicious patterns   | Reveals **evidence** of insecure practices |
| Verdict: `clean / infected`        | Report: `finding + evidence + severity + fix` |
| Runs in background, system‑wide    | Launched on‑demand for a specific binary in a sandbox |

RuntimeXRay **does not** look for viruses. It looks for things like:

- Hardcoded API keys and private keys
- Secrets lingering in memory after use
- Weak cryptographic algorithms (MD5, DES, …)
- Missing binary hardening (NX, PIE, RELRO, stack canary)
- Sensitive data crossing the network boundary
- Unexpected data flows that could leak credentials

The result is a **security posture scorecard** for your compiled code, not a malware alarm.

---

## How does RuntimeXRay help in the age of AI‑generated (“vibe”) code?

AI assistants now write thousands of lines of code in seconds. This boosts productivity, but it
also creates a serious trust gap:

- **Source review is not enough** – AI‑generated code may look correct yet introduce
  hardcoded tokens, weak encryption, or unexpected network calls that only manifest at runtime.
- **Hidden backdoors or logic bombs** are extremely difficult to spot by reading the source
  alone, but they leave observable traces in the executed binary.
- **Subtle security mistakes** (e.g., leaving a private key in memory for too long, disabling
  certificate validation) often survive code review and static analysis.

RuntimeXRay acts as a **post‑build security verifier** specifically designed for this
challenge. You compile the AI‑written code, run the binary in a sandbox, and get an
evidence‑based report that shows:

- What secrets actually appear in memory and where they travel (data lineage is planned, not yet fully implemented).
- Whether the binary respects modern hardening (NX, PIE, RELRO, stack canary).
- If sensitive data reaches the network, a log file, or an unexpected process.
- Which weak cryptographic primitives are in use, even if called indirectly.

This gives you **confidence that the compiled artifact does not hide dangerous
behaviour** — regardless of how (or by whom) the source was written.

---

## If I have source code, can’t a strong AI just find all the issues?

Source‑level AI is extremely valuable, but it **cannot observe what actually happens at runtime**.  
Many security problems are invisible in the source code alone:

- **Secrets only appear after dynamic decryption** – a key might be decrypted at startup and then sit in memory. No static analysis can say *when* or *for how long*.
- **Behaviour that depends on the environment** – which files are actually read, which variables are used, where data is sent over the network.
- **Compiler‑driven changes** – optimisations can remove security‑critical code (e.g., `memset` to clear a password) or inline functions in a way that changes data lifetime.
- **Binary‑only dependencies** – third‑party libraries without source code.

RuntimeXRay **complements** source‑level AI by providing **evidence from real execution**:
concrete memory contents, system call arguments, actual network destinations, and precise timings.

> **AI on source code says:** “This code path *might* leak a key.”
> **RuntimeXRay says:** “At timestamp 18:32:41.231 a 32‑byte AES key appeared at address 0x7f…, lived for 4.7 seconds, and was passed to `SSL_CTX_use_PrivateKey`. Here is the proof.”

---

## What is “data lineage” and why does it matter?

Data lineage (planned, not yet fully implemented) is the ability to trace **how a piece of sensitive information travels through the application**:
```
config.json
    |
    v
parse_config()
    |
    v
encrypted_secret
    |
    v
decrypt()
    |
    v
plaintext_key (in memory, 4.7 sec)
    |
    +---> TLS setup
    |
    +---> HTTP header -> api.example.com
```

Instead of just saying “a password was found”, RuntimeXRay will show you:

- **Where** the secret came from (file, environment, network)
- **Which functions** touched it
- **How long** it stayed in memory
- **Where** it was sent afterwards

This turns a vague warning into an actionable, evidence‑backed finding.

---

## What does a finding look like?

Every security finding in the report follows a consistent, developer‑friendly structure:

1. **What was found**  
   A factual description, e.g. *“Private RSA key recovered from process memory”*.

2. **Risk level**  
   **Critical / High / Medium / Low / Informational** — based on the sensitivity of the data and the context.

3. **Why it matters**  
   A short explanation of how this issue can be exploited. For example:  
   *“An attacker who obtains a memory dump can extract the private key and impersonate the server.”*

4. **Evidence**  
   Concrete proofs: memory addresses, system call arguments, file paths, timestamps. Everything can be verified.

5. **How to fix**  
   Actionable guidance grounded in security best practices. For instance:  
   *“Use OS‑protected key storage, minimise the plaintext key lifetime, or switch to hardware‑backed keys.”*

6. **Confidence**  
   How certain the engine is about the finding (e.g. **98%** for a hardcoded key, lower for inferred data flows).

This way you don’t just get a list of problems — you get a **remediation roadmap** with all the supporting evidence.

---

## Does RuntimeXRay replace IDA, Ghidra, or Frida?

No. Those are interactive reverse‑engineering tools used by security researchers to manually understand binaries.  
RuntimeXRay is an **automated security reporter for developers**. It does not require you to read assembly or write scripts – you run a single command and get a report.

If you *are* a reverse engineer, RuntimeXRay can be a quick first pass to highlight interesting spots for deeper investigation.

---

## Do I need an AI API key to use RuntimeXRay?

No, the AI analyst is **optional**.  
The core engine works entirely offline and produces structured results (JSON and plain text; HTML planned).  
If you provide an API key (e.g., DeepSeek), RuntimeXRay can generate **human‑readable explanations** for each finding, but this is a bonus layer, not a requirement.

---

## Can I run RuntimeXRay on production servers?

The current MVP is designed for **controlled lab/sandbox environments**.  
Production analysis is out of scope for now, because tracing and memory inspection can affect performance and stability.  
We plan to explore low‑overhead tracing backends (e.g., eBPF) in the future to enable production‑friendly analysis.

---

## How do I report a security vulnerability in RuntimeXRay itself?

Please follow our [Security Policy](SECURITY.md).  
Send an email to **[security@runtimexray.com](mailto:security@runtimexray.com)** – do **not** open a public issue.

---

## Where can I learn more?

- Visit our website: [runtimexray.com](https://runtimexray.com)
- Read the [Architecture](ARCHITECTURE.md) document
- See the [Threat Model](THREAT_MODEL.md) to understand what we can and cannot prove
- Check the [Contributing guidelines](CONTRIBUTING.md) if you want to help