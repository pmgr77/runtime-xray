# Security Checks in RuntimeXRay

This document describes the static and dynamic security checks currently performed by RuntimeXRay on ELF binaries.

## Table of Contents
- [NX (No eXecute)](#nx-no-execute)
- [PIE (Position-Independent Executable)](#pie-position-independent-executable)
- [RELRO (RELocation Read-Only)](#relro-relocation-read-only)
- [Stack Canary](#stack-canary)
- [Output Filtering](#output-filtering)
- [Dangerous API Detection](#dangerous-api-detection)
- [Dynamic Analysis Findings](#dynamic-analysis-findings)
- [Memory Analysis Findings](#memory-analysis-findings)
- [Real-world Examples](#real-world-examples)

---

## NX (No eXecute)

### What it is
NX marks memory pages (especially the stack and heap) as non-executable. The CPU will refuse to execute code from these pages.

### Why it matters
Many classic buffer overflow attacks inject shellcode into the stack and then jump to it. NX makes this impossible by preventing code execution from stack/heap. Attackers must then use more complex techniques like Return-Oriented Programming (ROP).

### How we detect it
We inspect the `PT_GNU_STACK` program header. If the `PF_X` flag is not set, NX is enabled.

### Example output
```
NX: Enabled
```

---

## PIE (Position-Independent Executable)

### What it is
PIE allows an executable to be loaded at a random base address, similar to shared libraries. This is a prerequisite for full Address Space Layout Randomization (ASLR).

### Why it matters
Without PIE, the main executable is loaded at a fixed address. Attackers know exactly where every function and gadget is located, which makes exploitation much easier. PIE randomizes the base, making addresses unpredictable.

### How we detect it
We check the ELF header field `e_type`. If it is `ET_DYN`, the binary is position-independent.

### Example output
```
PIE: Enabled
```

---

## RELRO (RELocation Read-Only)

### What it is
RELRO protects the Global Offset Table (GOT) from being overwritten. Partial RELRO makes only the `.got` section read-only; Full RELRO also makes `.got.plt` read-only after all relocations are resolved.

### Why it matters
The GOT contains addresses of dynamically linked functions. Attackers often try to overwrite GOT entries to redirect calls (e.g., from `printf` to `system`). RELRO prevents such overwrites.

### How we detect it
- Partial RELRO: presence of `PT_GNU_RELRO` segment.
- Full RELRO: additionally, the dynamic section contains `DT_BIND_NOW` or `DT_FLAGS` with `DF_BIND_NOW`.

### Example output
```
RELRO: Full
```

---

## Stack Canary

### What it is
A stack canary is a random value placed between a function's local variables and the saved return address. Before returning, the function checks that the canary is unchanged. If it was overwritten (by a buffer overflow), the program aborts immediately.

### Why it matters
Canaries detect stack buffer overflows before they can alter the return address. This makes direct return-address hijacking extremely difficult.

### How we detect it
We search the symbol tables (`.dynsym` or `.symtab`) for the symbol `__stack_chk_fail`. If present, stack canary is enabled.

### Example output
```
Canary: Enabled
```

---

## Output Filtering

By default, RuntimeXRay shows findings with severity **Medium and higher** (Critical, High, Medium). Use:
- `--min-severity High` to show only High and Critical.
- `--min-severity Info` or `--verbose` to show all findings including Low/Info.

*Note: `--min-severity=High` (equals form) is also supported.*

---

## Dangerous API Detection

### What it is
RuntimeXRay scans the dynamic and static symbol tables of an ELF binary for imported functions known to be dangerous or obsolete. For each match, it generates a finding with a severity level, a reason for the danger, a recommended safer alternative, and a CWE reference.

### Why it matters
Even well-written programs can unintentionally call insecure functions (e.g., `strcpy`, `system`, `MD5_Init`). These functions are often abused in real-world attacks:
- Buffer overflow via `strcpy` / `sprintf`
- Command injection via `system` / `popen`
- Weak cryptography via `MD5` / `DES`
- Predictable randomness via `rand`
- Insecure temporary files via `mktemp`

Detecting these symbols at the binary level helps developers identify risky code paths without needing source access.

### How we detect it
We parse the ELF section headers to locate symbol tables (`.dynsym` or `.symtab`). We iterate through the symbols, strip any version suffix (e.g., `strcpy@GLIBC_2.2.5`), and compare the base name against a curated list of dangerous APIs. Each entry has:
- Severity
- Description
- Recommendation
- CWE identifier

### Example output
```
Dangerous API usage:
  Dangerous API: strcpy (reason: Unsafe string function that does not check bounds, recommendation: Use strncpy, snprintf, or std::string, cwe: CWE-119)
```

### Current API categories
- **Unsafe string functions**: `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`, `scanf`, `sscanf`, `strncpy`, `strncat`, `strtok`
- **Command execution**: `system`, `popen`
- **Insecure temporary files**: `mktemp`, `tmpnam`, `tempnam`
- **Weak randomness**: `rand`, `random`, `srand`
- **Weak cryptographic hashes**: `MD5_*`, `SHA1_*`
- **Weak encryption**: `DES_*`, `RC4*`
- **Deprecated TLS protocols**: `SSLv3_*`, `TLSv1_*`, `TLSv1_1_*`
- **Memory functions (with caveats)**: `memcpy`, `memmove`, `memset`
- **Non-standard stack allocation**: `alloca`
- **Input parsing**: `getopt`, `getopt_long`
- **Unsafe conversions**: `atoi`, `atol`, `atoll`

*This list is maintained in `src/builtin_analyzers.cpp` and will be expanded over time.*

---

## Dynamic Analysis Findings

In addition to static binary checks, RuntimeXRay can observe a running process using `ptrace` (via the **Tachikoma** component) and generate findings from system call activity.

Currently implemented dynamic findings include:

- **Sensitive file access** – detects attempts to open known sensitive files (e.g., `/etc/shadow`, `~/.ssh/id_rsa`, `~/.aws/credentials`).
- **Suspicious network connection** – flags connections to sensitive ports (22, 3389, 445, 1433, etc.).
- **Sensitive data written** – identifies writes containing strings like `password=`, `api_key=`, `secret=`, `token=`.
- **Sensitive data in child output** – scans the captured stdout/stderr of the traced process for the same patterns.

These findings are still experimental and should be interpreted as indicators of potentially risky behaviour, not as definitive exploits.

### How to run dynamic analysis

```bash
./runtimexray trace /path/to/program
```
Use `--verbose` to show all system calls, not only interesting ones:

```bash
./runtimexray trace --verbose /path/to/program
```
For eBPF-based tracing (requires root):

```bash
sudo ./runtimexray trace --backend ebpf /path/to/program
```

For JSON output:

```bash
./runtimexray trace --output-format json /path/to/program
```

---

## Memory Analysis Findings

RuntimeXRay can also scan the memory of a running process to detect secrets and sensitive data.

Available via:

```bash
./runtimexray mem <pid>
```

Findings include:

- **Secrets in command line arguments** (`/proc/<pid>/cmdline`)
- **Secrets in environment variables** (`/proc/<pid>/environ`)
- **Password‑like strings** in readable memory pages
- **Private key blocks** (PEM markers) in memory

Use `--max-pages` to limit the number of pages scanned, or `--max-pages 0` to skip page scanning entirely and only check cmdline/environ.

---

## Real-world Examples

### `/usr/bin/wget`
Despite full hardening (NX, PIE, Full RELRO, Canary), `wget` imports weak cryptographic algorithms and predictable random functions, which could be dangerous in certain contexts.

```
Dangerous API: DES_set_key (reason: Weak encryption algorithm (known attacks), recommendation: Use AES-GCM or ChaCha20-Poly1305, cwe: CWE-327)
Dangerous API: DES_ecb_encrypt (reason: Weak encryption algorithm (known attacks), recommendation: Use AES-GCM or ChaCha20-Poly1305, cwe: CWE-327)
Dangerous API: random (reason: Weak predictable random number generator, recommendation: Use getrandom(), /dev/urandom, or std::random_device, cwe: CWE-338)
Dangerous API: sprintf (reason: Unsafe string function that does not check bounds or format, recommendation: Use snprintf or std::string, cwe: CWE-119)
```

### `/usr/bin/openssl`
The OpenSSL command-line tool, a mature cryptographic utility, still uses `strcpy`, highlighting that even well-maintained software can contain legacy unsafe functions.

```
Dangerous API: strcpy (reason: Unsafe string function that does not check bounds or format, recommendation: Use strncpy, snprintf, or std::string, cwe: CWE-119)
```

### `/usr/bin/redis-server` and `/usr/bin/redis-cli`

Redis is a widely used in-memory data store. Although the binaries are fully hardened (NX, PIE, Full RELRO, Canary), they rely on weak random number generators (`rand`, `random`, `srand`) and unsafe string functions (`strcpy`, `strcat`). This is particularly relevant because Redis is often targeted when exposed to untrusted networks.

```
Dangerous API: rand (reason: Weak predictable random number generator, recommendation: Use getrandom() or /dev/urandom, cwe: CWE-338)
Dangerous API: strcpy (reason: Unsafe string function that does not check bounds, recommendation: Use strncpy or std::string, cwe: CWE-119)
Dangerous API: strcat (reason: Unsafe string function that does not check bounds, recommendation: Use strncat or std::string, cwe: CWE-119)
```

These examples illustrate that even modern, well-protected services can include legacy APIs that deserve attention during security reviews.

---

*Last updated: 2026-08-24*