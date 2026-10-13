# Security Checks in RuntimeXRay

This document describes the security checks currently implemented by RuntimeXRay.

RuntimeXRay uses a common graph-based detection architecture for both static and runtime evidence:

```text
Collected observations
        ↓
   LineageGraph
        ↓
DetectionRuleRegistry
        ↓
  DetectionEngine
        ↓
      Findings
```

Collectors record facts.

Detection rules derive security conclusions from those facts.

The current built-in rules are:

```text
Primary:
  builtin.hardening
  builtin.dangerous_api
  builtin.sensitive_file_access
  builtin.network
  builtin.sensitive_data_presence

Composite:
  builtin.sensitive_data_flow
  builtin.sensitive_value_cross_process_pipe_chain
```

---

# Table of Contents

- [Severity filtering](#severity-filtering)
- [Static hardening checks](#static-hardening-checks)
  - [NX](#nx-no-execute)
  - [PIE](#pie-position-independent-executable)
  - [RELRO](#relro-relocation-read-only)
  - [Stack Canary](#stack-canary)
- [Dangerous and legacy API detection](#dangerous-and-legacy-api-detection)
- [Sensitive filesystem access](#sensitive-filesystem-access)
- [Network-service detection](#network-service-detection)
- [Sensitive-data presence](#sensitive-data-presence)
- [Sensitive-data flow](#sensitive-data-flow)
- [Cross-process pipe-chain detection](#cross-process-pipe-chain-detection)
- [Memory analysis](#memory-analysis)
- [Secret fingerprinting and redaction](#secret-fingerprinting-and-redaction)
- [Backend differences](#backend-differences)
- [Interpreting findings](#interpreting-findings)

---

# Severity filtering

RuntimeXRay uses these finding severities:

```text
Critical
High
Medium
Low
Info
```

The default minimum severity is:

```text
Medium
```

This means that by default:

```text
Critical → shown
High     → shown
Medium   → shown
Low      → hidden
Info     → hidden
```

To show all findings:

```bash
runtimexray analyze --min-severity Info /bin/ls
```

To show only High and Critical:

```bash
runtimexray analyze --min-severity High /bin/ls
```

The same filtering model applies to runtime and memory findings.

---

# Static hardening checks

Static ELF hardening properties are collected as `Static` observations.

`HardeningRule` converts them into Findings with:

```text
kind = binary_hardening
rule_id = builtin.hardening
```

Current severity policy is:

```text
Disabled → High
Partial  → Low
Enabled / Full → Info
```

This means secure hardening states are still represented as findings when `--min-severity Info` is used.

---

# NX (No eXecute)

## What it is

NX prevents selected memory regions, especially the stack, from being executable.

It is an important exploit-mitigation mechanism because it makes direct execution of injected shellcode more difficult.

NX does not prevent all memory-corruption attacks.

Techniques such as ROP can still be possible.

---

## How RuntimeXRay detects it

RuntimeXRay examines the ELF `PT_GNU_STACK` program header.

If the stack segment is not marked executable, RuntimeXRay reports:

```text
NX: Enabled
```

If executable stack permission is present:

```text
NX: Disabled
```

---

## Severity

```text
NX: Enabled  → Info
NX: Disabled → High
```

---

# PIE (Position-Independent Executable)

## What it is

PIE allows the executable image to be loaded at varying addresses.

This allows ASLR to randomize the main executable's location.

Without PIE, executable code addresses can remain more predictable.

---

## How RuntimeXRay detects it

RuntimeXRay examines the ELF type.

A position-independent executable is represented by:

```text
ET_DYN
```

RuntimeXRay reports:

```text
PIE: Enabled
```

or:

```text
PIE: Disabled
```

---

## Severity

```text
PIE: Enabled  → Info
PIE: Disabled → High
```

---

# RELRO (RELocation Read-Only)

## What it is

RELRO protects relocation-related structures such as the Global Offset Table from modification after linking work is completed.

RuntimeXRay distinguishes:

```text
Disabled
Partial
Full
```

---

## Partial RELRO

Partial RELRO is identified by the presence of:

```text
PT_GNU_RELRO
```

without immediate binding for all relocations.

Example:

```text
RELRO: Partial
```

---

## Full RELRO

Full RELRO additionally requires immediate relocation binding.

RuntimeXRay checks relevant dynamic flags such as:

```text
DT_BIND_NOW
```

or equivalent `DF_BIND_NOW` behavior.

Example:

```text
RELRO: Full
```

---

## Severity

```text
RELRO: Disabled → High
RELRO: Partial  → Low
RELRO: Full     → Info
```

---

# Stack Canary

## What it is

Stack canaries help detect stack-buffer overwrites before a function returns.

A canary value is placed in the stack frame and checked before returning.

If overwritten, the process normally terminates rather than continuing with a corrupted return path.

---

## How RuntimeXRay detects it

RuntimeXRay looks for the symbol:

```text
__stack_chk_fail
```

in ELF symbol information.

Presence indicates that stack-protector instrumentation is present somewhere in the binary.

---

## Important limitation

This does not prove that every function was compiled with stack protection.

It only proves that stack-protector support is referenced by the binary.

---

## Severity

```text
Canary: Enabled  → Info
Canary: Disabled → High
```

---

# Dangerous and legacy API detection

The current implementation is:

```text
DangerousApiRule
```

with stable rule ID:

```text
builtin.dangerous_api
```

The rule operates on static imported-symbol observations.

It strips ELF symbol-version suffixes before classification.

For example:

```text
strcpy@GLIBC_2.2.5
```

is evaluated as:

```text
strcpy
```

---

# What an API finding means

A dangerous-API finding means:

> The compiled binary references an API that may deserve security review.

It does not prove:

- that the function is actually executed;
- that attacker-controlled data reaches it;
- that its use is unsafe in this application;
- that exploitation is possible.

---

# Current API categories

## Unsafe string APIs — High

Current examples:

```text
strcpy
strcat
sprintf
vsprintf
gets
scanf
sscanf
```

Typical recommendation:

> Use bounded operations or safer string abstractions.

Associated weakness category:

```text
CWE-119
```

---

## Bounded string APIs with caveats — Medium

```text
strncpy
strncat
```

These APIs can still be misused, especially around null termination and size calculations.

Associated weakness:

```text
CWE-120
```

---

## Shell execution — High

```text
system
popen
```

Risk:

Untrusted input may become shell syntax.

Recommended direction:

Use exec-style APIs with explicit argument arrays when shell interpretation is not required.

Associated weakness:

```text
CWE-78
```

---

## Temporary-file APIs — Medium

```text
mktemp
tmpnam
tempnam
```

Risk:

Predictable or unsafe temporary-file naming.

Recommended direction:

```text
mkstemp
```

or another race-resistant temporary-file mechanism.

Associated weakness:

```text
CWE-377
```

---

## Weak random-number APIs — Medium

```text
rand
random
srand
```

These are not appropriate for cryptographic secrets.

Recommended alternatives include:

```text
getrandom()
/dev/urandom
cryptographically secure library RNGs
```

Associated weakness:

```text
CWE-338
```

---

## Weak hash APIs — High

RuntimeXRay currently recognizes families beginning with:

```text
MD5_
SHA1_
```

Associated weakness:

```text
CWE-327
```

---

## Weak encryption APIs — High

Current families include:

```text
DES_
RC4...
```

Associated weakness:

```text
CWE-327
```

---

## Deprecated TLS APIs — High

Current examples include:

```text
SSLv3_client_method
SSLv3_server_method
TLSv1_client_method
TLSv1_server_method
TLSv1_1_client_method
TLSv1_1_server_method
```

Recommended direction:

Use currently supported TLS versions such as TLS 1.2 or TLS 1.3.

Associated weakness:

```text
CWE-326
```

---

## Memory operations — Low

Current examples:

```text
memcpy
memmove
memset
```

These functions are not inherently vulnerabilities.

RuntimeXRay flags them at Low severity because unsafe size calculations may make them security relevant.

Associated weakness:

```text
CWE-805
```

---

## Stack allocation — Medium

```text
alloca
```

Risk:

Unbounded or attacker-controlled stack allocation may exhaust stack space.

Associated weakness:

```text
CWE-770
```

---

## Command-line parsing — Info

```text
getopt
getopt_long
```

These APIs are not dangerous by themselves.

They are included as informational review signals around input handling.

Associated weakness category:

```text
CWE-20
```

---

## Numeric conversion — Low

```text
atoi
atol
atoll
```

These APIs provide weak error reporting.

Recommended direction:

```text
strtol
strtoul
```

with explicit validation.

Associated weakness:

```text
CWE-190
```

---

## Tokenization — Low

```text
strtok
```

`strtok` modifies input and uses shared state.

Recommended direction:

```text
strtok_r
```

or safer parser abstractions.

Associated weakness:

```text
CWE-366
```

---

## Legacy hostname-resolution APIs — Medium

Current examples:

```text
gethostbyname
gethostbyaddr
```

Recommended replacements:

```text
getaddrinfo
getnameinfo
```

Associated weakness:

```text
CWE-362
```

---

## Legacy address formatting — Low

```text
inet_ntoa
```

The function uses shared static storage.

Recommended replacement:

```text
inet_ntop
```

Associated weakness:

```text
CWE-362
```

---

# Source of truth

The current API classification is implemented in:

```text
src/dangerous_api_rule.cpp
```

This file, not this document, is the authoritative implementation if the two ever diverge.

---

# Sensitive filesystem access

The current rule is:

```text
SensitiveFileAccessRule
```

with rule ID:

```text
builtin.sensitive_file_access
```

and semantic kind:

```text
sensitive_resource_access
```

The rule examines supported:

```text
open
openat
```

events with resolved paths.

---

# Current path classification

## Critical

Current path patterns include:

```text
/etc/sudoers
/etc/shadow
/root/
/.ssh
.ssh
.aws/credentials
.gnupg
id_rsa
id_dsa
id_ecdsa
id_ed25519
```

---

## High

Paths containing strings such as:

```text
secret
token
password
credential
api_key
```

---

## Medium

```text
/etc/passwd
/etc/group
```

---

## Low

```text
/etc/hosts
/etc/resolv.conf
```

---

## Info

```text
/etc/hostname
/etc/machine-id
```

---

# Access outcomes

RuntimeXRay distinguishes the syscall result.

A successful open produces:

```text
Sensitive file opened
```

with:

```text
outcome = opened
errno   = 0
```

---

## Permission denied

For errors such as:

```text
EACCES
EPERM
```

the Finding becomes:

```text
Sensitive file access denied
```

---

## Missing file

For:

```text
ENOENT
```

RuntimeXRay reports:

```text
Sensitive file access attempted
```

with failed outcome.

---

## Other failures

Other unsuccessful opens produce:

```text
Sensitive file access failed
```

---

# Important interpretation

A failed access attempt is still observable security evidence.

For example:

```text
open("/etc/shadow") → -EACCES
```

does not mean the file was read.

But it does prove that the process attempted the operation.

---

# Network-service detection

The current rule is:

```text
NetworkRule
```

with rule ID:

```text
builtin.network
```

and Finding kind:

```text
suspicious_network_connection
```

---

# Current detection model

The rule currently examines:

```text
connect
```

events with resolved endpoints.

It flags selected security-sensitive service ports.

Current ports are:

```text
22    SSH
3389  RDP
445   SMB
1433  Microsoft SQL Server
3306  MySQL
```

Current severity:

```text
Medium
```

---

# Important limitation

RuntimeXRay currently uses a fixed service-port classification.

It does not yet know:

- which destinations are expected by the application;
- which network ranges are approved;
- whether the destination is malicious;
- whether the connection succeeded in a meaningful application-level sense;
- whether data was exfiltrated.

Therefore a Finding means:

> The process attempted a connection to a service port currently classified by RuntimeXRay as security-sensitive.

It should not be interpreted automatically as malicious traffic.

---

# Sensitive-data presence

The current rule is:

```text
SensitiveDataPresenceRule
```

with rule ID:

```text
builtin.sensitive_data_presence
```

and kind:

```text
sensitive_data_presence
```

---

# How sensitive values are represented

Secret extraction produces `Data` observations containing:

```text
data_type
source
secret_type
fingerprint
size
address, where relevant
```

A `SensitiveDataPresenceRule` Finding is created when a `Data` observation has both:

```text
secret_type
fingerprint
```

---

# Current severity

Sensitive-data presence is currently:

```text
High
```

---

# Finding attributes

Typical attributes include:

```text
secret_type
location
fingerprint
length
address
```

The address is included only when available.

---

# Secret extraction

Current text-based detection recognizes keyword/value forms including keywords such as:

```text
password
passwd
pwd
pass
pswd
password_hash
password_salt
password_encrypted
hashed_password
api_key
secret
token
credentials
credential
auth
```

Typical forms include:

```text
password=value
api_key:value
token="value"
```

The extracted value must currently have a minimum length of six characters.

The extractor bounds normal value extraction to 128 characters.

---

# Private-key detection

RuntimeXRay currently recognizes PEM-style markers including:

```text
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
```

When an end marker is available, RuntimeXRay fingerprints the observed key block.

If the end marker is unavailable, the detector uses a bounded observed region.

---

# Detection locations

Sensitive data may be observed from sources such as:

```text
memory
cmdline
environment
supported syscall buffers
```

The exact `data_type` records where the evidence was observed.

---

# Sensitive-data flow

The current composite rule is:

```text
SensitiveDataFlowRule
```

with rule ID:

```text
builtin.sensitive_data_flow
```

and kind:

```text
sensitive_data_flow
```

Current severity:

```text
High
```

---

# Supported correlation

The current rule looks for:

```text
file
  ↓
read / recvfrom
  ↓
same exact fingerprint
  ↓
scanner-derived process memory
  ↓
write / writev / sendto
  ↓
connected socket
```

---

# Required conditions

The rule requires:

1. an input event:
   ```text id="3yuvkw"
   read
   recvfrom
   ```

2. the input FD to resolve to a file;

3. a `Data` observation where:
   ```text id="m9rfpi"
   data_type == memory
   ```

4. an output event:
   ```text id="ydn4zr"
   write
   writev
   sendto
   ```

5. the output FD to resolve to a connected socket;

6. all three observations to use the same exact fingerprint;

7. all observations to belong to the same:
   ```text id="p5f66o"
   process_instance_id
   exec_generation
   ```

8. the output event to occur after the input event.

---

# Why `--scan-memory` matters

The memory leg must come from an independent memory scan.

The rule does not create a fake memory relationship merely because the same secret was seen in a syscall buffer.

Therefore the current end-to-end correlation normally requires:

```bash
runtimexray trace --scan-memory /path/to/application
```

---

# Finding output

A correlated Finding has title:

```text
Sensitive object observed from file to socket
```

and attributes such as:

```text
fingerprint
secret_type
source_file
socket_destination
confidence
read_syscall
send_syscall
```

Current confidence string:

```text
exact-fingerprint-match
```

---

# Important limitation

Fingerprint equality proves exact value identity.

It does not by itself prove causality.

The current rule combines fingerprint equality with:

- same execution session;
- file/resource resolution;
- memory observation;
- event ordering;
- socket destination context.

Even then, the result should be interpreted as an observed sensitive-value path, not proof of malicious exfiltration.

---

# Cross-process pipe-chain detection

The current rule is:

```text
SensitiveValueCrossProcessPipeChainRule
```

with rule ID:

```text
builtin.sensitive_value_cross_process_pipe_chain
```

and kind:

```text
sensitive_value_cross_process_pipe_chain
```

Current severity:

```text
High
```

---

# Purpose

This rule detects the same sensitive value across two or more explicit cross-process pipe DataFlow boundaries.

Example:

```text
Process A
   │
   │ write(pipe 1)
   ▼
Process B
   │
   │ read(pipe 1)
   │
   │ write(pipe 2)
   ▼
Process C
```

---

# Required evidence

A pipe boundary must have:

- `DataFlow` edge;
- matching fingerprint on write and read;
- same nonzero `resource_id`;
- `resource_type == pipe`;
- source role:
  ```text id="63ditz"
  write
  ```
- destination role:
  ```text id="d167jh"
  read
  ```
- different `process_instance_id` values.

---

# Chaining boundaries

Two pipe boundaries may be connected only when:

- the first boundary ends in the same execution session where the second begins;
- the fingerprint matches;
- the incoming read completed before the outgoing write began.

Execution session identity uses:

```text
process_instance_id
exec_generation
```

---

# Minimum chain

A Finding requires at least:

```text
2 cross-process pipe boundaries
```

A single process-to-process pipe transfer remains graph evidence but does not produce this higher-level chain Finding.

---

# Finding evidence

The chain Finding records:

```text
evidence_observation_seqs
evidence_edges
supporting_finding_ids
```

Its `evidence_edges` contain the actual `DataFlow` relationships.

This is important:

> The pipe-chain proof is based on explicit graph DataFlow edges, not merely repeated fingerprints.

---

# Current attributes

The rule records information including:

```text
fingerprint
boundary_count
session_count
resource_ids
process_instance_ids
sessions
confidence
secret_types
```

Current confidence value:

```text
explicit-pipe-dataflow-chain
```

---

# Supporting findings

Matching `sensitive_data_presence` Findings may be referenced through:

```text
supporting_finding_ids
```

but only when they:

- use the same fingerprint;
- belong to a session participating in the actual chain.

A disconnected observation of the same value is not attached merely because its fingerprint matches.

---

# Memory analysis

The standalone command is:

```bash
runtimexray mem <pid>
```

Current sources include:

```text
/proc/<pid>/cmdline
/proc/<pid>/environ
readable memory mappings
```

---

# Limit page scanning

Use:

```bash
runtimexray mem --max-pages 500 <pid>
```

Current default:

```text
1000 pages
```

---

# Skip normal memory pages

Use:

```bash
runtimexray mem --max-pages 0 <pid>
```

This still examines:

```text
cmdline
environment
```

but skips regular mapped-page scanning.

---

# Memory-scan limitations

Memory scanning can miss data because:

- the process changes while scanning;
- the value exists briefly;
- access is denied;
- the scan limit is reached;
- the secret is encoded or transformed;
- the value does not match supported patterns;
- the process exits;
- the mapping is unreadable.

Memory scanning is not an atomic process snapshot.

---

# Secret fingerprinting and redaction

RuntimeXRay computes a per-run HMAC-SHA256 fingerprint from the exact extracted secret value.

Conceptually:

```text
exact secret
     ↓
per-run HMAC-SHA256
     ↓
fingerprint
```

The HMAC key is random for each RuntimeXRay execution.

This means:

- the same exact secret in one run receives the same fingerprint;
- fingerprints normally differ between separate RuntimeXRay runs;
- normal reports can correlate values without printing them.

---

# Why not plain SHA-256?

Low-entropy secrets may be guessable using offline candidate hashing.

A random per-run HMAC key prevents the report fingerprint from acting as a reusable unsalted hash of the secret.

---

# Redaction

Raw secret content is hidden by default.

To deliberately disclose secret values:

```bash
runtimexray mem --show-secrets <pid>
```

or:

```bash
runtimexray trace --show-secrets /path/to/application
```

This mode should be reserved for local debugging.

Do not use it in normal CI.

---

# Output and logging

RuntimeXRay separates three concepts:

```text
Findings
Runtime logs
Detailed syscall diagnostics
```

---

## Human-readable report

Default:

```text
stdout
```

or:

```bash
--report report.txt
```

---

## JSON

Use:

```bash
--json report.json
```

Both text and JSON can be generated in one execution.

---

## Logs

Runtime logs go to stderr by default.

Use:

```bash
--log-level debug
```

for detailed diagnostics.

Write logs separately with:

```bash
--log-file debug.log
```

---

# Backend differences

ptrace and eBPF should not be treated as identical capture mechanisms.

---

# ptrace

ptrace can:

- observe syscall entry and exit;
- read process memory;
- follow process/thread lifecycle;
- inspect supported buffers directly.

But it is intrusive and changes target timing.

---

# eBPF

eBPF captures supported information in the kernel tracing path.

Current kernel-side limits include:

```text
MAX_PATH      = 256
MAX_PAYLOAD   = 256
MAX_SOCKADDR  = 128
```

Current `writev` capture inspects only the first iovec.

Therefore a secret outside the captured payload may not be observed by eBPF.

---

# Large payloads

RuntimeXRay should not be interpreted as a packet capture or complete arbitrary-buffer recorder.

Payload inspection is intentionally bounded.

This improves performance and limits the amount of sensitive data collected.

---

# Interpreting findings

A RuntimeXRay Finding should be interpreted according to exactly what its evidence supports.

Examples:

---

## Binary hardening

```text
PIE: Disabled
```

Means:

> The ELF hardening property was observed as disabled.

Does not mean:

> The binary is exploitable.

---

## Dangerous API

```text
Dangerous API: system
```

Means:

> The binary imports the `system` API.

Does not mean:

> Command injection occurred.

---

## Sensitive file

```text
Sensitive file access denied
```

Means:

> The process attempted to access a classified path and the kernel denied it.

Does not mean:

> Sensitive file content was read.

---

## Network

```text
Suspicious network connection
```

Means:

> A connection attempt targeted one of the currently classified sensitive service ports.

Does not mean:

> The destination was malicious.

---

## Sensitive-data presence

```text
Sensitive data observed
```

Means:

> RuntimeXRay observed a value matching its current sensitive-data criteria.

Does not mean:

> An attacker obtained it.

---

## Sensitive-data flow

```text
Sensitive object observed from file to socket
```

Means:

> The same exact sensitive value was observed in the currently supported file-input, independent-memory, and socket-output evidence points.

Does not mean:

> Malicious exfiltration was proven.

---

## Pipe chain

```text
Sensitive value observed across a cross-process pipe chain
```

Means:

> Explicit pipe DataFlow evidence supports movement of the same exact sensitive value across at least two process boundaries.

This is stronger than simply finding the same string in multiple processes.

---

# Current detection-rule summary

| Rule | Stage | Finding kind | Typical severity |
|---|---|---|---|
| `builtin.hardening` | Primary | `binary_hardening` | High / Low / Info |
| `builtin.dangerous_api` | Primary | dangerous API finding | API-specific |
| `builtin.sensitive_file_access` | Primary | `sensitive_resource_access` | Critical → Info |
| `builtin.network` | Primary | `suspicious_network_connection` | Medium |
| `builtin.sensitive_data_presence` | Primary | `sensitive_data_presence` | High |
| `builtin.sensitive_data_flow` | Composite | `sensitive_data_flow` | High |
| `builtin.sensitive_value_cross_process_pipe_chain` | Composite | `sensitive_value_cross_process_pipe_chain` | High |

---

# What RuntimeXRay does not currently claim

RuntimeXRay does not currently provide:

- universal taint tracking;
- arbitrary transformed-value tracking;
- exact secret lifetime measurement;
- arbitrary function-level tracing;
- full buffer capture;
- proof of exploitability;
- proof of malicious intent;
- proof of successful remote exfiltration;
- complete execution-path coverage.

See [../THREAT_MODEL.md](../THREAT_MODEL.md) for the detailed boundaries.

---

# Source-of-truth principle

Documentation describes intended behavior.

The implementation and automated tests remain the ultimate source of truth for current behavior.

Important implementation files include:

```text
src/hardening_rule.cpp
src/dangerous_api_rule.cpp
src/sensitive_file_access_rule.cpp
src/network_rule.cpp
src/sensitive_data_presence_rule.cpp
src/sensitive_data_flow_rule.cpp
src/sensitive_value_cross_process_pipe_chain_rule.cpp
src/secret_extractor.cpp
```

---

*Last reviewed: 2026-10-13*