# Security Checks in RuntimeXRay

This document describes the security checks currently implemented by RuntimeXRay.

RuntimeXRay uses a common graph-based detection architecture for both static and runtime evidence:

```text id="6sg4ji"
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

```text id="cpag4f"
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

```text id="049zk3"
Critical
High
Medium
Low
Info
```

The default minimum severity is:

```text id="n73t3c"
Medium
```

This means that by default:

```text id="217j71"
Critical → shown
High     → shown
Medium   → shown
Low      → hidden
Info     → hidden
```

To show all findings:

```bash id="jqlkuq"
runtimexray analyze --min-severity Info /bin/ls
```

To show only High and Critical:

```bash id="cswg0p"
runtimexray analyze --min-severity High /bin/ls
```

The same filtering model applies to runtime and memory findings.

---

# Static hardening checks

Static ELF hardening properties are collected as `Static` observations.

`HardeningRule` converts them into Findings with:

```text id="wclvep"
kind = binary_hardening
rule_id = builtin.hardening
```

Current severity policy is:

```text id="kbwgsa"
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

```text id="sgyg68"
NX: Enabled
```

If executable stack permission is present:

```text id="109mlc"
NX: Disabled
```

---

## Severity

```text id="l74ad4"
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

```text id="lj4qwq"
ET_DYN
```

RuntimeXRay reports:

```text id="wawrv5"
PIE: Enabled
```

or:

```text id="ym8gcl"
PIE: Disabled
```

---

## Severity

```text id="s9a5fq"
PIE: Enabled  → Info
PIE: Disabled → High
```

---

# RELRO (RELocation Read-Only)

## What it is

RELRO protects relocation-related structures such as the Global Offset Table from modification after linking work is completed.

RuntimeXRay distinguishes:

```text id="1t7k6n"
Disabled
Partial
Full
```

---

## Partial RELRO

Partial RELRO is identified by the presence of:

```text id="ok5jmp"
PT_GNU_RELRO
```

without immediate binding for all relocations.

Example:

```text id="9raov4"
RELRO: Partial
```

---

## Full RELRO

Full RELRO additionally requires immediate relocation binding.

RuntimeXRay checks relevant dynamic flags such as:

```text id="ueebhr"
DT_BIND_NOW
```

or equivalent `DF_BIND_NOW` behavior.

Example:

```text id="r0osz6"
RELRO: Full
```

---

## Severity

```text id="vvdd9d"
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

```text id="gfjwmz"
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

```text id="2cnd98"
Canary: Enabled  → Info
Canary: Disabled → High
```

---

# Dangerous and legacy API detection

The current implementation is:

```text id="s1fnsv"
DangerousApiRule
```

with stable rule ID:

```text id="fc0522"
builtin.dangerous_api
```

The rule operates on static imported-symbol observations.

It strips ELF symbol-version suffixes before classification.

For example:

```text id="6qik4n"
strcpy@GLIBC_2.2.5
```

is evaluated as:

```text id="0su82e"
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

```text id="yswq9p"
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

```text id="2pdisz"
CWE-119
```

---

## Bounded string APIs with caveats — Medium

```text id="75w197"
strncpy
strncat
```

These APIs can still be misused, especially around null termination and size calculations.

Associated weakness:

```text id="2fbf33"
CWE-120
```

---

## Shell execution — High

```text id="krw81z"
system
popen
```

Risk:

Untrusted input may become shell syntax.

Recommended direction:

Use exec-style APIs with explicit argument arrays when shell interpretation is not required.

Associated weakness:

```text id="98c60e"
CWE-78
```

---

## Temporary-file APIs — Medium

```text id="lahtk5"
mktemp
tmpnam
tempnam
```

Risk:

Predictable or unsafe temporary-file naming.

Recommended direction:

```text id="f1l577"
mkstemp
```

or another race-resistant temporary-file mechanism.

Associated weakness:

```text id="92jbui"
CWE-377
```

---

## Weak random-number APIs — Medium

```text id="lh21ow"
rand
random
srand
```

These are not appropriate for cryptographic secrets.

Recommended alternatives include:

```text id="i7y3hw"
getrandom()
/dev/urandom
cryptographically secure library RNGs
```

Associated weakness:

```text id="95j7cs"
CWE-338
```

---

## Weak hash APIs — High

RuntimeXRay currently recognizes families beginning with:

```text id="ep7n7i"
MD5_
SHA1_
```

Associated weakness:

```text id="qxb9rp"
CWE-327
```

---

## Weak encryption APIs — High

Current families include:

```text id="868j20"
DES_
RC4...
```

Associated weakness:

```text id="fybk9l"
CWE-327
```

---

## Deprecated TLS APIs — High

Current examples include:

```text id="oz8bxp"
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

```text id="raumpn"
CWE-326
```

---

## Memory operations — Low

Current examples:

```text id="gi5mvw"
memcpy
memmove
memset
```

These functions are not inherently vulnerabilities.

RuntimeXRay flags them at Low severity because unsafe size calculations may make them security relevant.

Associated weakness:

```text id="ssxljx"
CWE-805
```

---

## Stack allocation — Medium

```text id="k01hsq"
alloca
```

Risk:

Unbounded or attacker-controlled stack allocation may exhaust stack space.

Associated weakness:

```text id="ke8me0"
CWE-770
```

---

## Command-line parsing — Info

```text id="mne5q5"
getopt
getopt_long
```

These APIs are not dangerous by themselves.

They are included as informational review signals around input handling.

Associated weakness category:

```text id="7nn8yr"
CWE-20
```

---

## Numeric conversion — Low

```text id="ewjwb4"
atoi
atol
atoll
```

These APIs provide weak error reporting.

Recommended direction:

```text id="zll1ci"
strtol
strtoul
```

with explicit validation.

Associated weakness:

```text id="iozp9e"
CWE-190
```

---

## Tokenization — Low

```text id="rjy01n"
strtok
```

`strtok` modifies input and uses shared state.

Recommended direction:

```text id="o1g5mv"
strtok_r
```

or safer parser abstractions.

Associated weakness:

```text id="54tp8z"
CWE-366
```

---

## Legacy hostname-resolution APIs — Medium

Current examples:

```text id="gsa6ra"
gethostbyname
gethostbyaddr
```

Recommended replacements:

```text id="wd86x0"
getaddrinfo
getnameinfo
```

Associated weakness:

```text id="1jix9x"
CWE-362
```

---

## Legacy address formatting — Low

```text id="u60a14"
inet_ntoa
```

The function uses shared static storage.

Recommended replacement:

```text id="zgvuz4"
inet_ntop
```

Associated weakness:

```text id="w3pkgy"
CWE-362
```

---

# Source of truth

The current API classification is implemented in:

```text id="h6i6n2"
src/dangerous_api_rule.cpp
```

This file, not this document, is the authoritative implementation if the two ever diverge.

---

# Sensitive filesystem access

The current rule is:

```text id="jj8cdt"
SensitiveFileAccessRule
```

with rule ID:

```text id="28te9q"
builtin.sensitive_file_access
```

and semantic kind:

```text id="o0q71r"
sensitive_resource_access
```

The rule examines supported:

```text id="lmo1bu"
open
openat
```

events with resolved paths.

---

# Current path classification

## Critical

Current path patterns include:

```text id="42hgtj"
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

```text id="z73rda"
secret
token
password
credential
api_key
```

---

## Medium

```text id="523fla"
/etc/passwd
/etc/group
```

---

## Low

```text id="2670x6"
/etc/hosts
/etc/resolv.conf
```

---

## Info

```text id="pwbcgo"
/etc/hostname
/etc/machine-id
```

---

# Access outcomes

RuntimeXRay distinguishes the syscall result.

A successful open produces:

```text id="6rbhzx"
Sensitive file opened
```

with:

```text id="1pkisy"
outcome = opened
errno   = 0
```

---

## Permission denied

For errors such as:

```text id="nvjen0"
EACCES
EPERM
```

the Finding becomes:

```text id="yxbvv9"
Sensitive file access denied
```

---

## Missing file

For:

```text id="xlq4o2"
ENOENT
```

RuntimeXRay reports:

```text id="sn06si"
Sensitive file access attempted
```

with failed outcome.

---

## Other failures

Other unsuccessful opens produce:

```text id="kltkb4"
Sensitive file access failed
```

---

# Important interpretation

A failed access attempt is still observable security evidence.

For example:

```text id="lxnmaz"
open("/etc/shadow") → -EACCES
```

does not mean the file was read.

But it does prove that the process attempted the operation.

---

# Network-service detection

The current rule is:

```text id="x6fg68"
NetworkRule
```

with rule ID:

```text id="nxgbzk"
builtin.network
```

and Finding kind:

```text id="xyfny2"
suspicious_network_connection
```

---

# Current detection model

The rule currently examines:

```text id="lxckvo"
connect
```

events with resolved endpoints.

It flags selected security-sensitive service ports.

Current ports are:

```text id="xx3z2a"
22    SSH
3389  RDP
445   SMB
1433  Microsoft SQL Server
3306  MySQL
```

Current severity:

```text id="j99ch9"
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

```text id="w16aev"
SensitiveDataPresenceRule
```

with rule ID:

```text id="b4ffom"
builtin.sensitive_data_presence
```

and kind:

```text id="f5raam"
sensitive_data_presence
```

---

# How sensitive values are represented

Secret extraction produces `Data` observations containing:

```text id="426zdl"
data_type
source
secret_type
fingerprint
size
address, where relevant
```

A `SensitiveDataPresenceRule` Finding is created when a `Data` observation has both:

```text id="l43b1f"
secret_type
fingerprint
```

---

# Current severity

Sensitive-data presence is currently:

```text id="cuwmgy"
High
```

---

# Finding attributes

Typical attributes include:

```text id="cb218g"
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

```text id="1ir6h1"
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

```text id="t4utog"
password=value
api_key:value
token="value"
```

The extracted value must currently have a minimum length of six characters.

The extractor bounds normal value extraction to 128 characters.

---

# Private-key detection

RuntimeXRay currently recognizes PEM-style markers including:

```text id="csoqox"
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

```text id="yz217y"
memory
cmdline
environment
supported syscall buffers
```

The exact `data_type` records where the evidence was observed.

---

# Sensitive-data flow

The current composite rule is:

```text id="sux3sm"
SensitiveDataFlowRule
```

with rule ID:

```text id="m6ht4q"
builtin.sensitive_data_flow
```

and kind:

```text id="r5aw0n"
sensitive_data_flow
```

Current severity:

```text id="g0wqjn"
High
```

---

# Supported correlation

The current rule looks for:

```text id="8p6wek"
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

```bash id="70kxif"
runtimexray trace --scan-memory /path/to/application
```

---

# Finding output

A correlated Finding has title:

```text id="gu5c0l"
Sensitive object observed from file to socket
```

and attributes such as:

```text id="35ys5g"
fingerprint
secret_type
source_file
socket_destination
confidence
read_syscall
send_syscall
```

Current confidence string:

```text id="dvrjj0"
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

```text id="1v8yxn"
SensitiveValueCrossProcessPipeChainRule
```

with rule ID:

```text id="vb20ab"
builtin.sensitive_value_cross_process_pipe_chain
```

and kind:

```text id="2erntj"
sensitive_value_cross_process_pipe_chain
```

Current severity:

```text id="cxevc4"
High
```

---

# Purpose

This rule detects the same sensitive value across two or more explicit cross-process pipe DataFlow boundaries.

Example:

```text id="mj2w4w"
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

```text id="p1amsh"
process_instance_id
exec_generation
```

---

# Minimum chain

A Finding requires at least:

```text id="zpmuw0"
2 cross-process pipe boundaries
```

A single process-to-process pipe transfer remains graph evidence but does not produce this higher-level chain Finding.

---

# Finding evidence

The chain Finding records:

```text id="zl8kwb"
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

```text id="e5n60k"
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

```text id="qr49u0"
explicit-pipe-dataflow-chain
```

---

# Supporting findings

Matching `sensitive_data_presence` Findings may be referenced through:

```text id="v8kb3m"
supporting_finding_ids
```

but only when they:

- use the same fingerprint;
- belong to a session participating in the actual chain.

A disconnected observation of the same value is not attached merely because its fingerprint matches.

---

# Memory analysis

The standalone command is:

```bash id="c1ghdc"
runtimexray mem <pid>
```

Current sources include:

```text id="coh465"
/proc/<pid>/cmdline
/proc/<pid>/environ
readable memory mappings
```

---

# Limit page scanning

Use:

```bash id="ikwd8b"
runtimexray mem --max-pages 500 <pid>
```

Current default:

```text id="9h3juc"
1000 pages
```

---

# Skip normal memory pages

Use:

```bash id="ds0w5y"
runtimexray mem --max-pages 0 <pid>
```

This still examines:

```text id="ed5bfe"
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

```text id="t1v1y0"
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

```bash id="hlix2u"
runtimexray mem --show-secrets <pid>
```

or:

```bash id="8gwnt5"
runtimexray trace --show-secrets /path/to/application
```

This mode should be reserved for local debugging.

Do not use it in normal CI.

---

# Output and logging

RuntimeXRay separates three concepts:

```text id="o796yl"
Findings
Runtime logs
Detailed syscall diagnostics
```

---

## Human-readable report

Default:

```text id="ch9cf7"
stdout
```

or:

```bash id="jlpg0o"
--report report.txt
```

---

## JSON

Use:

```bash id="56lhni"
--json report.json
```

Both text and JSON can be generated in one execution.

---

## Logs

Runtime logs go to stderr by default.

Use:

```bash id="bih35l"
--log-level debug
```

for detailed diagnostics.

Write logs separately with:

```bash id="txs3b3"
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

```text id="k0rfdw"
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

```text id="ya2lku"
PIE: Disabled
```

Means:

> The ELF hardening property was observed as disabled.

Does not mean:

> The binary is exploitable.

---

## Dangerous API

```text id="n6iyab"
Dangerous API: system
```

Means:

> The binary imports the `system` API.

Does not mean:

> Command injection occurred.

---

## Sensitive file

```text id="t3w8xi"
Sensitive file access denied
```

Means:

> The process attempted to access a classified path and the kernel denied it.

Does not mean:

> Sensitive file content was read.

---

## Network

```text id="w5uwbh"
Suspicious network connection
```

Means:

> A connection attempt targeted one of the currently classified sensitive service ports.

Does not mean:

> The destination was malicious.

---

## Sensitive-data presence

```text id="s9vx0j"
Sensitive data observed
```

Means:

> RuntimeXRay observed a value matching its current sensitive-data criteria.

Does not mean:

> An attacker obtained it.

---

## Sensitive-data flow

```text id="dqkxov"
Sensitive object observed from file to socket
```

Means:

> The same exact sensitive value was observed in the currently supported file-input, independent-memory, and socket-output evidence points.

Does not mean:

> Malicious exfiltration was proven.

---

## Pipe chain

```text id="ufdgrq"
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

```text id="aow5uw"
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