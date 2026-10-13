# Security Policy

RuntimeXRay is a security analysis tool and may process sensitive runtime information, including:

- process memory;
- file paths;
- process metadata;
- network endpoints;
- secret-like values;
- security findings;
- runtime lineage.

Security issues in RuntimeXRay itself should therefore be reported privately.

---

# Reporting a vulnerability

If you discover a security vulnerability in RuntimeXRay:

> **Do not open a public GitHub issue.**

Report it privately to:

**security@runtimexray.com**

Please use the subject:

```text
RuntimeXRay Security Report
```

---

# What should be reported privately?

Examples include:

- raw secrets exposed when redaction should have applied;
- secret values written unexpectedly to logs;
- report files created with unsafe permissions;
- privilege escalation caused by RuntimeXRay;
- unsafe handling of privileged eBPF operations;
- unsafe ptrace behavior that creates a security boundary failure;
- command injection or unsafe external-command execution;
- arbitrary file write or overwrite;
- unsafe temporary-file handling;
- memory corruption in RuntimeXRay;
- exploitable parsing bugs;
- malicious trace data causing code execution or memory corruption;
- vulnerabilities in future plugin-loading mechanisms;
- a traced target being able to escape an isolation mechanism that RuntimeXRay explicitly claims to provide.

RuntimeXRay currently does **not** provide sandbox isolation, so behavior that results only from running an untrusted target with excessive host privileges is not automatically a vulnerability in RuntimeXRay.

---

# What can be reported publicly?

Normal bugs can be reported through GitHub Issues.

Examples:

- incorrect Finding severity;
- missing Finding;
- incorrect syscall decoding;
- eBPF backend failing to start;
- unsupported kernel behavior;
- incorrect documentation;
- JSON formatting problems;
- false-positive detection;
- test failures;
- performance problems.

If you are unsure whether an issue has security impact, report it privately first.

---

# What to include

A useful security report should include as much of the following as possible:

```text
RuntimeXRay version or commit
Operating system
Kernel version
Architecture
Backend
Exact command
Security impact
Steps to reproduce
Expected behavior
Actual behavior
```

Relevant backends include:

```text
analyze
ptrace
eBPF
mem
```

For code-level vulnerabilities, include:

- affected file/function if known;
- minimal proof of concept;
- explanation of the security boundary being crossed;
- whether elevated privileges are required;
- whether a malicious analyzed target is required.

---

# Environment information

Useful commands include:

```bash
git rev-parse HEAD
```

```bash
uname -a
```

```bash
uname -m
```

For eBPF issues, kernel configuration and privilege information may also be important.

---

# Sensitive data in reports

Please do **not** send real production secrets when demonstrating a vulnerability.

Use synthetic values whenever possible.

For example:

```text
password=RXRAY_SECURITY_TEST_123
token=RXRAY_SYNTHETIC_TOKEN_456
```

Before attaching logs or JSON reports, review them for:

- credentials;
- private keys;
- tokens;
- customer data;
- internal file paths;
- internal hostnames;
- network addresses;
- proprietary binaries or source.

---

# Secret-redaction vulnerabilities

RuntimeXRay is designed to redact detected sensitive values by default.

The explicit:

```text
--show-secrets
```

option intentionally relaxes that protection.

A report generated with `--show-secrets` containing the requested raw value is therefore not by itself a vulnerability.

However, please report privately if raw secret material appears unexpectedly when `--show-secrets` was **not** enabled.

---

# Logs

Runtime logs are separate from normal Finding reports, but they may still contain operational information.

A security report involving logs should state:

```text
log level:
log destination:
--show-secrets enabled: yes/no
```

Raw secrets should not be written to normal RuntimeXRay logs.

---

# Privileged execution

Some RuntimeXRay functionality may require elevated privileges.

Examples include:

- eBPF loading;
- tracefs access;
- tracing protected processes;
- reading protected process memory.

Running RuntimeXRay as root increases the impact of vulnerabilities.

Security reports involving privileged execution should clearly identify:

```text
normal user
sudo
root
container capabilities
```

where applicable.

---

# Analyzed targets are not trusted

RuntimeXRay may analyze software that is untrusted or malformed.

Where practical, parsers and runtime collectors should therefore treat target-controlled data as untrusted input.

However:

> RuntimeXRay is not currently a sandbox.

Running an untrusted executable through:

```text
runtimexray trace
```

does not make that executable safe.

Use an appropriate VM, container, sandbox, or dedicated analysis host when analyzing hostile software.

---

# Coordinated disclosure

Please allow a reasonable period for investigation and remediation before publicly disclosing a vulnerability.

After receiving a report, the project will aim to:

1. acknowledge receipt;
2. reproduce and assess the issue;
3. determine affected versions;
4. develop and test a fix;
5. coordinate disclosure with the reporter where practical;
6. publish an advisory when appropriate.

The complexity and severity of the issue may affect the remediation timeline.

---

# Reporter credit

Security reporters will be credited in an advisory when appropriate unless they request anonymity.

Please state explicitly if you prefer:

```text
anonymous disclosure
```

or a particular name/handle for credit.

---

# Supported versions

RuntimeXRay is under active development.

Security fixes are focused on the current codebase and the most recent published release, where applicable.

Older development snapshots may not receive backported fixes.

A formal long-term support matrix does not currently exist.

---

# Dependencies

A vulnerability in a third-party dependency should be reported to the upstream project when the issue exists independently of RuntimeXRay.

Please also notify RuntimeXRay privately when:

- RuntimeXRay uses the vulnerable dependency in an exploitable way;
- a dependency update is required to protect RuntimeXRay users;
- RuntimeXRay documentation or packaging exposes users to the vulnerable configuration.

---

# Public disclosure after a fix

When appropriate, a security advisory may include:

- affected versions;
- impact;
- severity;
- remediation;
- fixed version or commit;
- reporter credit;
- relevant CVE/CWE information where applicable.

Technical details may be delayed when immediate publication would unnecessarily expose users who have not yet had time to update.

---

# Non-security contact

For normal project questions that do not involve a vulnerability:

**hello@runtimexray.com**

For security vulnerabilities:

**security@runtimexray.com**

---

# Core principle

RuntimeXRay asks users to trust it with highly sensitive runtime evidence.

The project should therefore treat vulnerabilities affecting:

```text
secret confidentiality
report integrity
privilege boundaries
target-controlled input
```

as security-sensitive by default.