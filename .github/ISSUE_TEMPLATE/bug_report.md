---
name: Bug report
about: Report a reproducible RuntimeXRay problem
title: ''
labels: bug
assignees: ''
---

## Describe the bug

Provide a clear and concise description of the problem.

Please describe what RuntimeXRay did, not only the final error message.

---

## Exact command

Paste the exact command you ran.

```bash
runtimexray ...
```

If the problem involves a traced target, include the target arguments too.

Do not include real credentials, private keys, tokens, customer data, or other sensitive values.

---

## Expected behavior

What did you expect RuntimeXRay to do?

---

## Actual behavior

What actually happened?

Include:

- error messages;
- incorrect Finding;
- missing Finding;
- crash;
- timeout;
- unexpected exit code;
- incorrect JSON;
- incorrect lineage/evidence relationship;

as applicable.

---

## Steps to reproduce

Provide the smallest reproducible sequence you can.

Example:

1. Build RuntimeXRay with ...
2. Run ...
3. Observe ...
4. Expected ...

If possible, provide a minimal synthetic target program instead of a proprietary application.

---

## RuntimeXRay version / commit

Provide one of:

```text
RuntimeXRay version:
```

or:

```text
git commit:
```

Example:

```bash
git rev-parse HEAD
```

---

## Command / analysis mode

Select the relevant mode:

- [ ] `analyze`
- [ ] `trace`
- [ ] `mem`

If `trace`:

- [ ] `ptrace`
- [ ] `eBPF`

---

## Architecture

Select the architecture where the issue occurs:

- [ ] x86_64
- [ ] ARM64
- [ ] Other

If Other:

```text
Architecture:
```

Useful command:

```bash
uname -m
```

---

## Operating system

Example:

```text
Ubuntu 24.04
```

Useful command:

```bash
cat /etc/os-release
```

Please include the distribution and version.

---

## Kernel

Provide:

```bash
uname -a
```

or at minimum:

```bash
uname -r
```

Kernel version is especially important for:

- eBPF;
- ptrace;
- `/proc` behavior;
- process-memory access;
- containerized environments.

---

## Build configuration

How was RuntimeXRay built?

Example:

```bash
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_EBPF_BACKEND=ON
```

Please mention any non-default CMake options.

If eBPF is involved, confirm whether RuntimeXRay was built with:

```text
BUILD_EBPF_BACKEND=ON
```

---

## Privileges

How was RuntimeXRay executed?

- [ ] Normal user
- [ ] `sudo`
- [ ] root shell
- [ ] Container with additional capabilities
- [ ] Other

If relevant, include Linux capabilities or container flags.

Do not include unrelated privileged configuration.

---

## Container / VM

Was RuntimeXRay running inside:

- [ ] Bare metal
- [ ] Virtual machine
- [ ] Docker
- [ ] Podman
- [ ] Other container
- [ ] Other virtualization environment

If containerized, include relevant security/capability options.

For example:

```text
--cap-add=SYS_PTRACE
```

or other options required to reproduce the issue.

---

## ptrace-specific information

If this is a ptrace problem, include where relevant:

- whether fork following was enabled;
- whether threads were involved;
- whether exec occurred;
- whether the issue reproduces with `--no-follow-forks`;
- whether the target uses anti-debugging behavior.

Useful system setting:

```bash
cat /proc/sys/kernel/yama/ptrace_scope
```

---

## eBPF-specific information

If this is an eBPF problem, include:

- whether RuntimeXRay successfully built the eBPF backend;
- whether tracefs is mounted;
- whether the process was run with sufficient privileges;
- whether the problem reproduces on another kernel.

Useful commands:

```bash
mount | grep tracefs
```

```bash
ls -ld /sys/kernel/tracing
```

If available:

```bash
bpftool feature
```

Do not paste extremely large output unless it is directly relevant.

---

## Memory-scan-specific information

If this is a `mem` or `--scan-memory` problem, include:

- target PID;
- whether the target is your own process;
- `ptrace_scope`;
- `--max-pages` value;
- whether the failure affects:
  - cmdline;
  - environment;
  - mapped memory;
  - all of them.

Do not paste real secret values.

Use synthetic values for reproductions.

---

## Logs

If possible, reproduce with:

```bash
--log-level debug
```

and attach the relevant portion.

For example:

```bash
runtimexray trace \
  --log-level debug \
  --log-file runtimexray-debug.log \
  ...
```

Review logs before attaching them.

RuntimeXRay redacts detected secrets by default, but logs and reports may still contain:

- file paths;
- process names;
- network endpoints;
- environment-specific information.

---

## JSON report

If the problem involves:

- Findings;
- lineage;
- evidence references;
- JSON schema;
- automation;

please attach the smallest relevant JSON report.

Prefer:

```bash
--json report.json
```

Do not manually rewrite the JSON unless necessary.

If you must redact environmental information, clearly mark what was changed.

---

## Finding details

For an incorrect or missing Finding, include where possible:

```text
rule_id:
kind:
severity:
title:
```

If evidence is wrong, include the relevant:

```text
evidence_observation_seqs
evidence_edges
supporting_finding_ids
```

and the referenced lineage observations.

---

## Reproducibility

How often does the issue occur?

- [ ] Every time
- [ ] Frequently
- [ ] Intermittently
- [ ] Only once

If timing or concurrency affects the issue, describe that here.

---

## Regression

Did this work in an earlier RuntimeXRay version or commit?

- [ ] Yes
- [ ] No
- [ ] Unknown

If Yes, provide the last known working version or commit.

---

## Additional context

Add anything else that may help reproduce or understand the issue.

Examples:

- unusual kernel configuration;
- very short-lived target;
- multi-process pipeline;
- large number of threads;
- namespace use;
- security modules;
- unusual filesystem;
- custom libc;
- static binary.

---

## Security-sensitive bugs

If the issue is a vulnerability in RuntimeXRay itself, do **not** open a public issue.

See:

[SECURITY.md](../../SECURITY.md)

Report it privately to:

```text
security@runtimexray.com
```