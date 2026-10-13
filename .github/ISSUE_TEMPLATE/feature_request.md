---
name: Feature request
about: Propose a new RuntimeXRay capability or evidence-driven security use case
title: ''
labels: enhancement
assignees: ''
---

## Problem / security question

What problem are you trying to solve?

Prefer describing the security question before describing an implementation.

Good example:

```text
Can RuntimeXRay determine whether the same sensitive value
crossed a Unix domain socket between two processes?
```

Less useful example:

```text
Add Unix sockets.
```

---

## Why does this matter?

Describe the practical value.

Examples:

- security review;
- CI/CD gating;
- incident investigation;
- binary-only component analysis;
- secret-handling validation;
- process-isolation validation;
- runtime behavior regression;
- organization-specific policy.

If possible, describe who would use the feature and what decision it would help them make.

---

## Desired result

What should RuntimeXRay be able to conclude or report?

Example:

```text
Sensitive value observed across an explicit
cross-process Unix-domain-socket transfer.
```

If the feature should produce a Finding, describe the intended semantic result.

Possible fields:

```text
kind:
severity:
title:
important attributes:
```

Do not worry about exact naming if you are unsure.

---

## Evidence required

What evidence would be necessary to support the desired conclusion?

For example:

```text
- socket resource identity
- write/send observation
- read/recv observation
- matching sensitive-value fingerprint
- process identities
- temporal ordering
```

If you are unsure, explain what you think RuntimeXRay would need to observe.

---

## What would NOT be enough evidence?

If relevant, describe cases that should not trigger the feature.

Example:

```text
The same fingerprint appearing in two unrelated
processes should not be treated as proof of transfer.
```

Negative cases are important for avoiding false correlation.

---

## Is this collection or detection?

If you know, select one or more:

- [ ] New evidence must be collected
- [ ] Existing `LineageGraph` evidence is already sufficient
- [ ] New resource / lineage modeling is required
- [ ] New Primary detection rule
- [ ] New Composite detection rule
- [ ] Reporting / presentation only
- [ ] Policy layer
- [ ] Not sure

A useful distinction is:

```text
Need a new fact?
    → collection

Need a new conclusion from existing facts?
    → detection
```

---

## Proposed workflow

If possible, show how you imagine the feature being used.

Example:

```bash
runtimexray trace \
  --scan-memory \
  ./application
```

Expected result:

```text
Finding:
Sensitive value crossed Unix domain socket

source_process=...
destination_process=...
fingerprint=...
confidence=...
```

---

## Example scenario

Provide a small concrete scenario.

For example:

```text
Process A reads a synthetic credential from a file.

Process A sends the credential through a Unix domain socket.

Process B receives it.

RuntimeXRay should connect those observations using
the same exact fingerprint and socket resource identity.
```

Synthetic examples are preferred.

Do not include real credentials or customer data.

---

## False-positive considerations

What benign behavior could look similar?

Examples:

- identical values used independently;
- reused file descriptors;
- repeated test credentials;
- multiple concurrent transfers;
- duplicated processes;
- reconnects;
- fork/exec inheritance.

If the proposed feature could easily over-correlate events, describe that risk.

---

## Backend considerations

Which evidence sources should support the feature?

- [ ] Static analysis
- [ ] ptrace
- [ ] eBPF
- [ ] Memory scanner
- [ ] Multiple backends
- [ ] Not sure

If the feature should work differently on ptrace and eBPF, explain why.

---

## Architecture considerations

Which RuntimeXRay layer do you expect this to affect?

- [ ] Collection
- [ ] `LineageGraph`
- [ ] Process/thread modeling
- [ ] Resource modeling
- [ ] Detection rules
- [ ] Narrative generation
- [ ] Reporting / JSON
- [ ] CI / integration
- [ ] Not sure

---

## Platform / architecture

Should this feature work on:

- [ ] x86_64
- [ ] ARM64
- [ ] Both
- [ ] Architecture-independent
- [ ] Other

If architecture-specific behavior is expected, describe it.

---

## Security and privacy impact

Could this feature collect or expose:

- [ ] Raw secrets
- [ ] Memory contents
- [ ] File paths
- [ ] Network destinations
- [ ] Process metadata
- [ ] Customer-specific data
- [ ] None of the above
- [ ] Not sure

Describe how sensitive data should remain protected or redacted.

RuntimeXRay should preserve redaction by default.

---

## Performance impact

Could this feature require:

- additional memory scans;
- larger syscall payload capture;
- more frequent checkpoints;
- more graph edges;
- deeper correlation;
- expensive external lookups?

If known, describe the expected performance tradeoff.

---

## Alternatives considered

What other approaches could solve the same problem?

Examples:

- use existing RuntimeXRay observations externally;
- add a custom detection rule;
- use `strace`;
- use eBPF directly;
- use a debugger;
- use another security tool.

Explain why RuntimeXRay should implement this capability itself.

---

## How would we test it?

Describe at least one positive and one negative case if possible.

Example:

```text
Positive:
same sensitive value crosses the same modeled resource
between two processes
→ Finding emitted

Negative:
same sensitive value appears in two processes without
a supported resource relationship
→ no Finding
```

---

## Definition of success

How would we know the feature is valuable and complete enough?

Examples:

```text
- produces a structured Finding
- references exact observations
- works on x86_64 and ARM64
- works with ptrace and eBPF
- has deterministic positive/negative tests
- does not expose raw secrets
```

---

## Additional context

Add:

- diagrams;
- research references;
- example programs;
- competing-tool behavior;
- relevant kernel APIs;
- protocol details;
- screenshots;

if they help explain the proposal.

---

## Core RuntimeXRay principle

A feature is especially valuable when it improves the project's ability to answer:

> **What happened, and what evidence proves it?**

Prefer evidence-backed conclusions over adding more independent warnings.