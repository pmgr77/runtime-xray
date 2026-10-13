# Contributing to RuntimeXRay

Thank you for your interest in contributing to RuntimeXRay.

RuntimeXRay is an evidence-driven security analysis project for compiled Linux applications.

The project values:

- correctness;
- evidence traceability;
- deterministic behavior;
- clear security boundaries;
- architecture-aware testing;
- explicit limitations;
- minimal unsupported claims.

---

# Contributor License Agreement (CLA)

Before significant contributions can be accepted, contributors may be required to sign the project's Contributor License Agreement.

The project currently uses:

[cla-assistant.io](https://cla-assistant.io)

When CLA automation is enabled for a pull request, follow the bot instructions provided there.

---

# How to contribute

1. Fork the repository.
2. Create a feature branch.

Example:

```bash
git checkout -b my-feature
```

3. Make your changes.
4. Add or update tests where behavior changes.
5. Build RuntimeXRay in Release mode.
6. Run the relevant CTest suite.
7. Run `git diff --check`.
8. Commit with a clear, descriptive message.
9. Push your branch to your fork.
10. Open a pull request against `main`.

---

# Development principles

RuntimeXRay separates:

```text
Collection
    ↓
LineageGraph
    ↓
Detection
    ↓
Findings
    ↓
Narrative
    ↓
Reporting
```

Contributions should preserve these boundaries.

---

## Collection records facts

Collectors should record what RuntimeXRay observed.

Examples:

```text
syscall
file path
socket endpoint
process relationship
memory observation
static ELF property
```

Collectors should not silently make high-level security conclusions.

---

## Detection derives conclusions

Security conclusions belong in `IDetectionRule` implementations.

Examples:

```text
binary_hardening
sensitive_resource_access
sensitive_data_presence
sensitive_data_flow
```

Detection rules should consume existing graph evidence rather than collect unrelated new evidence themselves.

---

## Reporting does not perform detection

Reporters should serialize existing Findings and evidence.

Do not add security logic only inside text or JSON rendering.

---

# Evidence-first rule

A RuntimeXRay Finding should make the strongest claim supported by the evidence — and no stronger.

For example:

Good:

```text
The same exact sensitive value was observed
in a file read, process memory, and socket-bound output.
```

Too strong without additional proof:

```text
The application exfiltrated a credential.
```

Likewise:

Good:

```text
Process attempted to connect to port 22.
```

Too strong:

```text
Process contacted a malicious SSH server.
```

---

# Code style

- Use C++17.
- Follow the formatting and style already used by surrounding code.
- Keep functions focused.
- Prefer explicit ownership and RAII.
- Avoid hidden global mutable state.
- Use descriptive names.
- Keep architecture-specific logic below semantic layers where possible.
- Write comments that explain reasoning, invariants, and non-obvious behavior rather than restating the code.
- Keep public behavior documented when it changes.

The repository currently does not define a project-wide `.clang-format` configuration.

Do not reformat unrelated code as part of a focused change.

---

# Security-sensitive code

RuntimeXRay handles potentially sensitive runtime data.

Never commit:

- real passwords;
- private keys;
- API tokens;
- customer data;
- production credentials;
- internal infrastructure secrets.

Use clearly synthetic test values.

Examples:

```text
password=RXRAY_TEST_SECRET_123
token=RXRAY_SYNTHETIC_TOKEN_456
```

---

# Secret handling

Sensitive values are redacted by default.

New code should preserve that behavior.

Prefer working with:

```text
fingerprint
secret_type
location
size
address
```

instead of raw secret text whenever possible.

Do not log raw secret values.

Avoid code such as:

```cpp
Logger::log(
    LogLevel::Debug,
    "Secret: " + raw_secret);
```

Debug logs can end up in CI artifacts, support bundles, terminals, or public bug reports.

---

# `--show-secrets`

`--show-secrets` exists only for explicit local debugging.

Do not enable it in normal CI.

Tests should use synthetic secrets even when raw output is intentionally tested.

---

# Building

RuntimeXRay uses CMake.

---

## Basic build without eBPF

```bash
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_EBPF_BACKEND=OFF

cmake --build build -j"$(nproc)"
```

---

## Build with eBPF support

```bash
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_EBPF_BACKEND=ON

cmake --build build -j"$(nproc)"
```

The eBPF build requires additional dependencies such as:

```text
clang
libbpf-dev
libelf-dev
zlib1g-dev
xxd
```

---

# Running tests

Run tests from the build directory through CTest.

Example:

```bash
ctest \
  --test-dir build \
  --output-on-failure
```

For the normal core suite:

```bash
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_EBPF_BACKEND=ON \
  -DSKIP_EBPF_TESTS=ON

cmake --build build -j"$(nproc)"

ctest \
  --test-dir build \
  --output-on-failure
```

The current core suite contains 56 tests when ptrace tests are enabled and eBPF runtime tests are excluded.

---

# Architecture-specific tests

RuntimeXRay supports:

```text
x86_64
ARM64
```

Low-level tracing code should be tested on the relevant native architecture.

Do not assume that passing x86_64 tests proves ARM64 behavior.

GitHub Actions currently runs native core tests on both architectures.

---

# ptrace changes

Changes to ptrace behavior should consider:

- x86_64 register decoding;
- ARM64 register decoding;
- syscall numbering;
- fork/vfork/clone handling;
- thread lifecycle;
- exec transitions;
- process-instance identity;
- no-follow-forks behavior;
- signal handling;
- target-memory reads.

Avoid hard-coded architecture-specific syscall numbers in shared higher-level logic.

Prefer semantic syscall names where possible.

---

# eBPF changes

The dedicated eBPF runtime suite runs separately from the core suite.

Current CI executes 16 eBPF runtime/integration tests on:

```text
x86_64
ARM64
```

Skipped eBPF runtime tests are treated as CI failures.

A successful build alone is not enough for eBPF changes.

Where practical, test actual runtime behavior.

---

# eBPF capture limits

eBPF payload capture is intentionally bounded.

Current examples include:

```text
MAX_PATH      = 256
MAX_PAYLOAD   = 256
MAX_SOCKADDR  = 128
```

Current `writev` handling inspects only the first iovec.

Do not write detection logic that assumes complete arbitrary-buffer capture.

---

# Adding a new detection rule

The current extension interface is:

```text
IDetectionRule
```

Rules are registered through:

```text
DetectionRuleRegistry
```

See:

[docs/extending_detectors.md](docs/extending_detectors.md)

---

# Primary vs Composite rules

Use a Primary rule when the conclusion can be derived directly from graph evidence.

Example:

```text
Static observation
        ↓
binary_hardening Finding
```

Use a Composite rule when the conclusion depends on already-classified Primary Findings in addition to the graph.

Example:

```text
Primary Findings
      +
LineageGraph
      ↓
Composite Finding
```

Rules in the same stage do not consume one another's output.

---

# Finding requirements

A rule should populate appropriate structured fields such as:

```text
kind
severity
title
summary
attributes
evidence_observation_seqs
evidence_edges
supporting_finding_ids
cwe_ids
```

Do not assign:

```text
finding_id
```

inside a rule.

`DetectionEngine` assigns Finding IDs.

---

# Evidence references

Use:

```text
Observation::seq
```

for public Finding evidence references.

Do not expose graph vector indices as stable identifiers.

---

# DataFlow rules

Do not create a DataFlow conclusion merely because:

```text
fingerprint A == fingerprint B
```

Fingerprint equality proves exact value identity within the current analysis.

It does not automatically prove causality.

Stronger conclusions should use evidence such as:

- resource identity;
- process identity;
- explicit graph edges;
- compatible ordering;
- source/sink context.

---

# Testing detection rules

Every new rule should normally include:

- positive test;
- negative test;
- severity check;
- semantic `kind` check;
- relevant attribute checks;
- evidence-reference validation.

Correlation rules should also include a case where the same value appears in unrelated observations.

That case should **not** produce a flow Finding.

---

# Prefer structured validation

Weak test:

```bash
grep -q "Sensitive" output.txt
```

Better test:

```text
find exact Finding kind
        ↓
validate attributes
        ↓
resolve evidence seq
        ↓
validate referenced observation
        ↓
validate explicit edge when required
```

Human-readable output is presentation.

Structured Findings and evidence are the better contract for semantic tests.

---

# Release-mode tests

RuntimeXRay tests must remain meaningful in Release builds.

Do not rely on standard C/C++ `assert()` for test correctness because:

```text
NDEBUG
```

may disable it.

Use the project's test-check mechanism where applicable.

---

# Test fixtures

Test fixtures should:

- use synthetic data;
- avoid external network dependencies where possible;
- be deterministic;
- clean up child processes/resources;
- avoid dependence on unrelated host configuration;
- validate semantics rather than incidental output text.

---

# Documentation changes

When behavior changes, update the relevant documentation.

Important files include:

```text
README.md
ARCHITECTURE.md
THREAT_MODEL.md
ROADMAP.md
FAQ.md
docs/security_checks.md
docs/extending_detectors.md
docs/integration_examples.md
docs/use_cases.md
docs/index.html
```

Do not document planned behavior as if it were implemented.

---

# JSON compatibility

RuntimeXRay currently emits:

```text
schema_version = 2.0
```

Changes to machine-readable output should consider downstream consumers.

Avoid silently renaming or removing fields without considering schema compatibility.

---

# Before committing

At minimum:

```bash
git diff --check
```

Review:

```bash
git diff
```

If code changed, build and run relevant tests.

If documentation changed, verify:

- code blocks;
- command names;
- file paths;
- links;
- claims about current behavior.

---

# Before opening a pull request

Please verify:

- the change has a clear purpose;
- unrelated formatting changes are excluded;
- relevant tests pass;
- new behavior has tests;
- documentation is updated;
- no real secrets are included;
- logs/reports are redacted;
- architecture-specific behavior has been considered;
- `git diff --check` passes.

---

# Pull request description

A useful pull request description should explain:

1. What problem does this solve?
2. What changed?
3. Why is this approach correct?
4. What evidence or tests validate it?
5. Which architectures/backends were tested?
6. Are there known limitations?
7. Does it change JSON/reporting behavior?

For evidence-correlation features, also explain:

> What exact observations justify the new conclusion?

---

# Reporting bugs

Open a public issue for normal bugs.

Include:

- exact RuntimeXRay command;
- expected behavior;
- actual behavior;
- commit or version;
- Linux distribution;
- kernel version;
- architecture:
  - x86_64
  - ARM64
- backend:
  - ptrace
  - eBPF
  - mem
  - analyze
- whether eBPF support was built;
- relevant privilege context;
- whether the target ran in a container or VM where relevant;
- minimal reproduction if possible.

Do not include real credentials or private data.

---

# Reporting security vulnerabilities

Do **not** open a public issue for a security vulnerability in RuntimeXRay itself.

See:

[SECURITY.md](SECURITY.md)

Report privately to:

```text
security@runtimexray.com
```

---

# Contribution priorities

Contributions with especially strong value include:

- stronger evidence correlation;
- more accurate runtime resource modeling;
- process/thread lifecycle correctness;
- ARM64 parity;
- eBPF runtime reliability;
- reduced false correlation;
- additional evidence-backed detectors;
- better structured reporting;
- real-world reproducible security scenarios;
- deterministic tests;
- documentation that accurately reflects implementation.

---

# Core principle

A useful RuntimeXRay contribution should help answer a security question with stronger evidence than the project could provide before.

When choosing between:

```text
more warnings
```

and:

```text
better-supported conclusions
```

prefer the second.