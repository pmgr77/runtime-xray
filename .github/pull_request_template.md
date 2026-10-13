## Summary

Describe what this pull request changes and why.

Keep the explanation focused on the actual behavior or architecture being changed.

If this fixes an issue:

```text
Fixes #
```

---

## Type of change

Select all that apply:

- [ ] Bug fix
- [ ] New feature
- [ ] Detection-rule change
- [ ] Runtime tracing change
- [ ] eBPF change
- [ ] ptrace change
- [ ] Memory-scanning change
- [ ] Reporting / JSON change
- [ ] Test / CI change
- [ ] Documentation update
- [ ] Breaking change

---

## Why is this change needed?

What problem does this solve?

If this introduces a new security conclusion or correlation, describe the exact question it answers.

Example:

```text
Question:
Did the same sensitive value cross two explicit
cross-process pipe boundaries?
```

---

## Evidence model

If this pull request adds or changes detection behavior, describe the evidence that supports the Finding.

For example:

```text
Required observations:
- write to pipe resource X
- matching fingerprint
- read from pipe resource X
- distinct process instances

Required relationship:
- explicit DataFlow edge
```

If this section is not relevant, write:

```text
N/A
```

---

## Security claim

If this change introduces or strengthens a Finding, write the exact claim the Finding makes.

Example:

```text
The same exact sensitive value was observed across
two explicit cross-process pipe DataFlow boundaries.
```

Also state what the Finding does **not** prove where relevant.

Example:

```text
This does not prove malicious intent or exfiltration.
```

---

## Architecture impact

Which layer changed?

- [ ] Collection
- [ ] `LineageGraph`
- [ ] Resource/process lineage
- [ ] Detection rule
- [ ] Detection engine / registry
- [ ] Finding model
- [ ] Narrative generation
- [ ] Reporting
- [ ] CLI
- [ ] Build system
- [ ] CI only
- [ ] Documentation only

Describe any important architectural impact:

```text

```

---

## Backends affected

- [ ] None
- [ ] ptrace
- [ ] eBPF
- [ ] Both ptrace and eBPF
- [ ] Memory scanner
- [ ] Static analyzer

If only one runtime backend changed, explain why the other backend is unaffected.

---

## Architectures tested

Select what was actually tested:

- [ ] x86_64
- [ ] ARM64
- [ ] Not architecture-specific
- [ ] Not tested locally

Do not mark an architecture merely because the code compiles for it.

---

## Tests

Describe the tests that validate this change.

Include:

- positive cases;
- negative cases;
- regression cases;
- evidence validation;

where relevant.

Example:

```text
Positive:
same fingerprint crosses two explicit pipe DataFlow edges
→ Finding emitted

Negative:
same fingerprint appears in several processes without
DataFlow edges
→ no chain Finding
```

---

## Commands used

Paste the relevant build/test commands.

Example:

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

For focused tests, include the exact `ctest -R ...` command.

---

## eBPF validation

Complete this section if the eBPF backend changed.

- [ ] eBPF backend compiled successfully
- [ ] eBPF runtime tests actually executed
- [ ] No relevant eBPF tests were skipped
- [ ] Tested on x86_64
- [ ] Tested on ARM64

If not applicable:

```text
N/A
```

---

## ptrace validation

Complete this section if ptrace behavior changed.

Consider:

- [ ] fork
- [ ] vfork
- [ ] clone
- [ ] threads
- [ ] exec
- [ ] `--no-follow-forks`
- [ ] target-memory reads
- [ ] x86_64
- [ ] ARM64

If not applicable:

```text
N/A
```

---

## JSON / reporting compatibility

Does this change JSON output?

- [ ] No
- [ ] Adds fields only
- [ ] Changes existing field semantics
- [ ] Removes or renames fields
- [ ] Changes `schema_version`

If JSON behavior changes, describe the compatibility impact.

Current schema:

```text
2.0
```

---

## Secret-handling review

If this change touches runtime data, memory, payloads, reports, or logs:

- [ ] Raw secrets remain redacted by default
- [ ] No raw secrets are written to logs
- [ ] Tests use synthetic secret values
- [ ] `--show-secrets` behavior remains explicit
- [ ] New report fields were reviewed for sensitive data

If not applicable:

```text
N/A
```

---

## Documentation

Select all updated files that apply:

- [ ] `README.md`
- [ ] `ARCHITECTURE.md`
- [ ] `THREAT_MODEL.md`
- [ ] `ROADMAP.md`
- [ ] `FAQ.md`
- [ ] `docs/security_checks.md`
- [ ] `docs/extending_detectors.md`
- [ ] `docs/integration_examples.md`
- [ ] `docs/use_cases.md`
- [ ] `docs/index.html`
- [ ] No documentation change required

If documentation was not changed for a behavior change, explain why.

---

## Final checklist

- [ ] I reviewed my own diff
- [ ] `git diff --check` passes
- [ ] Release build succeeds
- [ ] Relevant existing tests pass
- [ ] New behavior has focused tests where applicable
- [ ] Negative tests prevent unsupported correlation where applicable
- [ ] Findings reference valid observation sequence IDs
- [ ] `evidence_edges` correspond to real graph relationships where used
- [ ] I did not introduce hard-coded architecture-specific syscall numbers into shared semantic logic
- [ ] I did not add unrelated formatting changes
- [ ] I did not commit real credentials, keys, tokens, or customer data
- [ ] Documentation does not present planned behavior as implemented
- [ ] I have signed the CLA if required

---

## Known limitations

List any known limitations introduced or left unresolved by this change.

If none:

```text
None known.
```