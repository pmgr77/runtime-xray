# RuntimeXRay Governance

RuntimeXRay is currently maintained under a **single-maintainer model**.

The maintainer has final responsibility for:

- project direction;
- architecture;
- security boundaries;
- roadmap priorities;
- contribution acceptance;
- releases;
- repository administration.

This model is intended to keep technical direction clear while the project is still young and its core architecture is evolving rapidly.

---

# Project principles

Technical and project decisions should support RuntimeXRay's core direction:

> **Evidence-backed security conclusions over unsupported assumptions.**

Important project values include:

- correctness;
- evidence traceability;
- clear architectural boundaries;
- deterministic behavior;
- security and privacy by default;
- explicit limitations;
- meaningful customer/security value;
- reproducible testing;
- openness to technical disagreement.

---

# Decision making

The maintainer makes final project decisions.

Contributors are encouraged to challenge designs and propose alternatives when they can provide:

- technical reasoning;
- evidence;
- benchmarks;
- tests;
- simpler designs;
- stronger security guarantees;
- better failure-mode analysis.

Disagreement itself is not a problem.

Important technical decisions should be based on engineering arguments rather than authority alone.

---

# Architecture decisions

Changes that significantly affect project architecture should explain:

1. what problem is being solved;
2. what evidence or capability is missing today;
3. why the proposed layer is the correct place for the change;
4. which alternatives were considered;
5. what new failure modes are introduced;
6. how the behavior will be tested.

RuntimeXRay currently separates:

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

Changes should preserve those responsibilities unless there is a strong reason to change the architecture itself.

---

# Security decisions

Security-related changes should follow a conservative rule:

> A Finding should make the strongest claim supported by the available evidence — and no stronger.

For example:

```text
Observed:
same sensitive value crossed two explicit pipe DataFlow boundaries
```

does not automatically justify:

```text
Claim:
credential exfiltration occurred
```

New correlation features should include negative tests that demonstrate what evidence is **not** sufficient.

---

# Roadmap priorities

The maintainer determines roadmap priority.

In general, RuntimeXRay should prefer work that creates stronger user-visible security value.

Examples of high-value work:

- stronger evidence correlation;
- better process/resource lineage;
- new supported sources and sinks;
- fewer false correlations;
- architecture parity;
- reproducible real-world demonstrations;
- release-to-release behavioral comparison;
- useful CI/security-policy integration.

Purely cosmetic work normally has lower priority unless it improves correctness, security, usability, or maintainability.

---

# Contributions

Contributions are welcome from:

- security researchers;
- C++ developers;
- Linux systems engineers;
- eBPF developers;
- reverse engineers;
- testers;
- documentation contributors;
- users with reproducible security use cases.

See:

[CONTRIBUTING.md](CONTRIBUTING.md)

for contribution requirements.

---

# Pull requests

Pull requests are reviewed based on:

- correctness;
- architectural fit;
- test coverage;
- evidence quality;
- security impact;
- cross-architecture implications;
- maintainability;
- documentation;
- compatibility with project direction.

A technically valid pull request is not automatically guaranteed to be merged.

The maintainer may reject or postpone a contribution when it:

- conflicts with project scope;
- creates disproportionate maintenance cost;
- introduces unsupported security claims;
- duplicates planned architecture poorly;
- lacks sufficient tests;
- introduces excessive complexity for limited value.

The reason should be explained where practical.

---

# Evidence-driven feature proposals

Feature requests are especially useful when they begin with a security question.

For example:

```text
Can RuntimeXRay determine whether the same sensitive
value crossed a Unix domain socket between processes?
```

A strong proposal identifies:

```text
security question
        ↓
required evidence
        ↓
supported relationship
        ↓
possible Finding
```

This is preferred over feature proposals based only on adding another technology or API.

---

# Backward compatibility

RuntimeXRay is still under active development.

Breaking changes may occur while core architecture and public interfaces mature.

However, changes to externally consumed behavior should be deliberate.

Particular care should be taken with:

- JSON schema;
- Finding semantics;
- rule IDs;
- Finding kinds;
- CLI options;
- report structure;
- plugin/extension interfaces once public.

Breaking changes should be documented clearly.

---

# Releases

The maintainer controls release timing and versioning.

A release should normally require:

- successful Release build;
- relevant CTest suites passing;
- native architecture coverage where applicable;
- eBPF runtime validation where applicable;
- documentation synchronized with behavior;
- no known release-blocking security issue;
- reviewed release notes.

A green compile alone is not sufficient evidence for runtime-backend correctness.

---

# Security vulnerability handling

Security vulnerabilities in RuntimeXRay should be reported privately.

See:

[SECURITY.md](SECURITY.md)

Security reports should not be debated in public issues before coordinated disclosure when doing so would unnecessarily expose users.

---

# Contributor License Agreement

The project may require contributors to sign a Contributor License Agreement before significant contributions are merged.

The intended CLA workflow uses:

[cla-assistant.io](https://cla-assistant.io)

When CLA automation is enabled for a pull request, follow the instructions provided by the CLA bot.

The purpose of the CLA is to preserve the project's ability to distribute, maintain, and license contributed code, including potential future commercial use.

---

# Ownership and licensing

Contributions accepted into RuntimeXRay are distributed under the project's repository license unless explicitly documented otherwise.

The current project license is:

```text
Apache License 2.0
```

See:

[LICENSE](LICENSE)

for the authoritative license text.

---

# Community behavior

Participants are expected to communicate professionally and constructively.

Technical disagreement is welcome.

Personal attacks, harassment, or discriminatory behavior are not.

See:

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

# Transparency

Where practical, durable project decisions should be recorded in public project artifacts such as:

- GitHub Issues;
- GitHub Discussions;
- pull requests;
- architecture documentation;
- design notes;
- roadmap updates.

Chat discussions can be useful for exploration, but important technical decisions should eventually be distilled into durable project documentation.

---

# Future governance

The current single-maintainer model is appropriate while RuntimeXRay is small.

As the project grows, governance may evolve toward:

- multiple core maintainers;
- subsystem ownership;
- documented maintainer responsibilities;
- public design discussions;
- community roadmap input;
- explicit release responsibilities.

Governance should evolve when the contributor and user community makes additional structure useful, not merely for appearance.

---

# Maintainer succession

If RuntimeXRay grows beyond a single-maintainer project, future maintainers should be selected based on sustained contribution and demonstrated judgment in areas such as:

- code quality;
- security reasoning;
- architecture;
- review quality;
- project communication;
- reliability.

Repository access should follow the principle of least privilege and increase with demonstrated responsibility.

---

# Current model

For now:

```text
Contributors
     ↓
Discussion / Pull Requests
     ↓
Maintainer review
     ↓
Final project decision
```

The maintainer retains final responsibility for the project while actively encouraging evidence-based technical discussion.