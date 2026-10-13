# Extending RuntimeXRay Detection Rules

RuntimeXRay uses graph-based detection rules.

The current extension point is:

```text
IDetectionRule
```

Rules inspect collected evidence in a `LineageGraph` and return structured `Finding` objects.

The current detection pipeline is:

```text
LineageGraph
     ↓
DetectionRuleRegistry
     ↓
DetectionEngine
     ↓
Primary rules
     ↓
frozen Primary Findings
     ↓
Composite rules
     ↓
Final Findings
```

Custom detection rules currently require source integration and rebuilding RuntimeXRay.

Dynamic external `.so` plugin loading is not implemented yet.

---

# 1. Core interfaces

The main types are:

```text
IDetectionRule
DetectionContext
DetectionRuleRegistry
DetectionEngine
Finding
LineageGraph
```

Relevant headers:

```text
include/idetection_rule.hpp
include/detection_context.hpp
include/detection_rule_registry.hpp
include/detection_engine.hpp
include/finding.hpp
include/lineage.hpp
```

---

# 2. IDetectionRule

A detection rule implements:

```cpp
class IDetectionRule {
public:
    virtual ~IDetectionRule() = default;

    virtual std::string id() const = 0;
    virtual std::string description() const = 0;
    virtual DetectionStage stage() const = 0;

    virtual FindingList detect(
        const DetectionContext& context) const = 0;
};
```

A rule returns complete `Finding` objects.

There is no intermediate `Analyzer` or `Evidence` API in the current architecture.

---

# 3. Detection stages

RuntimeXRay currently supports:

```cpp
enum class DetectionStage {
    Primary,
    Composite
};
```

---

## Primary rules

Primary rules derive Findings directly from the `LineageGraph`.

Conceptually:

```text
LineageGraph
     ↓
Primary rule
     ↓
Finding
```

Typical uses:

- binary hardening checks;
- imported API classification;
- sensitive-file detection;
- network detection;
- sensitive-data presence.

---

## Composite rules

Composite rules can inspect:

```text
LineageGraph
+
frozen Primary Findings
```

Conceptually:

```text
LineageGraph
      +
Primary Findings
      ↓
Composite rule
      ↓
Higher-level Finding
```

Typical uses:

- source-to-sink correlation;
- multi-process evidence chains;
- higher-level conclusions built from lower-level Findings.

---

# 4. DetectionContext

Every rule receives a read-only context:

```cpp
struct DetectionContext {
    const LineageGraph& graph;
    const FindingList& previous_stage_findings;
};
```

For Primary rules:

```text
previous_stage_findings = empty
```

For Composite rules:

```text
previous_stage_findings = completed Primary Findings
```

Rules must not mutate the graph or existing Findings.

---

# 5. Stage isolation

Rules within the same stage do not see each other's output.

For example:

```text
Primary rule A
Primary rule B
Primary rule C
```

all receive the same graph and the same empty previous-stage Finding set.

Their output is collected only after each rule finishes.

Likewise, Composite rules all receive the same frozen Primary result set.

This keeps detection semantics independent of rule execution order.

---

# 6. Rule identity

Every rule must return a stable ID from:

```cpp
id()
```

Example:

```cpp
std::string MyRule::id() const
{
    return "acme.internal_secret_file";
}
```

Rule IDs should be:

- stable;
- unique;
- machine-readable;
- namespace-like.

Recommended pattern:

```text
organization.rule_name
```

Built-in rules use:

```text
builtin.*
```

Third-party rules should not use the `builtin.` namespace.

---

# 7. Finding identity

Rules should not assign:

```text
finding_id
```

The `DetectionEngine` assigns Finding IDs after collecting rule output.

This guarantees consistent Finding identity management.

---

# 8. Finding structure

A current `Finding` contains:

```cpp
struct Finding {
    uint64_t finding_id;
    std::string rule_id;
    std::string kind;
    FindingSeverity severity;
    std::string title;
    std::string summary;

    std::vector<uint64_t>
        evidence_observation_seqs;

    std::vector<FindingEdgeEvidence>
        evidence_edges;

    std::vector<uint64_t>
        supporting_finding_ids;

    std::vector<std::string>
        cwe_ids;

    FindingAttributes attributes;
};
```

---

# 9. rule_id vs kind

These are intentionally different.

## `rule_id`

Identifies the implementation.

Example:

```text
acme.internal_secret_file
```

---

## `kind`

Identifies the semantic result.

Example:

```text
sensitive_resource_access
```

A third-party rule may intentionally produce the same semantic `kind` as a built-in rule.

This allows Composite rules to consume compatible semantic results without depending on one specific implementation.

---

# 10. Findings should reference evidence

A rule should normally populate:

```text
evidence_observation_seqs
```

with the `Observation::seq` values that directly support the conclusion.

Do not store graph vector indices as public evidence identity.

Use:

```text
Observation::seq
```

instead.

---

# 11. Evidence edges

For Findings that depend on explicit graph relationships, use:

```text
evidence_edges
```

Example:

```cpp
FindingEdgeEvidence edge;
edge.from_seq = write_obs.seq;
edge.to_seq = read_obs.seq;
edge.relation = RelationType::DataFlow;

finding.evidence_edges.push_back(edge);
```

Use this only when the relationship actually exists in the graph.

Do not invent a `DataFlow` edge merely because two observations contain the same fingerprint.

---

# 12. Supporting Findings

Composite Findings can reference lower-level Findings through:

```text
supporting_finding_ids
```

Example:

```text
Sensitive-data presence Finding
Sensitive-file Finding
        ↓
Composite Finding
```

A Composite rule should only reference Findings that actually contribute to its conclusion.

---

# 13. Attributes

Rule-specific structured facts belong in:

```text
Finding::attributes
```

Supported value types include:

```text
string
int64_t
uint64_t
double
bool
vector<string>
vector<int64_t>
vector<uint64_t>
```

Example:

```cpp
finding.attributes["path"] =
    std::string("/etc/shadow");

finding.attributes["errno"] =
    static_cast<int64_t>(13);

finding.attributes["confidence"] =
    std::string("exact-fingerprint-match");
```

Use attributes for machine-readable facts rather than hiding important information inside prose.

---

# 14. Severity

Available severities are:

```cpp
enum class FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info
};
```

Severity should describe the rule's security interpretation.

Do not inflate severity merely because an observation sounds suspicious.

---

# 15. CWE references

If the rule has justified CWE mappings, use:

```cpp
finding.cwe_ids.push_back("CWE-78");
```

Do not attach a CWE simply because the observed API or behavior is vaguely related.

A CWE association should represent a meaningful mapping.

---

# 16. Example: simple Primary rule

The following rule flags successful access to a custom sensitive path.

```cpp
#include "idetection_rule.hpp"

#include <string>
#include <utility>

namespace acme {

class InternalSecretFileRule
    : public runtimexray::IDetectionRule
{
public:
    std::string id() const override
    {
        return "acme.internal_secret_file";
    }

    std::string description() const override
    {
        return
            "Detects successful access to "
            "Acme internal secret files";
    }

    runtimexray::DetectionStage
    stage() const override
    {
        return
            runtimexray::DetectionStage::Primary;
    }

    runtimexray::FindingList detect(
        const runtimexray::DetectionContext&
            context) const override
    {
        runtimexray::FindingList findings;

        for (const auto& observation :
             context.graph.observations) {

            if (observation.type !=
                runtimexray::ObservationType::Event) {
                continue;
            }

            if (observation.syscall_name != "open" &&
                observation.syscall_name != "openat") {
                continue;
            }

            if (observation.return_value < 0) {
                continue;
            }

            if (observation.source.find(
                    "/opt/acme/secrets/")
                == std::string::npos) {
                continue;
            }

            runtimexray::Finding finding;

            finding.kind =
                "sensitive_resource_access";

            finding.severity =
                runtimexray::FindingSeverity::High;

            finding.title =
                "Acme internal secret file opened";

            finding.summary =
                "Process successfully opened an "
                "Acme internal secret path.";

            finding.attributes["path"] =
                observation.source;

            finding.attributes["outcome"] =
                std::string("opened");

            if (observation.seq != 0) {
                finding
                    .evidence_observation_seqs
                    .push_back(
                        observation.seq);
            }

            findings.push_back(
                std::move(finding));
        }

        return findings;
    }
};

} // namespace acme
```

Notice that the rule does **not** assign:

```text
rule_id
finding_id
```

The engine assigns those.

---

# 17. Registering a rule

Rules are registered through:

```text
DetectionRuleRegistry
```

Example:

```cpp
#include "detection_rule_registry.hpp"

auto& registry =
    runtimexray::DetectionRuleRegistry::instance();

registry.register_rule(
    std::make_unique<
        acme::InternalSecretFileRule>());
```

Registration transfers ownership to the registry.

---

# 18. Replacing a rule

Rule ID is the stable implementation identity.

Registering another rule with the same ID replaces the previous implementation.

Example:

```text
acme.internal_secret_file
```

If a second implementation with that ID is registered, it replaces the first.

---

# 19. Disabling a rule

Use:

```cpp
registry.disable_rule(
    "acme.internal_secret_file");
```

The rule remains registered but will not execute.

---

# 20. Re-enabling a rule

```cpp
registry.enable_rule(
    "acme.internal_secret_file");
```

---

# 21. Removing a rule

```cpp
registry.unregister_rule(
    "acme.internal_secret_file");
```

---

# 22. Listing rule IDs

```cpp
for (const auto& id :
     registry.list_rule_ids()) {

    std::cout << id << "\n";
}
```

The returned list is sorted.

---

# 23. Example: Primary sensitive-data rule

A custom rule can inspect `Data` observations directly.

Example:

```cpp
#include "idetection_rule.hpp"

class AcmeApiTokenRule
    : public runtimexray::IDetectionRule
{
public:
    std::string id() const override
    {
        return "acme.api_token";
    }

    std::string description() const override
    {
        return
            "Detects Acme API token observations";
    }

    runtimexray::DetectionStage
    stage() const override
    {
        return
            runtimexray::DetectionStage::Primary;
    }

    runtimexray::FindingList detect(
        const runtimexray::DetectionContext&
            context) const override
    {
        runtimexray::FindingList findings;

        for (const auto& observation :
             context.graph.observations) {

            if (observation.type !=
                runtimexray::ObservationType::Data) {
                continue;
            }

            if (observation.secret_type !=
                "acme_api_token") {
                continue;
            }

            if (observation.fingerprint.empty()) {
                continue;
            }

            runtimexray::Finding finding;

            finding.kind =
                "sensitive_data_presence";

            finding.severity =
                runtimexray::FindingSeverity::High;

            finding.title =
                "Acme API token observed";

            finding.summary =
                "RuntimeXRay observed an "
                "Acme API token.";

            finding.attributes["fingerprint"] =
                observation.fingerprint;

            finding.attributes["location"] =
                observation.data_type;

            if (observation.seq != 0) {
                finding
                    .evidence_observation_seqs
                    .push_back(
                        observation.seq);
            }

            findings.push_back(
                std::move(finding));
        }

        return findings;
    }
};
```

This example assumes that some collector already produced:

```text
secret_type = acme_api_token
```

Detection rules should not invent observations that were never collected.

---

# 24. Example: Composite rule

A Composite rule may consume Primary Findings.

Suppose we want to detect when two different sensitive resources were accessed during the same analysis.

This is only an example of the Composite API.

```cpp
#include "idetection_rule.hpp"

#include <set>
#include <string>

class MultipleSensitiveResourcesRule
    : public runtimexray::IDetectionRule
{
public:
    std::string id() const override
    {
        return "acme.multiple_sensitive_resources";
    }

    std::string description() const override
    {
        return
            "Detects access to multiple "
            "sensitive resources";
    }

    runtimexray::DetectionStage
    stage() const override
    {
        return
            runtimexray::DetectionStage::Composite;
    }

    runtimexray::FindingList detect(
        const runtimexray::DetectionContext&
            context) const override
    {
        std::set<std::string> paths;

        std::vector<uint64_t>
            supporting_ids;

        for (const auto& finding :
             context.previous_stage_findings) {

            if (finding.kind !=
                "sensitive_resource_access") {
                continue;
            }

            const auto it =
                finding.attributes.find("path");

            if (it ==
                finding.attributes.end()) {
                continue;
            }

            const auto* path =
                std::get_if<std::string>(
                    &it->second);

            if (!path) {
                continue;
            }

            paths.insert(*path);

            if (finding.finding_id != 0) {
                supporting_ids.push_back(
                    finding.finding_id);
            }
        }

        if (paths.size() < 2) {
            return {};
        }

        runtimexray::Finding result;

        result.kind =
            "multiple_sensitive_resources";

        result.severity =
            runtimexray::FindingSeverity::High;

        result.title =
            "Multiple sensitive resources accessed";

        result.summary =
            "The analysis contains access "
            "to multiple distinct sensitive resources.";

        result.attributes["paths"] =
            std::vector<std::string>(
                paths.begin(),
                paths.end());

        result.supporting_finding_ids =
            std::move(supporting_ids);

        return {std::move(result)};
    }
};
```

---

# 25. Composite rule caution

The previous example demonstrates API usage, not a universal security rule.

Composite rules should not combine unrelated Findings merely because they coexist.

A higher-level conclusion should have a meaningful semantic basis.

---

# 26. Prefer semantic kind over built-in rule ID

Suppose a Composite rule wants to consume sensitive-resource Findings.

Prefer:

```cpp
if (finding.kind ==
    "sensitive_resource_access")
```

over:

```cpp
if (finding.rule_id ==
    "builtin.sensitive_file_access")
```

when compatible third-party rules should participate.

Use `rule_id` only when you intentionally depend on one specific implementation.

---

# 27. Working with graph observations

The graph contains:

```cpp
context.graph.observations
```

Observation types include:

```text
Event
Data
Static
```

---

## Event

Common runtime fields include:

```text
seq
pid
tid
tgid
process_instance_id
exec_generation
program_name
syscall_name
arg0 ... arg5
return_value
fingerprint
secret_type
source
resource_id
resource_type
resource_role
```

---

## Data

Common fields include:

```text
seq
pid
tid
tgid
process_instance_id
exec_generation
data_type
fingerprint
secret_type
address
size
source
```

---

## Static

Common fields include:

```text
seq
static_field
static_value
static_category
static_description
static_recommendation
cwe_id
```

---

# 28. Process identity

Do not use raw PID alone when reasoning about process lifetime.

Prefer:

```text
process_instance_id
```

For execution-session identity use:

```text
process_instance_id
+
exec_generation
```

A process may call `exec` without receiving a new PID.

---

# 29. Resource identity

Do not assume an FD number permanently identifies one resource.

Prefer:

```text
resource_id
resource_type
resource_role
```

when the collector has modeled them.

Example:

```text
resource_id   = 7
resource_type = pipe
resource_role = write
```

---

# 30. Fingerprints

Sensitive-value fingerprints are per-run HMAC-SHA256 identifiers.

Fingerprint equality means:

> RuntimeXRay observed the same exact extracted sensitive value during this analysis.

It does not automatically mean:

> observation A caused observation B.

For stronger data-flow conclusions, combine fingerprints with:

- process identity;
- resource identity;
- explicit graph edges;
- event ordering;
- source/sink context.

---

# 31. Searching graph edges

Rules may inspect:

```cpp
context.graph.edges
```

Each edge contains:

```text
from_index
to_index
relation
time_delta
details
```

The indices are internal graph indices.

When exposing evidence in a Finding, translate them to:

```text
Observation::seq
```

---

# 32. Example: consuming a DataFlow edge

```cpp
for (const auto& edge :
     context.graph.edges) {

    if (edge.relation !=
        runtimexray::RelationType::DataFlow) {
        continue;
    }

    if (edge.from_index >=
            context.graph.observations.size() ||
        edge.to_index >=
            context.graph.observations.size()) {
        continue;
    }

    const auto& from =
        context.graph.observations[
            edge.from_index];

    const auto& to =
        context.graph.observations[
            edge.to_index];

    // Analyze the supported relationship...
}
```

Before creating Finding edge evidence:

```cpp
runtimexray::FindingEdgeEvidence
    evidence;

evidence.from_seq = from.seq;
evidence.to_seq = to.seq;
evidence.relation = edge.relation;
```

---

# 33. Do not manufacture lineage

Bad:

```text
same fingerprint
+
close timestamps
=
DataFlow
```

That is not necessarily valid.

Better:

```text
same fingerprint
+
same modeled resource
+
explicit graph DataFlow edge
=
stronger supported relationship
```

RuntimeXRay's evidence-first design depends on preserving this distinction.

---

# 34. Determinism

Detection results should be deterministic for the same graph and rule set.

Avoid:

- dependence on unordered iteration where result identity matters;
- random rule output ordering;
- hidden global mutable state;
- rule behavior that depends on registration order.

The registry sorts active rules by stable ID before execution.

---

# 35. Rule side effects

Detection rules should be read-only consumers.

Avoid:

- modifying `LineageGraph`;
- modifying previous-stage Findings;
- running external commands;
- changing global process state;
- printing directly to stdout;
- producing report files.

Rules should return Findings.

Logging should be limited to real diagnostics.

---

# 36. Reporting separation

A rule should not generate JSON manually.

A rule should not format the final text report.

The intended flow is:

```text
DetectionRule
    ↓
Finding
    ↓
NarrativeBuilder
    ↓
Reporter
```

This keeps security logic independent of output format.

---

# 37. Do not put important machine data only in prose

Bad:

```cpp
finding.summary =
    "Secret from /tmp/a was sent "
    "to 10.0.0.5:443";
```

with no attributes.

Better:

```cpp
finding.summary =
    "Sensitive value observed "
    "from file to socket.";

finding.attributes["source_file"] =
    std::string("/tmp/a");

finding.attributes["socket_destination"] =
    std::string("10.0.0.5:443");
```

Machine-readable facts belong in `attributes`.

---

# 38. Secret handling

Detection rules should normally operate on:

```text
fingerprint
secret_type
location
size
address
```

rather than raw secret values.

Raw values may exist inside internal collection context, but they should not be copied unnecessarily into Findings.

RuntimeXRay reports are redacted by default.

---

# 39. Never log raw secrets

Custom rules should never do this:

```cpp
Logger::log(
    LogLevel::Debug,
    "Secret: " + raw_secret);
```

Even debug logs can escape into:

- CI artifacts;
- terminals;
- support bundles;
- issue reports.

Use fingerprints or redacted metadata instead.

---

# 40. Choosing a semantic kind

A custom rule should choose a stable semantic `kind`.

Examples:

```text
acme_policy_violation
credential_reconnaissance
sensitive_resource_access
sensitive_data_presence
```

A `kind` should describe the result, not the implementation.

Bad:

```text
my_rule_v2
```

Better:

```text
sensitive_database_credential_access
```

---

# 41. Rule versioning

There is no separate rule-version field today.

If semantics change incompatibly, consider using a new stable rule ID.

For example:

```text
acme.foo
```

should not silently change from one unrelated security meaning to another.

---

# 42. Rule registration today

Built-in rules are currently registered in:

```text
src/register_builtin_detection_rules.cpp
```

A source-integrated rule can be added there.

Example:

```cpp
registry.register_rule(
    std::make_unique<
        acme::InternalSecretFileRule>());
```

You must also include the rule in the build configuration.

---

# 43. Dynamic loading is not implemented

RuntimeXRay does not currently support:

```text
runtimexray --load-rule myrule.so
```

or equivalent runtime `.so` loading.

Current rule extension requires:

```text
source integration
+
compile
+
link
```

Dynamic external rule loading is planned future work.

---

# 44. Rule trust model

Detection rules run inside the RuntimeXRay process.

They are not sandboxed.

A malicious or buggy rule can:

- crash RuntimeXRay;
- consume excessive memory;
- consume excessive CPU;
- leak data;
- produce incorrect Findings.

Only trusted rule implementations should be integrated.

---

# 45. Testing custom rules

Every rule should have focused tests for:

```text
positive case
negative case
edge case
evidence references
severity
kind
attributes
```

For correlation rules, also test:

```text
same values without relationship
```

to ensure the rule does not create unsupported causality.

---

# 46. Positive and negative correlation example

Suppose a rule claims:

```text
secret crossed pipe
```

A positive test should prove:

```text
write
  ↓ DataFlow
read
```

with matching evidence.

A negative test should include:

```text
secret observed in process A
secret observed in process B
```

without a pipe DataFlow edge.

The rule must not emit the flow Finding.

---

# 47. Validate Finding evidence

Tests should verify that every:

```text
evidence_observation_seqs
```

entry refers to a real graph observation.

Similarly every:

```text
evidence_edges
```

entry should correspond to an actual graph relationship when the Finding claims that relationship.

---

# 48. Avoid grep-style tests

Weak test:

```bash
grep -q "Sensitive"
```

Strong test:

```text
Find exact Finding kind
        ↓
check exact fingerprint
        ↓
resolve evidence seq
        ↓
confirm matching observation
        ↓
confirm explicit edge if required
```

RuntimeXRay's own test direction follows this evidence-aware model.

---

# 49. Primary rule design guideline

Use a Primary rule when the conclusion can be made directly from graph evidence.

Examples:

```text
static hardening observation
        ↓
binary_hardening Finding
```

or:

```text
sensitive Data observation
        ↓
sensitive_data_presence Finding
```

---

# 50. Composite rule design guideline

Use a Composite rule when the conclusion benefits from already-classified semantic results.

Example:

```text
several sensitive_resource_access Findings
        ↓
credential_reconnaissance Finding
```

Composite rules should not repeat all lower-level classification logic unless necessary.

---

# 51. Built-in rules as examples

Useful implementation references include:

```text
src/hardening_rule.cpp
src/dangerous_api_rule.cpp
src/sensitive_file_access_rule.cpp
src/network_rule.cpp
src/sensitive_data_presence_rule.cpp
src/sensitive_data_flow_rule.cpp
src/sensitive_value_cross_process_pipe_chain_rule.cpp
```

These show several rule styles:

```text
single-observation Primary rule
static classification
runtime classification
Composite value correlation
explicit edge-chain correlation
```

---

# 52. SensitiveDataFlowRule as a correlation example

`SensitiveDataFlowRule` demonstrates a conservative correlation strategy.

It requires:

- same exact fingerprint;
- same execution session;
- input from a file;
- independent memory observation;
- output to a connected socket;
- compatible event ordering.

It intentionally does not manufacture DataFlow edges where none exist.

This is a useful pattern for future correlation rules.

---

# 53. Pipe-chain rule as an explicit-edge example

`SensitiveValueCrossProcessPipeChainRule` demonstrates a stronger graph-based model.

It requires:

- explicit `DataFlow` edges;
- pipe resource identity;
- different process instances;
- exact fingerprint equality;
- temporal compatibility;
- at least two process boundaries.

The Finding stores the actual edge evidence.

This is the preferred model when explicit resource relationships are available.

---

# 54. Future extension model

The planned direction is to make rules externally loadable without abandoning the current API concepts.

A future plugin design should preserve:

```text
stable rule identity
DetectionStage
DetectionContext
Finding
evidence references
deterministic execution
trust documentation
```

The current source-integrated rule API is therefore intended to be a foundation for future dynamic loading.

---

# 55. Checklist for a new rule

Before adding a rule, ask:

1. What exact security question does the rule answer?
2. Which observations support the answer?
3. Does it need Primary or Composite stage?
4. What semantic `kind` should it produce?
5. What evidence seqs prove the conclusion?
6. Are explicit graph edges available?
7. Which attributes should be machine-readable?
8. What severity is justified?
9. Is a CWE mapping actually justified?
10. What negative case prevents over-correlation?
11. Could raw secrets leak through attributes or logs?
12. Is the result deterministic?

---

# 56. Core principle

A detection rule should make the strongest claim that the available evidence supports — and no stronger.

If the graph only proves:

```text
same sensitive value observed twice
```

do not claim:

```text
data flowed from A to B
```

unless the relationship is actually supported.

That evidence discipline is the central extension contract in RuntimeXRay.

---

*Last reviewed: 2026-10-13*