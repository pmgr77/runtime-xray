# RuntimeXRay Real-World Validation: Docker

## Status

This document records a real-world validation cycle performed against the Docker CLI and related Docker workflows during RuntimeXRay development in September–October 2026.

This was not a synthetic unit-test-only exercise.

The goals were to:

- run RuntimeXRay against a real, widely used Linux application;
- establish ground truth independently with tools such as `strace`;
- test process, file-descriptor, socket, memory, secret, fork/exec, and IPC behavior;
- identify unsupported assumptions in RuntimeXRay;
- distinguish value identity from actual data-flow causality;
- turn failures discovered in the Docker workflow into deterministic regression tests.

RuntimeXRay evolved substantially during this validation cycle.

Some historical examples below were produced before the current DetectionRule/Finding architecture and before JSON schema `2.0`.

Therefore:

> Historical field names and report layouts shown here are evidence of the validation process, not a specification of the current JSON API.

The current RuntimeXRay documentation and implementation are authoritative for current output format.

---

# Why Docker?

Docker was selected as the first substantial real-world target because a single Docker CLI operation exercises many behaviors relevant to RuntimeXRay:

- Unix-domain sockets;
- local configuration files;
- child processes;
- `fork` / `exec`;
- file-descriptor inheritance;
- pipes;
- external credential helpers;
- credentials;
- environment inheritance;
- runtime memory;
- process boundaries;
- pre-existing daemons outside the traced process tree.

This makes Docker more useful as a validation target than a small purpose-built sample.

The purpose was not to find a vulnerability in Docker.

The purpose was to ask:

> Can RuntimeXRay accurately describe security-relevant behavior in a real application without inventing relationships that the evidence does not support?

---

# Test environment

The main Docker validation environment was:

```text
OS:          Ubuntu 24.04
Environment: Oracle VM
Docker:      29.8.0
containerd:  2.3.5
runc:        1.5.1
```

The initial Docker image inventory was intentionally small.

The main workload image was:

```text
redis:7
```

The Redis CLI version observed during the test cycle was:

```text
redis-cli 7.4.11
```

A local authenticated registry was later added at:

```text
127.0.0.1:5000
```

RuntimeXRay itself executed on the host.

---

# Validation methodology

The general method used throughout the experiment was:

```text
Expected behavior
       ↓
Independent ground truth
       ↓
RuntimeXRay trace / memory scan
       ↓
Compare observations
       ↓
Investigate disagreement
       ↓
Fix RuntimeXRay if necessary
       ↓
Add deterministic regression coverage
```

`strace` was frequently used as independent syscall-level ground truth.

RuntimeXRay was intentionally not treated as its own oracle.

A finding was considered useful only if the evidence supporting it could be explained.

---

# Phase 0 — Baseline inventory

The first phase recorded the environment before testing behavior.

The inventory included:

```bash
uname -a
cat /etc/os-release
uname -m

docker --version
docker version
docker info
docker compose version

which docker
sha256sum "$(which docker)"

dockerd --version
containerd --version
runc --version

docker images
docker ps -a
docker network ls

ls -la ~/.docker
ls -la ~/.docker/config.json

docker buildx version
docker buildx ls

ls -l /var/run/docker.sock
```

RuntimeXRay state was also recorded:

```bash
git rev-parse HEAD
git log --oneline -3
git status --short
ls -l build/runtimexray
```

This phase was important because later observations depended on:

- the exact Docker version;
- the user's `HOME`;
- `DOCKER_CONFIG`;
- installed credential helpers;
- existing Docker images;
- the Docker daemon already running before RuntimeXRay starts.

---

# Phase 1 — Basic Docker CLI behavior

## 1.1 `docker version`

The first real trace was deliberately simple:

```bash
docker version
```

Ground truth was captured with:

```bash
strace -f -tt \
  -e trace=openat,connect,execve,socket \
  /usr/bin/docker version
```

RuntimeXRay then traced the same command.

The important ground-truth result was:

```text
Docker CLI
    ↓
AF_UNIX
    ↓
/var/run/docker.sock
```

There was no corresponding TCP connection for this operation.

RuntimeXRay produced no security findings for the normal workflow.

This was the desired behavior.

### What this established

It confirmed an important Docker architectural boundary:

> The Docker CLI communicates with the already-running Docker daemon through `/var/run/docker.sock`.

This became important later.

`dockerd` is not created by the Docker CLI process being traced.

Therefore:

```text
docker CLI
   │
   ├── descendants created by docker
   │       RuntimeXRay can follow
   │
   └── pre-existing dockerd
           RuntimeXRay --follow-forks does not magically begin tracing it
```

`--follow-forks` follows descendants of the traced process.

It does not mean:

> follow every process that the target communicates with.

This distinction became one of the useful lessons from the Docker test.

---

# Phase 1.2 — `docker info` and environment correctness

The next test exposed a surprisingly useful environmental issue.

Two variants were tested.

## Correct environment

RuntimeXRay was executed with:

```text
HOME=/home/ubuntu
```

and an isolated throwaway:

```text
DOCKER_CONFIG
```

The result was:

```text
0 findings
```

for the configuration behavior under test.

---

## Incorrect sudo-induced environment

The same Docker operation was then run with:

```text
HOME=/root
```

The trace showed Docker attempting to access:

```text
/root/.docker/config.json
/root/.docker/cli-plugins
```

Both accesses failed with:

```text
ENOENT
```

RuntimeXRay reported those accesses.

At first glance, these looked suspicious because the test was being performed for user `ubuntu`.

But they were not RuntimeXRay false positives.

They were real Docker filesystem accesses caused by running Docker with a different `HOME`.

### Lesson

The correct interpretation was:

> RuntimeXRay had detected real behavior caused by the test environment.

This was a useful example of the difference between:

```text
false positive
```

and:

```text
true observation caused by an unexpected environment
```

Security tooling must preserve that distinction.

---

# Phase 2 — `docker run`

The next workload was:

```bash
docker run --rm --network none redis:7 redis-cli --version
```

Expected output:

```text
redis-cli 7.4.11
```

The daemon PID was recorded separately with:

```bash
pgrep -x dockerd
```

RuntimeXRay traced the Docker CLI using `--follow-forks`.

The important result was:

```text
0 references to the existing dockerd PID in the traced process graph
```

while the Docker CLI itself communicated through:

```text
AF_UNIX → /var/run/docker.sock
```

RuntimeXRay produced no security finding for this normal operation.

### Why this test mattered

This test demonstrated the boundary between:

```text
process lineage
```

and:

```text
IPC communication with an unrelated pre-existing process
```

The Docker container process was ultimately created through daemon-side infrastructure.

It is not simply a child of the Docker CLI in the CLI's normal process tree.

Therefore RuntimeXRay must not pretend that:

```text
--follow-forks
```

means:

```text
follow the complete distributed execution initiated by an IPC request
```

That would require explicit cross-process/resource modeling beyond ordinary fork lineage.

---

# Redis memory-scanning experiments

Before the later Docker credential-helper work, Redis inside Docker was also used to stress RuntimeXRay's secret scanner.

These experiments were important because they exposed both detection gaps and false positives.

---

## Initial memory scan

A live `redis-cli` process was scanned.

RuntimeXRay scanned approximately:

```text
5,301 pages
28 memory regions
```

An early scan produced a finding containing text from OpenSSL:

```text
Extended master secret
```

The surrounding memory originated from strings inside:

```text
libssl.so.3
```

and included content such as:

```text
Extended master secret: %s
Max Early Data: %u
Session-ID
Master-Key
```

This was not an actual application secret.

It was static library text containing the word:

```text
secret
```

### Lesson

A string merely containing a security-related keyword is not necessarily sensitive runtime data.

This exposed an important false-positive class:

```text
security terminology in executable/library data
        !=
actual secret
```

---

# Redis password experiments

Several ways of supplying a Redis password were tested.

The synthetic password used in these experiments was intentionally non-production data.

---

## Password in command line

A Redis password supplied through a command-line password option was visible in:

```text
argv
```

Initially RuntimeXRay did not classify this correctly.

That exposed a detector limitation.

The secret extractor was improved to recognize semantic password flags such as:

```text
-a
-p
--password
```

and normalize the associated value conceptually as:

```text
password=<value>
```

rather than depending only on literal:

```text
password=
```

text already existing in the source bytes.

---

## Password in environment

The experiments also tested environment-based password delivery.

A mixed test included a synthetic value in the environment and command line.

RuntimeXRay observed the same exact HMAC fingerprint in:

```text
cmdline
environment
memory
```

One historical run produced:

```text
location=cmdline
location=environment
location=memory
```

for the same 24-byte value.

However, inspecting the memory context showed that the memory copy was located in data resembling the initial process stack:

```text
REDIS_PASSWORD=...
REDIS_VERSION=...
PWD=...
/usr/local/bin/redis-cli
```

This was an important correction to our interpretation.

### What this did NOT prove

It did not prove that:

```text
Redis copied the password from environment into an application buffer.
```

A more likely explanation was that RuntimeXRay was observing the original argv/environment representation placed into the process's initial userspace memory by process startup.

Therefore:

> Same fingerprint at multiple locations proves value identity, not necessarily a copy operation.

This became a recurring RuntimeXRay design principle.

---

# Memory-scan performance lesson

One early Redis memory scan completed in roughly:

```text
106 ms
```

After expanding case-insensitive secret matching, an equivalent scan increased to approximately:

```text
4.102 seconds
```

for the same approximately 5,301 pages.

The cause was not Linux process-memory access itself.

The regression came from repeatedly lowercasing data independently for every keyword.

The implementation was changed so normalization work was not repeated per keyword.

The scan time dropped to roughly:

```text
~0.3 seconds
```

for the same workload.

### Lesson

Real-world workloads exposed performance problems that synthetic correctness tests had not made obvious.

---

# Phase 3 — Docker credential lifecycle

The next stage introduced actual credential movement.

A local registry was created so the entire experiment remained controlled.

---

# Local authenticated registry

A synthetic credential was created:

```text
username:
rxray_user

password:
RXRAY_DOCKER_PASS_X7kQ2mNv8pLr4ZtW9yBc3
```

The registry was bound only to localhost:

```text
127.0.0.1:5000
```

The registry used htpasswd authentication.

The initial verification:

```bash
curl http://127.0.0.1:5000/v2/
```

returned:

```text
401
```

confirming that authentication was required.

The password was stored in a test file with restricted permissions for repeatable experiments:

```text
~/rxray-docker-lab/phase3/password.txt
```

This was synthetic lab data, not a production credential.

---

# Phase 3.1 — `docker login --password-stdin`

The primary credential test was:

```bash
docker login \
  --username rxray_user \
  --password-stdin \
  127.0.0.1:5000
```

with the password redirected through stdin.

Both `strace` and RuntimeXRay were used.

RuntimeXRay was run with:

```text
--follow-forks
--scan-memory
```

The login succeeded.

RuntimeXRay detected the synthetic password in runtime data and also detected Docker's persisted authentication representation.

Historical reports classified these observations as, among others:

```text
secret_type=password
location=write_data
length=39
```

and an authentication value approximately:

```text
secret_type=auth
length=68
```

Raw secret output remained redacted by default.

---

# A critical lesson from Docker login

Our initial intuition was that the password detected on stdin/write paths and the credential persisted by Docker might form one exact-fingerprint lineage.

Docker disproved that assumption.

The raw password and Docker's persisted `auth` representation had different fingerprints.

That is correct.

Docker stores an encoded authentication representation rather than the original byte sequence as-is.

Therefore RuntimeXRay could observe:

```text
raw password
```

and:

```text
derived Docker auth representation
```

but exact fingerprint equality could not prove:

```text
password
    ↓ transformed into
auth
```

### This was an important validation success

RuntimeXRay did **not** have enough evidence to claim the transformation.

The correct result was therefore:

```text
two related-looking observations
but no exact-value causal proof
```

This directly reinforced the rule:

> Exact HMAC fingerprint equality proves exact value identity.
> Fingerprint inequality does not allow RuntimeXRay to infer transformations.

Supporting transformed-value lineage remains a separate problem.

---

# Phase 3.2 — `docker logout`

The next ground-truth test examined:

```bash
docker logout 127.0.0.1:5000
```

The expected and observed Docker behavior was:

```text
Removing login credentials for 127.0.0.1:5000
```

After logout, the isolated Docker configuration contained an empty authentication map:

```json
{
  "auths": {}
}
```

`strace` showed that logout itself did not need to contact the registry.

The relevant operation was local credential/configuration manipulation.

This was useful because it showed another distinction:

```text
credential lifecycle operation
        !=
network authentication operation
```

---

# Phase 3.3 — login and logout inside one RuntimeXRay trace

Login and logout were then executed inside one traced shell session:

```bash
/bin/sh -c '
  docker login ... &&
  docker logout ...
'
```

The purpose was to see whether the same stored authentication value could be recognized during:

```text
login configuration write
        ↓
later logout configuration read
```

Because the two observations occurred within one RuntimeXRay execution, they shared one per-run HMAC key.

This made exact fingerprint comparison meaningful.

The experiment validated the usefulness of per-run fingerprints for recognizing the same stored value at multiple runtime observations without placing the raw credential in the report.

---

# Phase 3.4 — password supplied with `-p`

Docker's explicitly insecure command-line mode was also tested:

```bash
docker login \
  --username rxray_user \
  -p 'RXRAY_DOCKER_PASS_X7kQ2mNv8pLr4ZtW9yBc3' \
  127.0.0.1:5000
```

Docker itself warns:

```text
Using --password via the CLI is insecure
```

Ground truth confirmed that the raw password was visible in:

```text
execve argv
```

This means the password can be observable through normal process argument inspection while the process exists.

### Security lesson

RuntimeXRay should distinguish different secret-delivery mechanisms.

These are not equivalent:

```text
password in argv
password through stdin
password in environment
password in a credential helper protocol
```

They create different exposure surfaces.

---

# Phase 3.5 — attempted interactive login through redirected stdin

The following form was tested without `--password-stdin`:

```bash
docker login \
  --username rxray_user \
  127.0.0.1:5000 \
  < password.txt
```

Docker refused:

```text
cannot perform an interactive login from a non-TTY device
```

`strace` showed TTY-related `ioctl` probes.

The raw password was not consumed as though this were `--password-stdin`.

### Lesson

An analysis tool must understand what the target actually did.

It must not infer:

```text
password file redirected to stdin
        ⇒
application consumed password
```

when the application rejected the interaction before reading the credential in the expected way.

---

# Phase 4 — Docker credential helper boundary

The most valuable Docker phase introduced an external credential helper.

A synthetic helper was created:

```text
docker-credential-rxraytest
```

located at:

```text
/home/ubuntu/rxray-docker-lab/phase4/bin/docker-credential-rxraytest
```

Docker was configured with:

```json
{
  "credHelpers": {
    "127.0.0.1:5000": "rxraytest"
  }
}
```

The helper implemented the normal helper operations:

```text
store
get
erase
list
```

and persisted data into an isolated test directory.

---

# Phase 4.1 — helper sanity test

Before RuntimeXRay was involved, the helper integration was tested directly.

The workflow was:

```text
docker login
    ↓
Docker invokes docker-credential-rxraytest
    ↓
helper receives credential JSON
    ↓
helper stores it
```

The login succeeded.

Docker's own config retained the helper mapping and did not contain the credential itself.

Conceptually:

```json
{
  "auths": {
    "127.0.0.1:5000": {}
  },
  "credHelpers": {
    "127.0.0.1:5000": "rxraytest"
  }
}
```

The helper's isolated store contained the credential JSON.

This established ground truth before tracing.

---

# Phase 4.2 — tracing the credential helper boundary

The helper-backed login was then traced with:

```text
--follow-forks
--scan-memory
```

This phase became one of the most important RuntimeXRay development tests.

The trace followed Docker-created helper descendants.

The exact same synthetic credential appeared in several observation contexts, including historical classifications such as:

```text
write_data
read
stdout
memory
```

All occurrences of an exact value shared the same per-run HMAC fingerprint.

One historical report used fingerprint:

```text
hmac-sha256:5b9f00142baa87f7499d620c32c0f16519e99f8883a8520fb1ba68cd3df26756
```

The exact fingerprint value itself is not stable across RuntimeXRay executions because RuntimeXRay uses a random per-run HMAC key.

---

# What Phase 4.2 exposed

At this point, simply grouping all identical fingerprints together was not sufficient.

The same value appearing in:

```text
Docker process
helper process
pipe input
pipe output
memory
stdout
```

does not mean every possible pair of those observations has a causal relationship.

This forced RuntimeXRay to model explicit runtime resources.

The lineage implementation evolved to assign identities to pipe resources and associate file descriptors with those resources.

Later reruns produced explicit DataFlow relationships such as:

```text
exact fingerprint observed across pipe resource_id=1
exact fingerprint observed across pipe resource_id=4
exact fingerprint observed across pipe resource_id=6
```

A historical run produced edges:

```text
648  → 1104   resource_id=1
1105 → 993    resource_id=4
1134 → 1861   resource_id=6
```

The exact sequence numbers are run-specific.

The important semantic fact was:

> RuntimeXRay now had explicit evidence that the same fingerprint crossed a particular pipe resource.

---

# A false correlation discovered and removed

Earlier correlation logic could accidentally combine same-fingerprint observations and produce a stronger file-to-socket interpretation than the evidence justified.

The Docker helper workload exposed this weakness.

The logic was tightened so that:

```text
fingerprint equality
```

means:

```text
same exact value
```

but not automatically:

```text
causal data flow
```

Strong cross-process claims require explicit modeled resource relationships.

The old unsupported file-to-socket correlation disappeared after the fix.

This was one of the most important architectural results of the Docker validation cycle.

---

# Phase 4.3 — file-descriptor and environment inheritance

The credential helper was instrumented to dump:

```text
argv
/proc/self/environ
/proc/self/fd/*
```

A synthetic environment secret was added:

```text
RXRAY_TEST_SECRET=password=rxray_env_inheritance_4_3
```

The helper confirmed that the environment variable was present after `exec`.

This is normal Unix process behavior.

The environment included ordinary session data such as:

```text
SSH_CLIENT
SSH_CONNECTION
DBUS_SESSION_BUS_ADDRESS
DOCKER_CONFIG
HELPER_STORE_DIR
HELPER_DUMP_DIR
PWD
```

and any explicitly exported test values.

### Important conclusion

Environment inheritance itself is not evidence that Docker deliberately transferred a secret.

It is ordinary `execve` environment inheritance.

---

# File descriptors observed in the helper

The helper diagnostic showed its standard streams connected through pipes used for communication with Docker.

The important negative results were that the helper did **not** inherit unrelated descriptors such as:

```text
password.txt
Docker configuration file
/var/run/docker.sock
```

The Docker socket remained associated with the Docker CLI side of the workflow.

This validated RuntimeXRay's need to track:

- FD identity;
- FD duplication;
- fork inheritance;
- exec inheritance;
- close-on-exec behavior;
- resource role.

---

# Phase 4.4 — same fingerprint does not imply causality

A final helper test deliberately created a particularly dangerous situation for a naive correlation engine.

The same synthetic value appeared in several places:

```text
environment
memory
write
read
stdout
```

If RuntimeXRay simply connected every observation that shared a fingerprint, it could invent a false graph.

Instead, the final correlated pipe-chain Finding used only explicit DataFlow edges.

A concrete historical run produced pipe-chain evidence using:

```text
621  → 3242
3243 → 3132
```

over pipe resources:

```text
1
17
```

The Finding did not use:

```text
environment coincidence
```

or:

```text
memory coincidence
```

as proof of pipe causality.

### Core lesson

This test established a critical RuntimeXRay invariant:

> Exact fingerprint equality establishes value identity.
> Causality must come from independent structural evidence.

For pipes, that evidence can be:

```text
same modeled pipe resource
+
write-side observation
+
read-side observation
+
exact fingerprint match
```

Environment and memory observations may strengthen context, but they must not fabricate an edge.

---

# Narrative validation

The Docker helper experiments also exposed an important requirement for RuntimeXRay narratives.

A human-readable narrative must not be freer than the structured Finding that supports it.

We found and corrected a case where a narrative statement could imply a relationship that was not backed by explicit Finding edge evidence.

The resulting rule became:

> A narrative describing flow must be backed by the same explicit graph relationship used by the Finding.

This eventually became regression-tested behavior.

---

# Process identity lessons

The Docker/helper workflow also stressed process identity.

A real traced workload contains:

- processes;
- threads;
- forks;
- exec transitions;
- helpers;
- shells.

Using PID/TID observations carelessly can make one logical process appear as several independent entities.

Docker testing helped drive the process-instance model toward:

```text
process_instance_id
exec_generation
```

rather than relying only on raw numeric PID/TID values.

The helper workflow was particularly useful because it combined:

```text
fork
exec
pipes
multiple process images
```

inside one practical task.

---

# Bugs and architectural weaknesses exposed by Docker

The Docker validation cycle was valuable partly because it did **not** simply pass.

It exposed several real problems or unsafe assumptions.

---

## 1. Environment-sensitive filesystem findings

Running under the wrong `HOME` generated accesses under:

```text
/root/.docker/
```

This was not a RuntimeXRay bug.

It taught us to distinguish environmental ground truth from false positives.

---

## 2. Password classification gap

A password passed through semantic CLI options such as:

```text
-a
-p
--password
```

was not initially classified correctly.

Secret extraction was improved.

---

## 3. Secret-scanner false positive

OpenSSL static text containing:

```text
Extended master secret
```

was initially treated as secret-like content.

This showed that raw keyword matching is insufficient.

---

## 4. Memory-scan performance regression

Case-insensitive keyword processing increased a roughly 5,301-page scan from sub-second behavior to roughly four seconds.

The matching implementation was optimized.

---

## 5. Fingerprint identity mistaken for possible causality

Docker credential-helper traffic demonstrated that identical fingerprints in multiple processes cannot safely be turned into arbitrary flow edges.

Explicit resource lineage became necessary.

---

## 6. Cross-process pipe identity

RuntimeXRay needed stable pipe resource IDs so that:

```text
write(fd=A)
```

in one process and:

```text
read(fd=B)
```

in another process could be recognized as operations on the same kernel pipe resource.

---

## 7. FD inheritance across fork/exec

The helper experiments required correct handling of:

- duplicated descriptors;
- inherited descriptors;
- regular-file provenance;
- standard streams;
- `CLOEXEC`.

---

## 8. Process/exec identity

The real process topology made raw PID/TID-only reasoning insufficient.

This reinforced the process-instance / exec-generation model.

---

## 9. Unsupported narrative causality

Narrative generation was tightened so it could not state a causal relationship merely because two observations shared a fingerprint.

---

## 10. Tracer behavior around nested exec/fork workflows

The Docker helper workflow exposed tracer behavior around post-`exec` events and nested process execution.

A post-exec `SIGTRAP` handling issue was fixed in the ptrace tracer.

This was one example where a real application topology exercised behavior that simpler fixtures had not stressed sufficiently.

---

# Regression tests derived from Docker findings

The goal was not to leave important Docker discoveries as manual knowledge.

Generic regressions were added so the semantics could be protected without requiring Docker in every unit/integration test.

Important tests added or strengthened as a result of this work included:

```text
check_ptrace_sensitive_pipe_chain_env
check_ebpf_sensitive_pipe_chain_env
check_ptrace_fd_exec_inheritance
check_ebpf_fd_exec_inheritance
```

with fixtures including:

```text
sensitive_pipe_chain_env.c
fd_exec_inheritance.c
```

Related FD/resource regressions also covered cases such as:

```text
check_ptrace_fd_alias_flow
check_ebpf_fd_alias_flow

check_ptrace_fork_dup_exec_flow
check_ebpf_fork_dup_exec_flow

check_ptrace_vfork_dup_exec_flow
check_ebpf_vfork_dup_exec_flow
```

These tests protect general RuntimeXRay semantics rather than Docker-specific implementation details.

---

# What those regressions protect

The regression coverage derived from the Docker work checks properties such as:

## Explicit pipe DataFlow

The same exact fingerprint crossing a known pipe resource can create an explicit DataFlow relationship.

---

## Environment coincidence is not flow

A value existing in:

```text
environment
```

and:

```text
memory
```

must not automatically create a causal edge.

---

## Narrative evidence discipline

Flow narratives must be backed by explicit Finding/graph evidence.

---

## FD provenance across exec

Regular files and standard streams retain correct resource identity where appropriate.

---

## CLOEXEC behavior

Descriptors marked close-on-exec must not incorrectly survive into the new executable image.

---

## Backend parity

The important semantics are exercised under both:

```text
ptrace
eBPF
```

where the backend supports the required evidence.

---

# What Docker validation proved about RuntimeXRay

The Docker cycle demonstrated that RuntimeXRay can already provide useful evidence in a real application.

It successfully observed and distinguished:

```text
filesystem access
Unix-socket access
process descendants
fork/exec behavior
credential-related runtime data
memory observations
environment observations
pipe resources
file-descriptor inheritance
exact-value identity
explicit cross-process pipe DataFlow
```

It also demonstrated that RuntimeXRay can avoid certain tempting but unsupported conclusions.

For example:

```text
same value in environment and memory
```

does not imply:

```text
environment → memory copy operation
```

and:

```text
raw password
+
different encoded auth value
```

does not prove:

```text
password → auth transformation
```

using exact fingerprint matching alone.

---

# What Docker validation did NOT prove

This test cycle does not establish that RuntimeXRay can understand every Docker workflow.

It does not yet prove:

- complete Docker daemon-side lineage;
- complete container runtime lineage;
- arbitrary IPC tracing;
- transformed-value tracking;
- full credential lifetime;
- TLS plaintext lineage;
- general taint tracking;
- malicious intent;
- exfiltration;
- exploitability;
- production-scale overhead;
- correctness across all Docker versions and Linux kernels.

---

# The Docker daemon boundary remains important

One especially important limitation is:

```text
docker CLI
     ↓
/var/run/docker.sock
     ↓
pre-existing dockerd
```

RuntimeXRay following Docker CLI descendants does not automatically cross into the already-running Docker daemon.

Therefore:

```text
docker run
```

cannot currently be interpreted as one complete process lineage from:

```text
CLI
```

through:

```text
dockerd
containerd
runc
container process
```

merely because those operations belong to one conceptual Docker action.

Doing that correctly would require explicit resource/session correlation across already-existing processes.

---

# Exact fingerprint semantics

The Docker tests were central to clarifying what RuntimeXRay fingerprints mean.

For two observations:

```text
fingerprint(A) == fingerprint(B)
```

RuntimeXRay can conclude:

> The same exact detected value was observed at A and B during this RuntimeXRay execution.

It cannot automatically conclude:

```text
A caused B
```

To claim flow, additional evidence is required.

Examples include:

```text
shared pipe resource
same process/exec session
resolved file descriptor
explicit DataFlow edge
```

depending on the Finding.

---

# Why the per-run HMAC model was useful

The credential experiments showed why RuntimeXRay uses a per-run HMAC fingerprint rather than printing raw secrets.

It allows observations such as:

```text
password seen in write
password seen in memory
password seen in pipe read
```

to be compared without placing the password itself in the normal report.

Because the HMAC key changes between RuntimeXRay executions:

> Fingerprints are intended for correlation inside one analysis run, not as stable global secret identifiers.

This is a desirable privacy property.

---

# Redaction validation

The Docker credential tests used synthetic credentials specifically so detection behavior could be inspected safely.

Normal RuntimeXRay reports were expected to avoid printing raw secret values unless explicitly requested with:

```text
--show-secrets
```

The Docker login tests confirmed that useful evidence could still be produced using:

```text
secret type
length
location
fingerprint
resource/process evidence
```

without requiring normal reports to expose the credential.

---

# Why `strace` remained useful

RuntimeXRay is not intended to replace `strace` as a generic syscall debugging tool.

During this validation, `strace` was extremely useful as an independent oracle for questions such as:

```text
Did Docker really open this path?
Did it connect to TCP?
Was the password present in execve argv?
Did logout contact the registry?
Did Docker probe for a TTY?
```

RuntimeXRay's value was elsewhere:

```text
raw events
    ↓
resource/process identity
    ↓
secret identity
    ↓
correlation
    ↓
structured security Finding
```

The two tools served different purposes.

---

# Most important lessons from the Docker cycle

## Lesson 1 — Real software breaks assumptions

Docker exposed behaviors that small fixtures did not:

- pre-existing daemon boundaries;
- helper subprocesses;
- encoded credentials;
- inherited environments;
- inherited pipes;
- nested exec workflows.

---

## Lesson 2 — Same value is not the same as flow

Fingerprint equality is powerful, but dangerous if overinterpreted.

The Docker helper work forced RuntimeXRay to separate:

```text
value identity
```

from:

```text
causality
```

---

## Lesson 3 — Resource identity matters

Cross-process flow cannot be made reliable using only:

```text
PID
FD number
timestamp
fingerprint
```

A file descriptor number such as:

```text
3
```

has no global meaning.

The underlying resource identity is what matters.

---

## Lesson 4 — Negative evidence matters

Some of the strongest Docker results were negative:

```text
dockerd was not a traced descendant

helper did not inherit docker.sock

helper did not inherit password.txt

same fingerprint in environment/memory did not create fake causality

transformed Docker auth did not match raw password fingerprint
```

These negative results define the boundaries of trustworthy analysis.

---

## Lesson 5 — Findings must not be stronger than evidence

Docker was the workload that repeatedly reinforced the principle:

> RuntimeXRay should make the strongest statement supported by the evidence — and no stronger.

---

# Validation outcome

The Docker validation was successful, but not because every initial RuntimeXRay behavior was correct.

It was successful because the real workload exposed weaknesses that were then converted into architectural improvements and regression tests.

The progression was approximately:

```text
Docker CLI tracing
      ↓
Docker socket boundary
      ↓
credential detection
      ↓
memory observations
      ↓
credential helper
      ↓
fork/exec + FD inheritance
      ↓
same-fingerprint ambiguity
      ↓
explicit pipe resource identity
      ↓
cross-process DataFlow edges
      ↓
evidence-backed pipe-chain Finding
      ↓
narrative constrained by evidence
```

This is the main value of the Docker exercise.

It changed RuntimeXRay itself.

---

# Current interpretation

Docker should currently be described as:

> The first substantial real-world application used to validate RuntimeXRay's evidence model.

It should **not** yet be described as broad real-world validation of RuntimeXRay as a product.

One real application is not enough.

The next validation targets should exercise substantially different execution patterns before broad public claims are made.

---

# Future use of this validation record

This document is intended to serve three purposes:

1. preserve why important RuntimeXRay architecture decisions were made;
2. provide a reproducible record of the first real-world validation cycle;
3. provide source material for a future technical article.

A future article can be built around the central story:

```text
We pointed an evidence-driven runtime security tool at Docker.

Docker did not merely confirm that the tool worked.

It exposed where our assumptions were wrong.
```

That is the most important result of this validation.