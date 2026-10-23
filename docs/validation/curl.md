# RuntimeXRay Real-World Validation: curl

## Status

This document records the real-world `curl` validation experiments performed during RuntimeXRay development, culminating in the **October 19, 2026** verification of process-image-aware runtime memory scanning.

It is a companion to [`docker.md`](docker.md). The Docker campaign established the local authenticated registry, process/FD lineage foundations, and the principle that **equal secret fingerprints establish value identity, not causality**. The curl campaign used that same controlled HTTP endpoint to investigate how credentials appear in process arguments, files, syscall buffers, and live memory.

**Verified on October 19, 2026:**

- **A1:** `--user` credential observed in command-line arguments, live memory, and a `sendto` event, with a matching HMAC fingerprint.
- **C1:** `.netrc` credential observed through a `read` event, live memory, and a `sendto` event, with a matching HMAC fingerprint.
- **C1 event-driven scanning:** two different scan reasons were authorized for the same process image; the first scanned 1,000 pages and found no secret observations, while the second scanned 1,000 pages and produced one `http_basic_password` observation.
- **C1 graph evidence:** the recorded JSON had two `observed_at` edges, and the automated regression verified the actual edge endpoints and a process-to-memory `observed_in` edge.
- **Regression:** `check_c1_memory_scan_coordinator` passed, and the complete suite passed **61/61** tests.

The earlier baseline C1 observation — missing memory evidence under the previous one-scan-per-PID approach — is preserved as development history, not presented as a reproduced A/B benchmark with unchanged binaries and test conditions.

This is validation of *observable behavior*, not a claim that RuntimeXRay proves the entire file-to-network causal path, finds every in-memory copy, or accurately measures arbitrary applications at production scale.

---

# Why curl?

`curl` is a mature real-world Linux application whose HTTP authentication code creates a compact but nontrivial credential lifecycle. The same application can accept credentials through two meaningfully different mechanisms:

```text
A1: command-line option (--user)
    └── credential is available in argv
        └── curl constructs an HTTP Basic Authorization value
            └── outbound syscall buffer

C1: restricted .netrc file (--netrc-file)
    └── curl reads a file containing login/password entries
        └── curl constructs an HTTP Basic Authorization value
            └── outbound syscall buffer
```

Both mechanisms allow us to ask whether RuntimeXRay can:

1. capture credential observations at the correct execution boundaries;
2. correlate the same detected value inside **one** analysis run without revealing it;
3. retain reliable process-image identity;
4. associate syscall-backed `Data` observations with event evidence;
5. distinguish the credential's presence from an inferred transfer, copy, or security compromise;
6. justify memory scans at different points in the application's execution.

Unlike a small synthetic fixture, curl's parsing, buffering, request construction, and memory allocation are controlled by real application/library code. Unlike tracing the `docker` CLI, curl directly makes the network request being inspected. The endpoint remained a local Docker registry; no third-party service was involved.

---

# Test environment and provenance

| Item | Recorded value or requirement |
| --- | --- |
| Host | Ubuntu VM used for RuntimeXRay development |
| Repository | `~/workspace/runtime-xray` |
| Instrumented application | `/usr/bin/curl` |
| Backend in final A1 run and automated C1 regression | `ptrace` |
| Endpoint | `http://127.0.0.1:5000/v2/` |
| HTTP server | Local Basic-auth-protected Docker registry from the Docker validation campaign |
| Unauthenticated endpoint response | `401` |
| Test credentials | Synthetic, local-only; never production credentials |
| C1 historical `.netrc` | `/home/ubuntu/rxray-curl-lab/c1.netrc`, permissions `0600` |
| Output directory | `/home/ubuntu/rxray-curl-lab` |
| JSON reporter | RuntimeXRay lineage observations and edges; schema `2.0` in the contemporary implementation |
| Core Stage B commit | `9d21e17` — `feat(memory): introduce process-image-aware memory scan coordination` |
| Stage A commit | `2982e64` — `feat(memory): prioritize memory regions for credential scanning` |
| Validation record commit | `4d8fc9f` — extended Docker validation history |

The test timestamps and measured runtimes below are from recorded executions; they are not generic performance guarantees. Versions of curl, OpenSSL, libraries, and the kernel were **not recorded in the supplied A1/C1 logs**. Capture these when reproducing the experiment; do not infer them from the Docker campaign's historical inventory.

## Ground truth versus RuntimeXRay evidence

Ground truth for the observed October 19 run included:

```text
curl http://127.0.0.1:5000/v2/
→ HTTP 401 without authentication

C1 .netrc file
→ exists, restricted to owner read/write (0600)

RuntimeXRay trace
→ process exits successfully and creates a JSON report
```

Here, `trace exit=0` reports the **RuntimeXRay command's shell exit status**. It does not mean the registry accepted the credentials. In these curl commands, HTTP `401` need not cause a nonzero curl exit status without `--fail` or equivalent HTTP-error handling.

The observed `read`/`sendto` correlations come from RuntimeXRay trace output and graph assertions, **not** from a separately captured `strace` file for this final curl run. Independent `strace` was extensively used in the preceding Docker campaign, but a matching curl `strace` baseline was not included in the preserved October 19 evidence.

---

# Validation methodology

The workflow followed the same evidence-first pattern as Docker:

```text
Controlled credential source
         ↓
Expected file/argv/network behavior
         ↓
RuntimeXRay trace with --scan-memory
         ↓
Inspect scan-reason and budget logs
         ↓
Parse JSON lineage observations
         ↓
Compare fingerprints within the same run
         ↓
Verify evidence edges by from_seq / to_seq
         ↓
Turn observations into a repeatable integration regression
         ↓
Run the complete CTest suite
```

We explicitly separated three levels of claim:

- **Observation:** a credential value was detected in a specified context (`cmdline`, `memory`, `read`, `sendto`).
- **Correlation:** two observations have the same per-run HMAC fingerprint.
- **Causality:** a transfer or transformation was independently supported by modeled events and resources, **not** by fingerprint equality alone.

This distinction is essential when interpreting the experiments below.

---

# Phase 0 — Local registry and laboratory checks

The registry was initially created for `docs/validation/docker.md` (historical Docker Phase 3). The curl campaign reused it; the October 19 A1/C1 tests did **not** reinstall the registry.

## 0.1 Check local endpoint

```bash
cd ~/workspace/runtime-xray
LAB=/home/ubuntu/rxray-curl-lab

curl -sS -o /dev/null \
  -w 'Registry HTTP %{http_code}\n' \
  http://127.0.0.1:5000/v2/
```

**Recorded output:**

```text
Registry HTTP 401
```

A `401` is useful here: it means that the server requires authentication and curl can reach the intended local endpoint. It does **not** by itself verify that any particular credential is valid.

For a new environment, prepare an isolated authenticated registry using the Docker validation document's historical Phase 3 setup, or provide an equivalent local Basic-auth server. The automated regression expects the registry to be running but deliberately does **not** create or destroy Docker containers.

## 0.2 Verify historical C1 credential file

```bash
ls -l "$LAB/c1.netrc"
```

**Recorded result:**

```text
-rw------- 1 ubuntu ubuntu 84 Oct 17 08:06 /home/ubuntu/rxray-curl-lab/c1.netrc
```

The 84-byte file size and timestamp describe that historical lab artifact; they are **not** mandatory properties of another `.netrc` file. The restriction to `0600` protects the synthetic test credential. Do not copy any private `.netrc` contents into commits, issues, log bundles, or a public validation article.

## 0.3 Record versions for a fresh reproduction

```bash
uname -a
/usr/bin/curl --version
./build/runtimexray --help

git rev-parse HEAD
git status --short
```

These are **recommended reproduction commands**; their output is not part of the preserved October 19 evidence.

---

# Phase 1 — A1: credential supplied through command-line arguments

## Question

Can RuntimeXRay recognize a credential delivered via `curl --user` in three different observation contexts during one trace?

```text
argv / cmdline
      │
      ├── same exact detected value in memory?
      │
      └── same exact detected value in sendto?
```

The intent was to test value identity across contexts, not to claim that the scanner could reconstruct curl's internal data copying steps.

## Procedure (verified October 19, 2026)

```bash
cd ~/workspace/runtime-xray
LAB=/home/ubuntu/rxray-curl-lab

sudo env HOME=/home/ubuntu \
  ./build/runtimexray trace \
  --backend ptrace \
  --follow-forks \
  --scan-memory \
  --json "$LAB/a1-coordinator.json" \
  --report "$LAB/a1-coordinator-report.txt" \
  /usr/bin/curl \
  --silent \
  --show-error \
  --user 'rxray_a1:A1_test_password_2026' \
  --output /dev/null \
  http://127.0.0.1:5000/v2/ \
  > "$LAB/a1-coordinator-stdout.txt" 2>&1

echo "trace exit=$?"
```

**Recorded exit status:** `trace exit=0`.

This command intentionally places a **synthetic test credential** on the process command line. That is acceptable for a disposable security lab; avoid it for real secrets. The test value above is historical and may be changed for a new local reproduction.

## Runtime scan log

```text
2026-10-19 18:38:08 [INFO] Initial process context inspection: TGID=1363736 instance=1 generation=0 observations=1
2026-10-19 18:38:19 [INFO] Runtime memory scan: TGID=1363736 instance=1 generation=0 reason=DataBoundaryCrossing pages=1000 observations=1
```

Interpretation:

- `Initial process context inspection` recorded one observation from initial command-line/environment inspection. This line does **not** represent a 1,000-page memory scan.
- The actual runtime memory scan was triggered at a `DataBoundaryCrossing` and attempted 1,000 pages.
- The scan yielded one secret observation.
- Both observations were associated with process instance `1`, exec generation `0`.
- There was no recorded `SensitiveDataDiscovery` scan in this A1 run. That is consistent with the event-driven design; the coordinator does not run every reason on every invocation.

## JSON validation

The command used to validate that one exact detected value appeared in all three contexts was:

```bash
jq '
  [.lineage.observations[] | select(.type == "data")] as $data |
  [.lineage.observations[] |
    select(.type == "event" and .syscall == "sendto")
  ] as $sends |
  {
    cmdline_count: (
      [$data[] | select(.source == "cmdline")] | length
    ),
    memory_count: (
      [$data[] | select(.source == "memory")] | length
    ),
    sendto_fingerprints: (
      [$sends[] | select((.fingerprint // "") != "")] | length
    ),
    same_secret_in_all_three: (
      any(
        $data[];
        . as $cmd |
        .source == "cmdline" and
        (.fingerprint // "") != "" and
        any(
          $data[];
          .source == "memory" and
          .fingerprint == $cmd.fingerprint
        ) and
        any(
          $sends[];
          .fingerprint == $cmd.fingerprint
        )
      )
    )
  }
' "$LAB/a1-coordinator.json"
```

**Recorded output:**

```json
{
  "cmdline_count": 1,
  "memory_count": 1,
  "sendto_fingerprints": 1,
  "same_secret_in_all_three": true
}
```

## Result and limits

**PASS:** a matching fingerprint was recorded for command-line data, a memory observation, and a `sendto` event within the same analysis run.

This establishes **exact detected-value identity** across those contexts. It does not establish precisely where curl allocated the credential, whether it was copied into a fresh heap buffer, how many physical copies existed, or whether the observation was from an initial stack region. A separate memory-map/address and lifetime analysis would be required to make those claims.

---

# Phase 2 — C1: credentials from a restricted .netrc file

## Question

Can RuntimeXRay associate one recognized HTTP Basic password with a file read, an outbound send event, and a later live-memory observation?

```text
.netrc file
   │
   └── read() ── observed credential fingerprint
                          │
                          ├── same fingerprint in memory
                          │
                          └── same fingerprint in sendto()
```

**Important:** the diagram summarizes correlated observations. The arrows do **not** constitute proof of byte-for-byte internal copying or a fully established source-to-sink `DataFlow` edge.

## Historical limitation preceding Stage B

The earlier implementation allowed only the first runtime memory scan per PID. In the earlier C1 experiment, syscall evidence identified credentials during `read` and outbound `sendto`, but the memory observation was missing. This was the practical motivation for replacing the one-scan-per-PID guard with a coordinator that can authorize another scan for a *different semantic reason*.

The historical observation is recorded qualitatively. The original pre-coordinator JSON and its exact scan log are **not reproduced here**, so this is **not** a controlled numeric comparison against the October 19 binary. The later experiment does establish that a second scan can produce useful evidence after the first scan did not.

## Procedure (verified October 19, 2026)

First verify the local registry and `c1.netrc` as in Phase 0. Then:

```bash
cd ~/workspace/runtime-xray
LAB=/home/ubuntu/rxray-curl-lab

sudo env HOME=/home/ubuntu \
  ./build/runtimexray trace \
  --follow-forks \
  --scan-memory \
  --json "$LAB/c1-coordinator.json" \
  --report "$LAB/c1-coordinator-report.txt" \
  /usr/bin/curl \
  -sS \
  --netrc-file "$LAB/c1.netrc" \
  -w 'HTTP %{http_code}\n' \
  http://127.0.0.1:5000/v2/ \
  > "$LAB/c1-coordinator-stdout.txt" 2>&1

echo "trace exit=$?"
```

**Recorded exit status:** `trace exit=0`.

The manual C1 command above did not explicitly set `--backend ptrace`; it used the command's configured default backend. The subsequently automated C1 regression **explicitly** chose ptrace. Do not silently conflate those two commands.

## Scan logs — central result of Stage B

```text
2026-10-19 13:13:40 [INFO] Initial process context inspection: TGID=1358540 instance=1 generation=0 observations=0
2026-10-19 13:13:50 [INFO] Runtime memory scan: TGID=1358540 instance=1 generation=0 reason=SensitiveDataDiscovery pages=1000 observations=0
2026-10-19 13:13:51 [INFO] Runtime memory scan: TGID=1358540 instance=1 generation=0 reason=DataBoundaryCrossing pages=1000 observations=1
```

| Stage | Reason or action | Pages attempted | New observations |
| --- | --- | ---: | ---: |
| Initial process context | argv/environment check | Not a memory-page scan | 0 |
| First memory scan | `SensitiveDataDiscovery` | 1,000 | 0 |
| Second memory scan | `DataBoundaryCrossing` | 1,000 | **1** |
| **Total memory scans** | **Same process image** | **2,000 page attempts** | **1** |

This was the decisive test of the coordinator:

- Both scans targeted TGID `1358540`.
- Both were authorized for `process_instance_id=1`, `exec_generation=0`.
- The two scan reasons were independent.
- The first scan did **not** find the credential in the pages inspected at that moment.
- The second scan **did** find one secret observation, later identified as `http_basic_password`.
- Total attempted pages respected the then-current 2,000-page process-image budget.

**A crucial caveat:** 1,000 + 1,000 page attempts do not mean 2,000 **unique** pages were scanned. The coordinator budgets *work*, not unique memory addresses. The two scans may revisit some or all of the same regions at different times. The experiment also does not by itself tell us whether the second observation appeared because of a memory-state change, scheduling/timing, different buffers, or another factor.

## Output files

The historical run produced:

```text
/home/ubuntu/rxray-curl-lab/c1-coordinator-report.txt   86K
/home/ubuntu/rxray-curl-lab/c1-coordinator-stdout.txt   597B
/home/ubuntu/rxray-curl-lab/c1-coordinator.json         589K
```

These are approximate shell-reported file sizes, not output-size requirements of the test. Files were owned partly by root because the tracer was run with `sudo`.

## Inspect the two scan reasons

```bash
grep -E \
  'Initial process context inspection|Runtime memory scan:' \
  "$LAB/c1-coordinator-stdout.txt"
```

## Inspect fingerprint correlation without printing fingerprints

```bash
jq '
  [.lineage.observations[] | select(.type == "data" and .source == "memory")] as $memory |
  [.lineage.observations[] |
    select(
      .type == "event" and
      (.syscall == "read" or .syscall == "sendto") and
      (.fingerprint // "") != ""
    )
  ] as $events |
  {
    memory_observations: ($memory | length),
    memory_matches_read: (
      [$memory[] as $m |
       $events[] |
       select(.syscall == "read" and .fingerprint == $m.fingerprint)]
      | length
    ),
    memory_matches_sendto: (
      [$memory[] as $m |
       $events[] |
       select(.syscall == "sendto" and .fingerprint == $m.fingerprint)]
      | length
    ),
    observed_at_edges: (
      [.lineage.edges[] | select(.relation == "observed_at")]
      | length
    ),
    memory_context: [
      $memory[] |
      { process_instance_id, exec_generation, secret_type }
    ]
  }
' "$LAB/c1-coordinator.json"
```

**Recorded output:**

```json
{
  "memory_observations": 1,
  "memory_matches_read": 1,
  "memory_matches_sendto": 1,
  "observed_at_edges": 2,
  "memory_context": [
    {
      "process_instance_id": 1,
      "exec_generation": 0,
      "secret_type": "http_basic_password"
    }
  ]
}
```

**PASS:** RuntimeXRay recognized the same HMAC fingerprint in one memory observation, one `read` event, and one `sendto` event; the memory observation belonged to the expected process image.

Two `observed_at` edges were recorded. The raw count alone would not guarantee that the edges point to the correct observations: that stronger assertion was added in the automated regression described next.

---

# Phase 3 — Why the new MemoryScanCoordinator mattered

## Stage A: prioritize regions before adding more scans

The initial memory-scanning improvement was committed as:

```text
2982e64 feat(memory): prioritize memory regions for credential scanning
```

It introduced region-policy selection based on `/proc/<pid>/maps`, giving higher priority to writable stack, heap, and anonymous mappings before lower-priority mappings. The policy uses a stable sort so ties preserve the original order. This increases the chance that a fixed page budget reaches application-relevant writable data rather than spending it on read-only executable/library regions.

**What Stage A does not prove:** that all interesting data reside in those regions, or that the same region ranking is optimal for every workload.

## Stage B: process-image-aware scan coordination

Committed as:

```text
9d21e17 feat(memory): introduce process-image-aware memory scan coordination
```

The integration introduced:

- `include/process_image_key.hpp`: `{process_instance_id, exec_generation}` identity, avoiding simple PID-only accounting and differentiating images after a successful `execve`.
- `include/memory_scan_coordinator.hpp` and `src/memory_scan_coordinator.cpp`: policies, scan permits, reservation/accounting, and completion with refunds for unused page reservations.
- `LineageAnalyzer::active_process_image(tgid)`: side-effect-free lookup of the current image identity.
- A dedicated `TraceMemoryScanSession` in `src/commands/trace_command.cpp`, avoiding scan-policy logic scattered through syscall handling.
- New unit coverage for coordinator accounting and process/exec identity.

### Default policy at the time of this validation

| Policy field | Default |
| --- | ---: |
| `max_scans_per_reason` | 1 |
| `max_scans_per_process_image` | 3 |
| `max_pages_per_scan` | 1,000 |
| `max_pages_per_process_image` | 2,000 |
| `max_observations_per_scan` | 50 |

These are policy defaults in the October 2026 implementation, not externally mandated limits.

### Scan reasons

The coordinator defined the following semantic reasons:

```text
InitialInspection
SensitiveDataDiscovery
MemoryStateChange
DataBoundaryCrossing
ExplicitRequest
```

Only the relevant event-driven triggers were integrated into the curl tests:

- **Initial context**: `capture_initial_context` scans `/proc` command-line/environment inputs once per process image; it is **not yet** an `InitialInspection` **memory scan**.
- **SensitiveDataDiscovery**: when a sensitive inbound read/receive buffer is recognized on syscall exit, request a memory scan.
- **DataBoundaryCrossing**: during an outbound syscall entry (including `sendto`, or another recognized sensitive payload), request a separate memory scan.

The coordinator supports other reasons structurally, but the October 19 curl runs did not demonstrate `MemoryStateChange`, `ExplicitRequest`, or a fork-triggered `InitialInspection` memory scan.

### Identity and budgets

The key is the process **image**, not just the PID:

```text
{ process_instance_id = 1, exec_generation = 0 }
               |
               +-- SensitiveDataDiscovery -> scan permit
               |
               +-- DataBoundaryCrossing   -> independent permit
```

Repeated requests with the same reason for the same image are bounded. Budgets and reasons are accounted for separately as specified by policy. Page reservations are reconciled on scan completion. A successful `execve` changes the generation; a newly observed child has an independent process-instance identity.

A different image key alone does **not** establish inherited-secret data flow.

### Contextual event sequences

The trace code records the triggering syscall event sequence as context for a requested scan when available. This helps attach observations to the correct process image and nearby runtime evidence, but **the event reference itself is not proof that the detected bytes came from that syscall**.

This is particularly important when a memory observation is correlated with an outbound network event. The secret may have existed in memory well before the network send.

---

# Phase 4 — Automated C1 integration regression

The manual success was turned into a reproducible test:

```text
tests/test_c1_memory_scan_coordinator.sh
```

Registered with CMake/CTest as:

```text
check_c1_memory_scan_coordinator
```

The test is not a pure unit test: it executes real `/usr/bin/curl` against the local authenticated registry and inspects live process memory with ptrace.

## Fixture model

The script:

1. checks for `curl`, `python3`, `timeout`, and suitable privilege access;
2. checks the registry returns unauthenticated HTTP `401`;
3. creates a private temporary directory and a `.netrc` with randomly generated disposable credentials (mode `0600`);
4. invokes RuntimeXRay with `--backend ptrace --follow-forks --scan-memory`;
5. emits a temporary JSON report and runtime log;
6. parses both without printing the raw credential or fingerprint;
7. removes the temporary artifacts during cleanup.

It **does not** start the registry and **does not** require the registry to accept the random credentials. Its purpose is to trace credential loading and HTTP Basic request construction, not to test login success.

## Assertions

The regression checks:

- exactly one `SensitiveDataDiscovery` runtime memory scan;
- exactly one `DataBoundaryCrossing` runtime memory scan;
- same process-image identity and TGID for those scans;
- 1,000 pages or fewer per scan and no more than 2,000 attempted pages for the image;
- a scanner-derived `http_basic_password` memory observation;
- matching fingerprint in `read` and `sendto` events belonging to the same image;
- real `observed_at` edges from the correct syscall events to their corresponding `Data` observations, verified using `from_seq` and `to_seq` rather than edge counts alone;
- an `observed_in` edge connecting the memory observation to its process node.

The test can fail when timing or memory layout differs enough that a credential falls outside the scanned pages. That would need investigation; it should not be silently reclassified as success.

## Run directly

```bash
cd ~/workspace/runtime-xray

sh tests/test_c1_memory_scan_coordinator.sh \
  ./build/runtimexray

echo "test exit=$?"
```

**Recorded result:** nine `PASS` lines and `test exit=0`.

The output included:

```text
PASS: SensitiveDataDiscovery scan authorized
PASS: DataBoundaryCrossing scan authorized
PASS: both scans share one process-image identity
PASS: page budget respected (1000 + 1000 pages)
PASS: matching HTTP Basic credential observed in memory
PASS: matching fingerprint observed in read and sendto
PASS: read and sendto observed_at edges verified
PASS: memory observed_in process edge verified
PASS: C1 MemoryScanCoordinator regression
```

## Run under CTest

```bash
ctest --test-dir build \
  -R '^check_c1_memory_scan_coordinator$' \
  --output-on-failure -V
```

**Recorded result:**

```text
1/1 Test #34: check_c1_memory_scan_coordinator ... Passed  11.58 sec
100% tests passed, 0 tests failed out of 1
```

Another observed full-suite execution took `11.74 sec` for this same test. These times are diagnostic observations, not performance targets.

CTest config for this integration scenario includes:

```cmake
set_tests_properties(
    check_c1_memory_scan_coordinator
    PROPERTIES
        SKIP_RETURN_CODE 125
        TIMEOUT 150
)
```

### SKIP semantics

The script returns:

```text
0   assertions passed
1   test failed
125 external environment not available (CTest SKIP)
```

A skip is **not** an assertion pass. In CI, always inspect whether the C1 test actually ran against a registry; a suite can complete while this optional integration scenario is skipped.

For this October 19 run the C1 integration test actually executed and passed.

---

# Phase 5 — Complete regression suite

After registering the new C1 test, the complete test suite was run:

```bash
cd ~/workspace/runtime-xray
ctest --test-dir build --output-on-failure -j"$(nproc)"
```

**Recorded result:**

```text
100% tests passed, 0 tests failed out of 61
Total Test time (real) = 51.00 sec
```

Relevant registered tests visible in the output included:

```text
check_memory_region_priority
check_memory_scan_coordinator
check_process_image_identity
check_c1_memory_scan_coordinator
check_ptrace_sensitive_object_flow
check_ptrace_sensitive_pipe_chain_env
check_ptrace_fd_exec_inheritance
check_cross_boundary_evidence
```

**Meaning:** the new coordinator and C1 behavior passed alongside the existing suite, including lineage and process/FD regressions. It does not establish performance, memory consistency, or protocol completeness beyond those tested behaviors.

---

# Evidence interpretation: what curl established, and what it did not

## Evidence that *was* established

**A1** demonstrated the same detected credential value in `cmdline`, `memory`, and `sendto` during one analysis run.

**C1** demonstrated the same detected HTTP Basic credential value in a file-read-associated event, memory, and an outbound send event, and verified corresponding evidence-edge structure through the regression test.

**Stage B** demonstrated that a second scan of one process image, justified by a different semantic event, can find a secret when the earlier scan found none.

**The entire suite** completed with 61 passing tests on the reported host.

## Claims that were *not* established

- **Not complete taint tracking.** Equal fingerprints alone do not prove a specific source-to-sink byte-copy chain.
- **Not password-exfiltration detection.** The destination is a controlled local registry, and a Basic Authorization value in an outbound HTTP request can be entirely expected application behavior.
- **Not complete memory coverage.** Pages were limited per scan; 2,000 attempted pages need not be unique.
- **Not proof of a fresh heap allocation.** Memory hits could be in stack, heap, anonymous, or other mapped regions; a source label of `memory` is insufficient to distinguish them without map/address evidence.
- **Not proof of secret lifetime.** A snapshot cannot establish when a credential was created, whether it was later erased, or whether multiple copies survived.
- **Not proof of causality from `observed_at` alone.** The edge documents captured syscall-related evidence; it does not imply that unrelated memory bytes originated in that event.
- **Not a TLS plaintext result.** The verified endpoint was `http://127.0.0.1:5000/v2/`, not HTTPS.
- **Not fork/exec inheritance validation.** A1 and C1 each reported the observed credential on one process image (instance `1`, generation `0`).
- **Not a production overhead benchmark.** The recorded test elapsed time includes tracing, curl execution, memory scanning, reporting, and fixture/runtime effects.
- **Not cross-run fingerprint stability.** RuntimeXRay's per-run HMAC key means hashes must be compared within the same run, not across independent reports.

## Why `observed_at` and `observed_in` are different

The C1 regression explicitly verifies both kinds of relationship:

```text
Syscall Event (read or sendto)
        │
        └── observed_at ──> syscall-backed Data observation

Process node
        │
        └── observed_in ──> memory-derived Data observation
```

A matching fingerprint between the syscall-backed `Data` and the memory-derived `Data` establishes value identity. It does **not** automatically add a causal edge between the two observations.

That restraint is deliberate: the Docker credential-helper tests had already exposed the danger of inventing flows solely because values match.

---

# Re-run playbook (current Stage B implementation)

This is a condensed set of reproducible commands using the current-style JSON schema and scanner logs. It complements, rather than replaces, the dated test records above.

## Step 1 — Confirm the fixture

```bash
cd ~/workspace/runtime-xray
LAB=/home/ubuntu/rxray-curl-lab
mkdir -p "$LAB"

curl --noproxy '*' -sS -o /dev/null \
  -w 'Registry HTTP %{http_code}\n' \
  http://127.0.0.1:5000/v2/
```

Expected for the authenticated local fixture: `Registry HTTP 401`.

## Step 2 — Run the maintained C1 regression

```bash
ctest --test-dir build \
  -R '^check_c1_memory_scan_coordinator$' \
  --output-on-failure -V
```

This is the **preferred** repeatable C1 path because the script generates synthetic credentials itself and checks exact lineage endpoints. It also avoids reliance on the historical `c1.netrc`.

## Step 3 — Optionally repeat A1 manually

```bash
sudo env HOME=/home/ubuntu \
  ./build/runtimexray trace \
  --backend ptrace --follow-forks --scan-memory \
  --json "$LAB/a1-coordinator.json" \
  --report "$LAB/a1-coordinator-report.txt" \
  /usr/bin/curl \
  --noproxy '*' --silent --show-error \
  --user 'rxray_a1:A1_test_password_2026' \
  --output /dev/null \
  http://127.0.0.1:5000/v2/ \
  > "$LAB/a1-coordinator-stdout.txt" 2>&1
```

Note: the added `--noproxy '*'` makes the reproduction explicitly independent of proxy-related environment settings; it was **not** present in the original recorded A1 command. For strict historical reproduction, use the command in Phase 1.

## Step 4 — Verify full suite

```bash
ctest --test-dir build --output-on-failure -j"$(nproc)"
```

## Step 5 — Check integrity of repository changes

```bash
git diff --check
git status --short
```

## Safe publication checklist

Before attaching any output to GitHub or publishing an article:

- Keep `.netrc` and temporary credentials out of version control.
- Do not publish raw `--show-secrets` traces.
- Review `strace`, diagnostic logs, and helper stores before sharing: they may include argv, environment, or authentication buffers.
- Do not treat synthetic dummy credentials as proof of exploitability.
- Prefer reporting counts, event types, and lineage structure over raw credential values.
- Clearly state that an HTTP `401` and tracer exit `0` are compatible outcomes.

---

# Engineering lessons and next steps

## Lesson 1 — A scan is a time-bounded observation, not a process property

The first C1 scan found zero secret observations. The second found one. A `0` result from a limited scan should therefore mean:

> No matching secret observation in the attempted pages at this moment.

It should **not** mean:

> This process never contained the secret.

## Lesson 2 — Trigger reasons must remain independent

The successful C1 run required both `SensitiveDataDiscovery` and `DataBoundaryCrossing` to be allowed for the same image. A single `already_scanned[pid]` flag cannot express that requirement.

## Lesson 3 — Identity matters across process changes

`ProcessImageKey` gives the coordinator a principled unit for scan budgets and evidence attribution. The curl tests exercised one image; future `fork`/`execve` scenarios must test how multiple images are created and how old memory evidence is separated from new generations.

## Lesson 4 — Evidence quality matters more than an impressive flow diagram

C1 provides strong multi-context correlation. It is still essential not to assert an unobserved internal copy or a full file-to-network causal chain. Stronger claims require corresponding source/FD/resource/event evidence.

## Lesson 5 — Regression tests should validate graph endpoints

Counting two `observed_at` edges is weaker than checking which syscall observations those edges actually connect. The automated C1 test went beyond aggregate counts and checked `from_seq` / `to_seq` semantics.

## Follow-up work (not yet validated by this curl campaign)

1. **Stage C — InitialInspection on fork and successful exec.** Scan each newly observed process image with an explicit permit, not merely argv/environment context inspection.
2. **Inherited secrets.** Observe a credential in a parent and child and distinguish plausible COW inheritance from proven repeated presence; avoid inventing causality from same address/fingerprint alone.
3. **Exec generation boundary.** Successful `execve` replaces private user-space mappings. A secret detected afterward needs new provenance evidence; old COW mappings are not a sufficient explanation.
4. **Memory consistency metadata.** Record whether target threads were stopped during scanning; differentiate private and shared mappings and recognize snapshot limitations.
5. **More complete scan-budget accounting.** Consider whole-session caps so a large fork tree cannot receive unlimited aggregate memory-scanning work.
6. **Coverage and performance experiments.** Measure which regions were inspected, estimate re-scans of the same pages, and benchmark on larger multithreaded workloads.
7. **Additional curl modes.** HTTPS, redirection, proxies, authentication negotiation, credential changes during a long-running request, and multiple independent transfers require separate tests.
8. **Deterministic A1 regression.** The A1 result was verified manually. A dedicated automated A1 test may be valuable, but one was not established in the preserved October 19 record.

---

# Outcome

The curl campaign demonstrated a concrete gain from process-image-aware event-driven scanning:

```text
Earlier C1 limitation:
    read + send evidence, missing memory observation
                    ↓
Stage A:
    prioritize writable, application-relevant memory regions
                    ↓
Stage B:
    allow separate scans for separate semantic reasons
                    ↓
October 19 C1:
    discovery scan: 1000 pages, 0 observations
    boundary scan:  1000 pages, 1 observation
                    ↓
    same credential fingerprint in read, memory, sendto
                    ↓
    verified syscall-to-Data and process-to-memory evidence edges
                    ↓
    permanent C1 regression + 61/61 passing tests
```

The result is significant **because an initially empty scan did not terminate the evidence collection process**. A later semantically justified scan produced a useful observation without loosening the project's core evidence discipline.

The curl tests remain one controlled real-world validation scenario, not a comprehensive claim about curl, HTTP authentication, credential lifetime, or memory scanning in general.

---

# Planned expansion — Credential Source Matrix (2026-10-23)

**Status:** proposed follow-up campaign, not a results report. All October 19 A1/C1 results above remain historical; no expanded-scenario PASS is claimed here.

The existing local HTTP Basic-auth registry and evidence discipline remain the baseline. For each new case, use only disposable credentials and record the actual kernel, curl version, RuntimeXRay commit, trace backend and memory reader. Keep generated credential files (`0600`) and unredacted artifacts outside version control.

The first additional target is config-file credentials (B1), followed by direct header (D1), URL userinfo (E1), stdin (F1) and interactive prompt (G1). Negative controls must ensure that fingerprint equality alone never creates a false causal flow.

## Scenario matrix

Test IDs are stable. The rows marked **planned** are proposals, not claimed results.

| ID | Input mechanism | Intended distinct evidence | Status / notes |
| --- | --- | --- | --- |
| **A1** | `--user user:password` | Initial argv; in-memory recognition; outbound HTTP Basic | Historical PASS; rerun first |
| **C1** | `--netrc-file FILE` | File read / FD context; memory; outbound HTTP Basic | Historical PASS; maintained regression |
| **B1** | `--config FILE` containing a `user` option | Config file read; authentication derived from its content; network boundary | Planned; avoid putting password in argv |
| **D1** | `--header 'Authorization: Basic ...'` | Encoded header supplied in argv; outbound Basic header; decoded-value detector if supported | Planned; do **not** require a plaintext password memory hit |
| **E1** | `http://user:password@127.0.0.1:5000/v2/` | URL userinfo in argv; outbound Basic; URL parsing/normalization | Planned; credentials intentionally occur in argv |
| **F1** | `--config -` with config bytes from stdin | Read from FD 0/pipe; outbound Basic; correct FD/source attribution | Planned; stdin is the source, not necessarily a named file |
| **G1** | `--user user` with password supplied at an interactive prompt | PTY/TTY input; outbound Basic; absence of password from original argv | Planned; must use a real PTY fixture |
| **H1** | Environment-mediated invocation | Distinguish the originating shell/wrapper from curl's actual input | Optional; curl does not have a generic `CURL_PASSWORD` input mechanism |
| **N0** | No authentication | No invented secret observation or auth-specific flow | Planned negative control |
| **N1** | Unrelated decoy secret present but not sent | No fabricated decoy-to-network DataFlow solely from a fingerprint or temporal proximity | Future controlled fixture |

Implementation notes:

- For **B1**, a curl config file can set the `user` option. Capture its read without leaking its contents into logs.
- For **D1**, the exact bytes supplied to curl are **already encoded**. Keep separate the raw header value, a decoded password, and any transformation tag such as `base64_decoded`. Missing plaintext in memory is not automatically a bug.
- For **F1**, avoid creating the supposed stdin-origin secret as an argument or environment variable of the traced curl process. A dedicated parent fixture can write the private config into a pipe; document any extra helper process explicitly.
- For **G1**, a pipe is not equivalent to an interactive terminal. Use a PTY harness and record whether the tested curl version actually prompts.
- For **H1**, shell expansion of `$SOME_SECRET` into `--user` produces an **argv** input to curl. A correct report should not claim that curl itself read that variable unless such a read was observed.
- Send every case to the local endpoint only. Do not mix redirects, proxies, HTTPS or multiple transfers into this first matrix; they are later, independent scenarios.

## Required evidence per run

Each test produces a small private record with:

| Category | Required fields / checks |
| --- | --- |
| Provenance | Commit, UTC timestamp, `curl --version`, kernel, architecture, endpoint, fixture variant |
| RuntimeXRay mode | `ptrace` or `ebpf`; `proc` or `vmread`; scan-memory enabled; budget/limit settings |
| Ground truth | Input mechanism, expected credential representation, local server response, curl/tracer exit statuses |
| Secret observations | `type`, `source`, `secret_type`, `transform` when present, count, fingerprint equality **within this run** |
| Process identity | TGID, process instance, exec generation; ensure observations belong to the correct image |
| Syscall/resource evidence | `read`/`recv`/`sendto`/`sendmsg`/`write` as actually seen, FD identity, file/socket and destination when supported |
| Graph structure | Verify `observed_at` / `observed_in` **endpoints** (`from_seq`, `to_seq`), not just edge counts |
| Memory scanning | Scan reason, attempted pages, budget, observation count; record misses as bounded observations |
| Output safety | No plaintext credential in default JSON, human report, or diagnostic logs; no raw secrets published |

Important: fingerprints use a **per-run HMAC key**. Comparing literal fingerprint strings across independent runs is invalid. Compare the structure and classification of the evidence across runs instead.

For `sendto`, prefer the captured syscall and socket/FD evidence over assuming the application always uses a particular syscall. A different syscall is not itself a failure if the same observable boundary is reliably represented.

## PASS / FAIL / INCONCLUSIVE / SKIP

### PASS

A scenario passes when its **scenario-specific required** observations and process/resource relations are found, its positive correlations use the right per-run fingerprints and transformations, graph endpoints are valid, and outputs remain redacted. It must not manufacture a causality or exfiltration finding for the expected local authentication exchange.

For **A1/C1 regression**, retain the stronger previously established assertions, including memory evidence, where required by the maintained test. If they cease to hold, investigate the changed code, timing, memory coverage and reader configuration; do not weaken the test silently.

### FAIL

Fail on demonstrated incorrect attribution, invalid edge endpoints, a mismatch of a required detected value, unredacted credential exposure by the default reporter, a fabricated source-to-sink causal assertion, an unexpected crash, or an unmet hard assertion under a valid fixture.

### INCONCLUSIVE

Use this for a memory observation absent under a bounded scan **when memory presence is not a mandatory scenario assertion**, or when instrumentation cannot distinguish two plausible explanations. Preserve coverage and timing evidence. A zero-hit scan means only “not detected in the pages inspected at that time,” not “the process never had the secret.”

### SKIP / BLOCKED

Use this for a missing local server, unsupported eBPF privileges, unavailable PTY fixture, missing binaries, or another unmet external prerequisite. A `125` CTest skip is **not** a PASS.

## Execution phases and gates

### Phase I — Re-establish the baseline

1. Verify the loopback registry returns unauthenticated HTTP `401`.
2. Capture fresh host, `curl`, RuntimeXRay and commit versions.
3. Run the existing C1 integration regression with **actual execution**, not a CTest skip:

   ```bash
   ctest --test-dir build \
     -R '^check_c1_memory_scan_coordinator

- [`docker.md`](docker.md): earlier real-world Docker validation, local registry setup, credential-helper work, and original Docker Phases 0–4 runbook.
- [`../../tests/test_c1_memory_scan_coordinator.sh`](../../tests/test_c1_memory_scan_coordinator.sh): maintained C1 integration regression.
- [`../../include/memory_scan_coordinator.hpp`](../../include/memory_scan_coordinator.hpp): scan reasons and default budgets.
- [`../../include/process_image_key.hpp`](../../include/process_image_key.hpp): process image identity.
- [`../../src/commands/trace_command.cpp`](../../src/commands/trace_command.cpp): `TraceMemoryScanSession` and syscall-driven scan requests.
- [`../../src/memory_region_policy.cpp`](../../src/memory_region_policy.cpp): memory-region prioritization.
- [`../../tests/unit/test_memory_scan_coordinator.cpp`](../../tests/unit/test_memory_scan_coordinator.cpp): coordinator unit tests.
- [`../../tests/unit/test_process_image_identity.cpp`](../../tests/unit/test_process_image_identity.cpp): process-image identity unit tests.

This document is intended as both a reproducible validation record and source material for a future technical article on evidence-driven memory inspection and credential correlation in a real Linux application.

 \
     --output-on-failure -V
   ```

4. Repeat A1 using the safe, synthetic invocation already recorded in [`curl.md`](curl.md); initially select `--backend ptrace --memory-reader proc` explicitly.
5. Compare observation sources, fingerprints **within each run**, identity and graph endpoints with the historical expectations. Record differences instead of assuming parity.

**Gate I:** A1 and C1 run successfully on the current build, or any regression is diagnosed before adding new cases.

### Phase II — Add three new source mechanisms

Implement and verify **B1 config file**, **D1 direct Authorization header**, and **E1 URL userinfo**, separately. For each case, begin with a manual trace and a saved assertion specification. Convert it to an automated regression only after its detection contract is clear.

**Gate II:** Each case has independently reproducible local ground truth, source-specific attribution, validated graph endpoints, and redacted default output.

### Phase III — Input boundaries and negative controls

Add **F1 stdin**, **G1 PTY prompt**, and **N0 unauthenticated**. Add **H1 environment-mediated** only if the wrapper/input provenance can be independently controlled. Design **N1 decoy** as a distinct fixture, not a claim inferred from a normal curl run.

**Gate III:** No false transfer is asserted for an unrelated value, and origin attribution survives the extra input boundary.

### Phase IV — Backend and memory-reader parity

Once a case is stable under `ptrace + proc`, repeat selected cases under `ptrace + vmread` and, where supported, `ebpf + proc` / `ebpf + vmread`. Compare **semantic evidence**, not byte-identical reports, time ordering, physical page identity, or elapsed runtime.

Remember Stage D: on the tested kernel `process_vm_readv()` caused COW unsharing in controlled cases, while `/proc/<pid>/mem` preserved sharing. Reader selection is part of provenance, not a reason to demand identical physical-memory side effects.

**Gate IV:** Essential detections and supported graph claims agree across available modes, or differences are documented with reproducible traces and clear limitations.

## Automation and publication policy

- Add one maintained regression per stable scenario, or a table-driven harness that reports individual scenario outcomes; do not create a single opaque “curl works” PASS.
- Preserve separate test IDs in logs and CTest names; detect test skips explicitly.
- Generate synthetic credentials at runtime. Restrict temporary directories and always clean up, including failure paths.
- Keep secret-bearing reports private. Public evidence should contain structured counts, redacted fields, test result summaries, and methodology only.
- Capture curl/server response independently where practical; do not equate tracer success with successful HTTP authentication.
- Retain a minimal sanitized failure artifact plus reproduction metadata when a regression is found; do not commit raw command lines containing disposable passwords just because they are synthetic.
- Publish a dated **results** document only after the campaign runs. This plan is not a results report and does not assert future PASS outcomes.

## Immediate next action

**Run Phase I only.** First verify the controlled local endpoint and rerun `check_c1_memory_scan_coordinator` against the current commit. Then rerun A1. Inspect the current `proc` reader path and the graph evidence before changing implementation or building out the rest of the matrix.

If Phase I is green, start **B1** (config-file credentials), because it introduces a new real input surface without adding PTY complexity or already-encoded header ambiguity.

---

# Related records and implementation

- [`docker.md`](docker.md): earlier real-world Docker validation, local registry setup, credential-helper work, and original Docker Phases 0–4 runbook.
- [`../../tests/test_c1_memory_scan_coordinator.sh`](../../tests/test_c1_memory_scan_coordinator.sh): maintained C1 integration regression.
- [`../../include/memory_scan_coordinator.hpp`](../../include/memory_scan_coordinator.hpp): scan reasons and default budgets.
- [`../../include/process_image_key.hpp`](../../include/process_image_key.hpp): process image identity.
- [`../../src/commands/trace_command.cpp`](../../src/commands/trace_command.cpp): `TraceMemoryScanSession` and syscall-driven scan requests.
- [`../../src/memory_region_policy.cpp`](../../src/memory_region_policy.cpp): memory-region prioritization.
- [`../../tests/unit/test_memory_scan_coordinator.cpp`](../../tests/unit/test_memory_scan_coordinator.cpp): coordinator unit tests.
- [`../../tests/unit/test_process_image_identity.cpp`](../../tests/unit/test_process_image_identity.cpp): process-image identity unit tests.

This document is intended as both a reproducible validation record and source material for a future technical article on evidence-driven memory inspection and credential correlation in a real Linux application.

