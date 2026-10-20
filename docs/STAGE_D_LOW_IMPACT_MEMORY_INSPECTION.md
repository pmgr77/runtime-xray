# Stage D — Low-Impact Memory Inspection

**RuntimeXRay engineering validation record**  
**Date:** 2026-10-20 
**Validation host:** Linux `6.17.0-1018-oracle`, Ubuntu on ARM64 
**Status:** Implementation and regression validation GREEN on the validation host; default backend has **not** been changed.

## 1. Summary and decision

RuntimeXRay now offers two explicitly selectable backends for its **bulk process-memory scanner**:

- `vmread`: `process_vm_readv(2)`, the original/default mechanism;
- `proc`: `pread(2)` on `/proc/<pid>/mem`, opened once per scan and closed using RAII.

The decision is to **retain both backends**, validate them independently and prefer `proc` as a *candidate* for low-impact scanning. On the tested kernel, a read-only `process_vm_readv()` caused private fork/COW physical pages to become unshared **before the traced application wrote to them**. Equivalent `/proc/<pid>/mem` reads preserved shared physical-page identity in the tested scenarios. This matters because an observer should avoid perturbing the process state it is measuring.

The original default remains `vmread` during Stage D. The experiments do **not** establish that `/proc/<pid>/mem` is side-effect-free on every kernel, mapping type, or workload. Nor do they establish that all RuntimeXRay reads, including syscall-buffer capture elsewhere in the tracer, are free of COW side effects.

## 2. Why we investigated

A forked child may share the same physical `MAP_PRIVATE` page with its parent until the first application write. RuntimeXRay performs `InitialInspection` for each process image, including forked children. The original bulk scanner read target pages with `process_vm_readv()`; during strict COW regression, the fixture observed unexpected PFN divergence **prior to the first application write**.

We isolated the effect using a standalone parent/child program with a pre-populated private page and `/proc/<pid>/pagemap` PFN comparison. The outcomes on the validation host were:

| Remote-read operation | PFNs before read | PFNs after read | Observation |
| --- | --- | --- | --- |
| No remote read | Equal | Equal | Shared COW page retained |
| One-byte `process_vm_readv()` | Equal | Different | Remote read alone caused physical unsharing |
| One-byte `/proc/<pid>/mem` `pread()` | Equal | Equal | Remote read retained physical sharing |

The test was independent of RuntimeXRay. The result supports a kernel-level cause, not a RuntimeXRay lineage-algorithm defect. A plausible kernel mechanism is the `FOLL_PIN` / `gup_must_unshare()` path used by `process_vm_readv()` on this kernel; do not generalize the exact mechanism to every Linux version without checking its source and configuration.

## 3. Implementation

| File | Responsibility |
| --- | --- |
| `include/memory_reader.hpp` | `MemoryReader` interface, `MemoryReadBackend`, `open_memory_reader()` factory |
| `src/memory_reader.cpp` | `ProcessVmMemoryReader`, `ProcMemMemoryReader`, error checking and descriptor RAII |
| `src/memory_scanner.cpp` | Calls the selected reader instead of directly invoking `process_vm_readv()` |
| `CMakeLists.txt` | Compiles `src/memory_reader.cpp` and registers Stage D regression tests |
| `tests/test_memory_reader_cow_differential.sh` | Controlled negative/positive COW comparison of the two backends |
| `tests/test_memory_reader_evidence_parity.sh` | Semantic evidence parity across fork and exec scenarios |

Selection is currently via an **experimental environment variable**:

```sh
# Legacy default: process_vm_readv()
./build/runtimexray trace ...

# Explicit old backend
RXRAY_MEMORY_READ_BACKEND=vmread ./build/runtimexray trace ...

# Experimental alternative
RXRAY_MEMORY_READ_BACKEND=proc ./build/runtimexray trace ...
```

This is not yet a documented end-user CLI setting. Reader selection does not silently fall back to the other backend. A `ProcMem` descriptor is opened for one scan and is not retained across `execve()` generations. Existing VMA prioritization, 4096-byte scanner chunks, secret extraction and scan-budget accounting were intended to remain unchanged by the backend substitution.

**Scope boundary:** the new abstraction covers the **bulk memory scanner**. It does not automatically change every other tracer facility that may read a tracee's memory.

## 4. Contiguous 32 MiB benchmark

**Environment:** validation host, 32 MiB resident private anonymous memory, 8192 4-KiB pages; first (“cold”) pass plus five repeated (“warm”) passes, separate fork for each configuration. The benchmark timed the read sweeps, excluding process creation and auxiliary pagemap/smaps measurements. One timed run per configuration; these are measurements, not confidence intervals.

Source: `tests/benchmarks/benchmark_remote_memory_cow.c` (if copied into the repository; otherwise retain the original experimental source).

Command:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror \
  tests/benchmarks/benchmark_remote_memory_cow.c \
  -o /tmp/benchmark_remote_memory_cow
sudo /tmp/benchmark_remote_memory_cow --mb 32 --warm 5
```

| Reader | Block | Cold, ms | Cold, MiB/s | Warm, MiB/s | Shared PFNs before → after | PFN splits |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `vmread` | 4 KiB | 35.76 | 894.9 | 3596.6 | 8192 → 0 | 8192 |
| `proc` | 4 KiB | 11.81 | 2710.6 | 2839.9 | 8192 → 8192 | 0 |
| `vmread` | 64 KiB | 32.45 | 986.2 | 5348.4 | 8192 → 0 | 8192 |
| `proc` | 64 KiB | 8.44 | 3789.6 | 3942.0 | 8192 → 8192 | 0 |
| `vmread` | 256 KiB | 34.88 | 917.3 | 6324.6 | 8192 → 0 | 8192 |
| `proc` | 256 KiB | 8.21 | 3897.1 | 3942.2 | 8192 → 8192 | 0 |

The `proc` path was substantially faster on the first pass; `vmread` was faster on repeated passes. Crucially, after the first pass the physical-page sharing state was **different**, so warm-pass timings are informative but not comparisons of precisely identical memory state. The 8192 diverged pages represent 32 MiB of private physical-page identities, **not** a direct measurement of a 32-MiB increment in RSS or `Private_Dirty`.

## 5. Fragmented VMA benchmark

A second synthetic tracee models a fragmented address space containing private anonymous RW/RO/RX, shared anonymous RW, private file-backed RO and dirty, shared file-backed RW/RO, `PROT_NONE`, and unmapped holes. The `maps` policy visits readable mappings and respects VMA boundaries. The `probe` policy deliberately attempts to cross protected/unmapped regions and is primarily for access-semantics diagnostics.

Source: `tests/benchmarks/benchmark_remote_memory_vma.c` (if copied into the repository).

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror \
  tests/benchmarks/benchmark_remote_memory_vma.c \
  -o /tmp/benchmark_remote_memory_vma

sudo /tmp/benchmark_remote_memory_vma \
  --mb 32 --warm 5 --segment-pages 16 --probe

sudo /tmp/benchmark_remote_memory_vma \
  --mb 32 --warm 5 --segment-pages 64 --probe
```

### `maps` policy: directly comparable workloads

| Readable VMAs | Data | Reader | Block | Cold, ms | Cold, MiB/s | Warm, MiB/s | Read calls, cold | Tracked PFN splits |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 410 | 25.62 MiB | `vmread` | 4 KiB | 27.02 | 948.5 | 3155.1 | 6560 | 3296 / 3296 |
| 410 | 25.62 MiB | `proc` | 4 KiB | 9.87 | 2597.2 | 2815.0 | 6560 | 0 / 3296 |
| 410 | 25.62 MiB | `vmread` | 64 KiB | 24.13 | 1062.1 | 5002.3 | 410 | 3296 / 3296 |
| 410 | 25.62 MiB | `proc` | 64 KiB | 7.25 | 3532.6 | 3677.9 | 410 | 0 / 3296 |
| 410 | 25.62 MiB | `vmread` | 256 KiB | 24.78 | 1034.1 | 5138.4 | 410 | 3296 / 3296 |
| 410 | 25.62 MiB | `proc` | 256 KiB | 7.17 | 3575.3 | 3772.7 | 410 | 0 / 3296 |
| 102 | 25.50 MiB | `vmread` | 64 KiB | 25.53 | 998.6 | 4972.9 | 408 | 3264 / 3264 |
| 102 | 25.50 MiB | `proc` | 64 KiB | 7.90 | 3227.7 | 3841.4 | 408 | 0 / 3264 |
| 102 | 25.50 MiB | `vmread` | 256 KiB | 25.13 | 1014.8 | 5391.4 | 102 | 3264 / 3264 |
| 102 | 25.50 MiB | `proc` | 256 KiB | 7.42 | 3434.7 | 3923.0 | 102 | 0 / 3264 |

At 410 VMAs, a 256-KiB buffer still produces 410 reads because VMAs are generally only 64 KiB. Increasing the buffer past the typical accessible VMA size cannot reduce the number of reads. At 102 VMAs, 256-KiB blocks reduce cold read-call count from 408 to 102, but offer only a modest additional gain for `proc`. A 64-KiB read block is an interesting **future optimization candidate**, *not* yet an approved scanner change: secret extraction currently operates on 4096-byte chunks, and changing boundaries may alter detections.

### `probe` policy: intentionally different workloads

For the 410-VMA, 4-KiB case:

| Reader | Bytes read | Cold read errors | Interpretation |
| --- | ---: | ---: | --- |
| `vmread` | 25.62 MiB | 1632 | Unmapped holes and `PROT_NONE` unreadable in this experiment |
| `proc` | 28.81 MiB | 816 | `PROT_NONE` readable through this API on this host; holes unreadable |

The data volume is **not equal** under `probe`; therefore a throughput comparison of these rows is not a fair same-workload performance comparison. Reading otherwise protected mappings is a separate **policy and security** choice, not something to enable accidentally as a consequence of changing the API.

## 6. Strict COW regression under RuntimeXRay

The `fork_cow_mutation` fixture executes independent **parent-first** and **child-first** write orders. Each pair reads its original private page before either party writes, confirms shared PFNs, performs the first write, then verifies distinct PFNs and correct private contents. PFNs come from `/proc/<pid>/pagemap` and must be genuinely available; masking them is not acceptable proof of COW preservation.

**Manual strict `proc` run:**

```sh
D=$(sudo mktemp -d /tmp/rxr-procmem-XXXXXX)
sudo env -u RXRAY_SKIP_PFN_CHECK RXRAY_MEMORY_READ_BACKEND=proc \
  ./build/runtimexray trace \
    --backend ptrace --follow-forks --scan-memory \
    --json "$D/report.json" --report /dev/null \
    /tmp/fork_cow_mutation
```

Observed log on the validation host:

```text
PFN_CHECK stage=before_write parent_pid=1385852 child_pid=1385853 ... parent_pfn=0x122430 child_pfn=0x122430 equal=1
PFN_CHECK stage=after_first_write parent_pid=1385852 child_pid=1385853 ... parent_pfn=0x1644ae child_pfn=0x122430 equal=0
PFN_CHECK stage=before_write parent_pid=1385852 child_pid=1385854 ... parent_pfn=0x151f95 child_pfn=0x151f95 equal=1
PFN_CHECK stage=after_first_write parent_pid=1385852 child_pid=1385854 ... parent_pfn=0x151f95 child_pfn=0x169e9d equal=0
PASS: parent-first COW preserves child's original, then isolates both edits
PASS: child-first COW preserves parent's original, then isolates both edits
PASS: physical PFN shared after reads; PFNs diverged after first COW write
```

The JSON report contained **three `process` nodes** (one parent, two children). RuntimeXRay logs showed separate bounded `InitialInspection` scans for both children. This run omitted `RXRAY_SKIP_PFN_CHECK`; the physical PFN assertions genuinely ran.

### Automated differential control

`tests/test_memory_reader_cow_differential.sh`:

1. Runs the untraced fixture as a physical-PFN baseline.
2. Runs RuntimeXRay with `RXRAY_MEMORY_READ_BACKEND=vmread`. **Expected negative control:** the fixture fails specifically with `physical PFN relationship unexpected (before first write)`. An unrelated failure does not pass.
3. Runs with `RXRAY_MEMORY_READ_BACKEND=proc`. **Expected positive control:** both write orders pass strict PFN assertions.
4. Checks the process graph and evidence that children received bounded `InitialInspection` scans. It inspects the **tracee's captured fixture output**, not merely RuntimeXRay's exit status.

Verified output:

```text
PASS: baseline COW PFN behavior verified without RuntimeXRay
PASS: vmread caused early COW PFN unsharing (expected negative control)
PASS: proc preserved shared PFNs until application write, in both orders
PASS: both backends performed bounded child InitialInspection scans
PASS: Stage D differential COW regression
```

The test uses **exit code 125 as SKIP** when essential environmental requirements (e.g. readable PFNs or usable sudo) are unavailable. In CTest it must be registered with `SKIP_RETURN_CODE 125`. The negative control is **kernel-specific**: on a kernel without `vmread`-induced COW unsharing, the test should be adapted or classified as not applicable, not misinterpreted as a product regression.

## 7. Evidence parity regression

`tests/test_memory_reader_evidence_parity.sh` runs the `fork_cow_secret` and `exec_memory_transition` fixtures separately under both backends (four traced runs total). It compares **semantic invariants**, not whole JSON files:

- Inherited password in the child after parent erase, distinct parent/child process instances, and child `observed_in` memory evidence.
- No invented secret `DataFlow` in the memory-only fork case.
- A failed `execve` remains in generation 0; successful `execve` advances the image to generation 1 in the same process instance.
- Each generation independently has environment and memory evidence for its password, linked by fingerprint **within that report**; old password is not spuriously attributed to the new image.
- `InitialInspection` is bounded and attached to the expected process generation.

**Important:** the `SecretFingerprinter` creates a new random HMAC key per RuntimeXRay run. Fingerprint strings are **not** comparable across independently executed trace sessions. The test compares matching fingerprints within a report and a normalized set of semantic claims between reports. Duplicate environment observations are allowed if they agree on one **distinct** password fingerprint; an exact count of one observation would be an invalid assertion.

Verified output:

```text
PASS: fork evidence parity (child password, observed_in, instance separation)
PASS: exec evidence parity (two generations, old/new secret isolation)
PASS: both backends use bounded InitialInspection
PASS: no invented secret DataFlow in either scenario
PASS: Stage D.2 memory reader evidence parity
```

The original overly restrictive environment assertion was corrected (one unique fingerprint instead of one observation); the revised test was reported GREEN.

## 8. Reproduction and regression commands

From the repository root:

```sh
cmake -S . -B build
cmake --build build -j"$(nproc)"

# Explicitly validate Stage D tests
ctest --test-dir build --output-on-failure \
  -R '^check_memory_reader_(cow_differential|evidence_parity)$'

# Full default regression suite
ctest --test-dir build --output-on-failure -j"$(nproc)"

# Full suite with experimental bulk-scanner backend
RXRAY_MEMORY_READ_BACKEND=proc \
  ctest --test-dir build --output-on-failure -j"$(nproc)"
```

The user reported **GREEN** for both the default and `proc` full test runs, followed by **GREEN** after registering the Stage D evidence-parity test. The exact final number of registered tests was not recorded here; do not infer a count. Some older scripts may invoke `sudo` without preserving inherited environment variables; dedicated Stage D tests explicitly set the reader backend across `sudo` and are the authoritative backend-specific controls.

Direct invocation of the two Stage D scripts:

```sh
./tests/test_memory_reader_cow_differential.sh ./build/runtimexray
./tests/test_memory_reader_evidence_parity.sh ./build/runtimexray
```

### Required sources and prerequisites

- Built `./build/runtimexray` (ptrace backend supported).
- POSIX shell, C compiler and Python 3; passwordless `sudo` or root for privileged scripts.
- The test fixtures in `tests/dynamic_analysis/`: `fork_cow_mutation.c`, `fork_cow_secret.c`, `exec_memory_transition.c`.
- Readable physical PFNs through `/proc/<pid>/pagemap` for the strict differential COW test.
- CTest test names and `SKIP_RETURN_CODE 125` as described above.
- Benchmark C sources must be checked in to `tests/benchmarks/` if reproducibility from a fresh clone is desired.

## 9. Limitations and follow-up

1. **Host-specific observations.** COW/unshare and `FOLL_PIN` behavior, ptrace permission checks, procfs semantics, huge pages, and special mappings can differ by kernel and configuration. Do not globally promise non-invasive reads.
2. **Benchmark representativeness.** Test mappings are synthetic; run against controlled real applications too. Repeat runs, randomize order, assess noise and include whole-trace overhead before using these numbers for performance claims.
3. **Physical memory accounting.** PFN divergence alone does not establish RSS/PSS deltas. For memory-cost claims, measure per-mapping `Private_Clean`, `Private_Dirty`, RSS and PSS before/after alongside pagemap and (where appropriate) system-wide consumption.
4. **Beyond bulk scanning.** Audit any tracer paths that still call `process_vm_readv()` for syscall arguments or other captures; a bulk-scanner backend switch does not eliminate potential side effects elsewhere.
5. **Access-policy difference.** `/proc/<pid>/mem` may access `PROT_NONE` on this kernel; preserve deliberate VMA filtering until policy and security implications are reviewed.
6. **Correctness under races.** VMAs can change while being scanned; short reads, holes, target exit, permission changes and `execve()` transitions remain real cases. Continue tests for each.
7. **Buffer size.** Maintain 4096-byte scanner chunks until detection behavior (especially boundary-crossing secrets) is validated with larger read sizes.
8. **Default selection.** A change from `vmread` to `proc` as the product default should be a **separate, explicit change** backed by tests and documentation; Stage D alone does not change the default.

## 10. Stage D acceptance record

| Acceptance criterion | Result |
| --- | --- |
| Explicit backend abstraction, no silent fallback | Implemented |
| Existing behavior retained by default | Implemented (`vmread`) |
| Standalone kernel-level COW differential reproducer | PASS on validation host |
| Contiguous and fragmented-VMA benchmarks | Completed; results above |
| Strict parent-first and child-first PFN check with `proc` | PASS |
| `vmread` negative COW control | PASS (expected early PFN split) |
| `proc` positive COW control | PASS (sharing preserved to first write) |
| Fork and exec semantic evidence parity | PASS |
| Stage D tests registered in CTest | Reported complete |
| Full CTest regressions | Reported GREEN |
| Switch production default to `proc` | **Not yet performed** |

**Conclusion:** On the measured Linux host, `/proc/<pid>/mem` is a compelling lower-impact backend for bounded RuntimeXRay memory inspection. Both mechanisms remain available so behavior can be measured and validated rather than assumed. Stage D captures the implementation, experimental evidence and reproducible acceptance tests; changing the production default is the next independent decision.

