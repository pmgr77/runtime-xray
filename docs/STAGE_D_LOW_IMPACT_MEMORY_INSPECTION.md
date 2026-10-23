# Stage D — Low-Impact Memory Inspection

**RuntimeXRay engineering and experimental validation record**
**Updated:** 2026-10-23
**Validation machine:** Ubuntu ARM64, Linux 6.17.0-1018-oracle, ARM Neoverse-N1, 1 vCPU, 4 KiB pages
**Status:** Stage D.1–D.5 implemented and reported GREEN on this host; default backend is now `proc`.

## 1. Executive conclusion

RuntimeXRay needs to inspect a running process without unnecessarily changing the execution state being observed. Its remote-memory reader supports two Linux mechanisms:

| Backend | Mechanism | Selection |
| --- | --- | --- |
| `proc` | `pread()` on `/proc/<pid>/mem` | **Default** |
| `vmread` | `process_vm_readv()` | Explicit opt-in |

On the tested ARM64 Linux kernel, read-only `process_vm_readv()` caused physical unsharing of fork-inherited private pages **before an application write**. Equivalent reads through `/proc/<pid>/mem` preserved shared PFN identity. This was reproducible both in a standalone C fixture and under RuntimeXRay.

The measured tradeoff is real: `proc` is considerably faster for a first read of these shared pages, while `vmread` is faster after those pages have already become unshared. We are not claiming that `proc` is universally faster, side-effect-free, or equivalent on every Linux kernel.

**Decision:** Keep both mechanisms, use `proc` as the normal reader, expose `--memory-reader proc|vmread` for deliberate comparison, and do not silently fall back between mechanisms. This is an observational-impact decision informed by correctness tests, not a claim of a universal throughput win.

The separately maintained [benchmark page](benchmarks/memory-readers.html) contains interactive graphs and downloadable statistical summaries.

## 2. Origin of the investigation

After `fork()`, a parent and child can share the same physical pages for private mappings until one writes. RuntimeXRay may inspect a child during its bounded `InitialInspection`, before application writes occur. Earlier strict `fork_cow_mutation` tests detected unexpected divergence of parent/child page-frame numbers (PFNs) at this pre-write stage.

A standalone reproducer compared the parent and child PFNs using `/proc/<pid>/pagemap`:

| Operation before first application write | PFNs before | PFNs after | Result |
| --- | --- | --- | --- |
| No remote read | Equal | Equal | Expected COW sharing |
| One-byte `process_vm_readv()` read | Equal | Different | Early physical unsharing |
| One-byte `pread(/proc/<pid>/mem)` | Equal | Equal | Sharing preserved |

This isolates the observation from RuntimeXRay's evidence graph. A plausible kernel explanation is the `FOLL_PIN` / `gup_must_unshare()` path on the specific tested kernel; it is a hypothesis about the kernel implementation, not proof that all Linux versions take the same path.

PFN divergence measures page identity, **not** an equivalent measured increase in RSS, PSS or private-dirty bytes.

## 3. Implementation and configuration

The design includes a common reader interface and backend selection:

| Component | Role |
| --- | --- |
| `include/memory_reader.hpp` | `MemoryReader` interface, `MemoryReadBackend` and factory |
| `src/memory_reader.cpp` | `ProcMemMemoryReader` and `ProcessVmMemoryReader` with resource/error handling |
| `src/memory_scanner.cpp` | Bulk scanner reads through the selected interface |
| `include/common_cli.hpp` / `src/common_cli.cpp` | Default and CLI parsing |
| `src/commands/trace_command.cpp` | Trace command and scan-session selection |
| `src/commands/mem_command.cpp` | Standalone memory-scan command |
| `include/itrace_backend.hpp` | Propagation in `TraceConfig` |
| `src/ptrace_backend.cpp` / `src/ebpf_backend.cpp` | Userspace capture readers |
| `src/tachikoma.cpp` | Ptrace tracer memory reads |

The default is `MemoryReadBackend::ProcMem`. The selection flows explicitly through the trace/mem commands and reader-using components. It is not a runtime-global setting or a hidden mutable environment dependency.

~~~sh
# Default (proc)
./build/runtimexray mem <pid>
./build/runtimexray trace --backend ptrace --scan-memory /bin/true

# Opt into process_vm_readv
./build/runtimexray mem --memory-reader vmread <pid>
./build/runtimexray trace --memory-reader vmread --backend ptrace --scan-memory /bin/true
~~~

Both `--memory-reader proc` and `--memory-reader=proc` forms are supported by the common CLI parser. `RXRAY_MEMORY_READ_BACKEND` was an experimental Stage D.1/D.2 setting and is **no longer the selector**. The old documentation describing `vmread` as the default is superseded by this revision.

The reader does **not** automatically switch methods after a read failure. Such a switch would change COW and access semantics without a deliberate user decision. A `/proc/<pid>/mem` descriptor is scoped to its reader/session, not intentionally retained across process-image generations.

The independent memory-reader lifecycle regression (commit `357f722`) exercises reader behavior across VMA and process transitions. Direct production `process_vm_readv()` calls were audited: the actual invocation is in `src/memory_reader.cpp`; syscall-name tables and standalone test benchmarks are intentional exceptions.

See [Stage D.5 configuration](STAGE_D5_UNIFIED_MEMORY_READER_CONFIGURATION.md) for the end-to-end option contract and test matrix.

## 4. Benchmark method and host

The measurements were taken on 2026-10-22 UTC:

- Linux `6.17.0-1018-oracle`, AArch64, ARM Neoverse-N1, **one virtual CPU**.
- 4096-byte pages, root/privileged access to PFN information.
- Two separate C fixtures in `tests/benchmarks/`.
- Read chunks of 4, 64 and 256 KiB.
- Fresh fork per benchmark case; one first (**cold**) pass and five subsequent (**warm**) passes.
- Ten invocations per method/block/layout in the final main series.
- Contiguous run order alternated `proc` / `vmread`; the VMA fixture uses its fixed method order.
- Results below are **medians** in MiB/s. IQR is the interpolated P25–P75 interval from ten observations.
- Timed loops exclude fork, `pagemap`, `smaps`, and open/close. The `proc` reader needs extra file-open/close operations not reflected in these throughput numbers.

**Important:** the two readers finish the cold sweep in different COW states. Warm-pass rates are useful but should not be read as measurements of identical resulting physical memory layouts.

### 4.1 Contiguous 32 MiB private-memory fixture

There are 8192 tracked pages. Every case starts from a fresh shared COW state.

| Method | Block | Cold median | Cold P25–P75 | Warm median | Warm P25–P75 | PFN splits |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `proc` | 4 KiB | 2765.30 | 2720.05–2777.25 | 2694.90 | 2678.57–2702.55 | 0/8192 |
| `vmread` | 4 KiB | 901.25 | 874.45–913.58 | 3007.85 | 2993.88–3033.93 | 8192/8192 |
| `proc` | 64 KiB | 3574.60 | 3452.20–3692.10 | 3598.20 | 3534.10–3665.77 | 0/8192 |
| `vmread` | 64 KiB | 977.65 | 972.22–988.40 | 4667.80 | 4643.10–4680.55 | 8192/8192 |
| `proc` | 256 KiB | 3608.45 | 3597.25–3685.68 | 3643.30 | 3606.57–3704.45 | 0/8192 |
| `vmread` | 256 KiB | 922.25 | 906.08–958.55 | 4707.10 | 4686.68–4756.10 | 8192/8192 |

At 256 KiB, `proc` had approximately **3.91×** the cold throughput, whereas `vmread` had approximately **29% higher** warm throughput. The split count was invariant across all ten repetitions in each configuration.

### 4.2 Fragmented readable mappings — 410 VMA

The fixture models private anonymous RW/RO/RX, shared anonymous, private/shared file-backed mappings, `PROT_NONE` and holes. The maps-aware policy scans **only the readable ranges** and respects VMA boundaries. Readable data: **25.62 MiB**. Tracked shared COW pages: **3296**.

| Method | Block | Cold median | Cold P25–P75 | Warm median | Warm P25–P75 | PFN splits |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `proc` | 4 KiB | 2489.75 | 2465.82–2541.32 | 2634.40 | 2623.57–2658.95 | 0/3296 |
| `vmread` | 4 KiB | 886.75 | 868.50–915.50 | 3018.20 | 3003.17–3036.97 | 3296/3296 |
| `proc` | 64 KiB | 3330.00 | 3216.15–3349.45 | 3538.80 | 3462.65–3594.25 | 0/3296 |
| `vmread` | 64 KiB | 1006.00 | 981.02–1021.52 | 4780.20 | 4672.50–4824.20 | 3296/3296 |
| `proc` | 256 KiB | 3288.95 | 3188.70–3385.82 | 3507.55 | 3484.20–3537.65 | 0/3296 |
| `vmread` | 256 KiB | 991.30 | 973.95–1009.20 | 4748.80 | 4661.68–4877.65 | 3296/3296 |

For this layout, 64- and 256-KiB buffers both require 410 cold read calls because the readable VMAs are generally only 64 KiB.

### 4.3 Fragmented readable mappings — 102 VMA

Readable data: **25.50 MiB**. Tracked shared COW pages: **3264**.

| Method | Block | Cold median | Cold P25–P75 | Warm median | Warm P25–P75 | PFN splits |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `proc` | 4 KiB | 2546.00 | 2531.90–2562.53 | 2635.15 | 2617.40–2659.22 | 0/3264 |
| `vmread` | 4 KiB | 911.30 | 897.05–917.75 | 3000.95 | 2978.50–3043.13 | 3264/3264 |
| `proc` | 64 KiB | 3308.90 | 3285.55–3359.65 | 3496.60 | 3452.22–3523.07 | 0/3264 |
| `vmread` | 64 KiB | 1007.40 | 993.23–1023.55 | 4700.20 | 4634.70–4807.30 | 3264/3264 |
| `proc` | 256 KiB | 3300.95 | 3244.25–3319.68 | 3540.55 | 3524.45–3574.13 | 0/3264 |
| `vmread` | 256 KiB | 977.15 | 947.80–983.95 | 4898.90 | 4756.73–4931.27 | 3264/3264 |

At 102 VMAs, the 256-KiB size reduces read calls relative to 64-KiB, but the observed `proc` throughput gain is small. Increasing RuntimeXRay's actual scan size remains **future work**: the scanner currently processes 4096-byte chunks, and boundary-spanning secret recognition must be validated before changing it.

## 5. Access semantics: explicit probe across inaccessible ranges

The VMA benchmark also has a deliberate `--probe` mode. Unlike the maps-aware throughput tests, it attempts reads across mapped readable regions, `PROT_NONE` and unmapped holes. The two APIs therefore have **different workloads**. The measurements below are from one probe run per layout, using 4-KiB blocks.

| Layout | Method | Data read | Failed read attempts | Interpretation |
| --- | --- | ---: | ---: | --- |
| 410 VMA | `vmread` | 25.62 MiB | 1632 | `PROT_NONE` and holes rejected |
| 410 VMA | `proc` | 28.81 MiB | 816 | `PROT_NONE` read; holes rejected |
| 102 VMA | `vmread` | 25.50 MiB | 1664 | `PROT_NONE` and holes rejected |
| 102 VMA | `proc` | 28.75 MiB | 832 | `PROT_NONE` read; holes rejected |

The extra approximately 3.19/3.25 MiB read through `proc` corresponds to the probe's `PROT_NONE` pages. This does **not** imply a privilege bypass: inspecting the process still requires appropriate process-access permissions. It means API selection and VMA selection policy are different questions. RuntimeXRay must not accidentally broaden its scan to intentionally protected mappings just because one reader can access them.

Do **not** compare probe MiB/s as equivalent workloads. Some larger-block probe rows also report short reads at protection boundaries; these are access-semantics diagnostics, not throughput evidence.

## 6. RuntimeXRay correctness regressions

### 6.1 Strict fork/COW differential

`tests/test_memory_reader_cow_differential.sh` compares:

1. The untraced fixture's shared-before-write physical PFNs.
2. `vmread` as the **expected negative control** on the validation kernel: early unsharing must fail the fixture specifically for a pre-write PFN mismatch.
3. `proc` as the positive control: both parent-first and child-first write orders preserve sharing until the application writes.
4. Bounded child `InitialInspection` evidence and the expected three-node process graph.

The earlier strict run recorded shared PFNs before writing and divergent PFNs only after the first application write, with both parent-first and child-first content checks passing. The fixture's captured output, not just the tracer's exit code, is checked.

The script uses exit code **125** for an unsupported privilege/PFN environment; CTest should register `SKIP_RETURN_CODE 125`. The negative control is specifically host dependent. Lack of a COW side effect on another Linux kernel is not automatically a RuntimeXRay regression.

### 6.2 Secret evidence parity

`tests/test_memory_reader_evidence_parity.sh` verifies semantic rather than byte-for-byte JSON parity for:

- `fork_cow_secret`: inherited child secret, separate process instances, child memory observation, no fabricated secret `DataFlow`.
- `exec_memory_transition`: failed exec remains generation 0, successful exec becomes generation 1 in the same process instance, old/new secrets stay attributed to their correct images.
- Bounded `InitialInspection` in the correct generation.

Each RuntimeXRay invocation creates a new random HMAC fingerprint key. Fingerprint bytes are **not** comparable across separate runs; normalized semantic claims and within-report fingerprints are.

### 6.3 Reader lifecycle and CLI

- `tests/test_memory_reader_lifecycle.cpp` covers reader lifecycle across VMA/process transitions; committed locally as `357f722`.
- `tests/test_memory_reader_cli.sh` checks default/explicit reader selection, errors for missing/invalid values, and actual syscall selection where `strace` is available.
- Both standalone `mem` and `trace` commands use the same explicit selection model.
- Earlier Stage D differential/parity scripts were migrated from `RXRAY_MEMORY_READ_BACKEND` to `--memory-reader`.

The user reported the dedicated tests and the relevant full CTest runs **GREEN**. This is a validation record for the tested source tree and host, not a claim that every kernel/environment has been tested.

## 7. Reproduction

From the repository root:

~~~sh
cmake -S . -B build
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure -j"$(nproc)"
~~~

Run the independent microbenchmarks:

~~~sh
cc -std=c11 -O2 -Wall -Wextra -Werror \
  tests/benchmarks/benchmark_remote_memory_cow.c \
  -o /tmp/benchmark_remote_memory_cow

sudo /tmp/benchmark_remote_memory_cow --mb 32 --warm 5 --method both

cc -std=c11 -O2 -Wall -Wextra -Werror \
  tests/benchmarks/benchmark_remote_memory_vma.c \
  -o /tmp/benchmark_remote_memory_vma

sudo /tmp/benchmark_remote_memory_vma --mb 32 --warm 5 --segment-pages 16
sudo /tmp/benchmark_remote_memory_vma --mb 32 --warm 5 --segment-pages 64
sudo /tmp/benchmark_remote_memory_vma --mb 32 --warm 5 --segment-pages 16 --probe
~~~

The repeated benchmark logs were saved by the operator under `build/benchmarks/stage-d/`:

- `system.txt` — uname, CPU and page size.
- `cow-baseline.txt` — initial contiguous measurement.
- `cow-repeats.txt` — ten contiguous repeats (60 data rows).
- `vma-maps-repeats.txt` — ten repeats at each VMA density (120 data rows).
- `vma-probe.txt` — explicit access-semantics probe.

The HTML page embeds aggregate results and exports a summary CSV. **Before public publication**, consider checking in sanitized raw logs or a machine-readable raw dataset to make the calculation of quantiles independently verifiable. The raw logs have not been claimed to be committed.

## 8. Historical Stage D.1/D.2 exploratory measurements

Before the ten-repeat campaign, single-invocation benchmark runs on the same host motivated the implementation. They were never confidence intervals.

| Layout | Reader | Block | Earlier cold MiB/s | Earlier warm MiB/s | PFN splits |
| --- | --- | ---: | ---: | ---: | ---: |
| Contiguous 32 MiB | `vmread` | 4 KiB | 894.9 | 3596.6 | 8192 |
| Contiguous 32 MiB | `proc` | 4 KiB | 2710.6 | 2839.9 | 0 |
| Contiguous 32 MiB | `vmread` | 64 KiB | 986.2 | 5348.4 | 8192 |
| Contiguous 32 MiB | `proc` | 64 KiB | 3789.6 | 3942.0 | 0 |
| Contiguous 32 MiB | `vmread` | 256 KiB | 917.3 | 6324.6 | 8192 |
| Contiguous 32 MiB | `proc` | 256 KiB | 3897.1 | 3942.2 | 0 |

Earlier fragmented runs likewise showed 3296/3296 or 3264/3264 split by `vmread` and zero split by `proc`. The present 10-repeat series supersedes earlier single-sample rates for reporting. Historical figures are retained so the decision trail is not lost.

## 9. Limitations, risks and follow-up

1. **Kernel dependence.** `FOLL_PIN` behavior, procfs access semantics, huge pages, process permissions, and special mappings vary. Recheck on x86-64 and other kernels.
2. **Timing boundaries.** End-to-end scanner performance includes open/close, VMA enumeration, selection, secret extraction, scheduling and report generation; the microbenchmark does not.
3. **Physical accounting.** PFN identity is not RSS/PSS. Use `smaps` and complementary measurements before claiming memory-capacity savings.
4. **Protected regions.** `proc` may read `PROT_NONE` under authorized inspection; use explicit VMA policy rather than backend-dependent accidental expansion.
5. **Races and lifecycle.** A target can exit, exec, change permissions or remap a VMA while scanning. Preserve correct short-read and error behavior.
6. **Application representativeness.** Synthetic contiguous and mixed-VMA mappings do not establish results for all real applications. Add controlled real-process tests.
7. **Buffer size.** Preserve existing 4-KiB scanner chunks until detection parity is demonstrated at larger read granularity.
8. **Non-COW side effects.** Neither backend has been proven completely non-invasive for every mapping and device type; use precise claims.
9. **Raw data provenance.** Publish raw trial outputs with environment metadata when turning the HTML dashboard into a public research artifact.

## 10. Acceptance record

| Criterion | Status |
| --- | --- |
| Memory reader abstraction with two backends | Implemented |
| No silent fallback | Implemented |
| Default switched to `proc` | Implemented |
| Unified `--memory-reader proc|vmread` for trace and mem | Implemented |
| Experimental env selector removed | Implemented |
| Reader-using tracer/scanner paths audited | Reported complete |
| Standalone kernel-level COW differential | PASS on validation host |
| Ten-repeat contiguous and VMA benchmarks | Complete (180 rows) |
| Explicit `PROT_NONE`/hole probe | Complete |
| Strict fork COW positive/negative controls | PASS on validation host |
| Fork/exec evidence parity | PASS |
| Lifecycle and CLI selection tests | Reported GREEN |
| Full regression suite | Reported GREEN |
| Public HTML visualization | Prepared at `docs/benchmarks/memory-readers.html` |

**Conclusion:** The measured evidence supports `/proc/<pid>/mem` as the default lower-perturbation reader for the tested RuntimeXRay workflow, while preserving explicit access to `process_vm_readv()` for comparison, compatibility and future kernels. The remaining work is wider-host validation, raw data publication and end-to-end workload benchmarking.
