# Stage D — Memory-Reader Benchmark Data Provenance

- **Project:** RuntimeXRay
- **Experiment date:** 2026-10-22 (UTC)
- **Documentation update:** 2026-10-23
- **Scope:** Linux remote-process memory reads, fork/COW effects, and VMA access semantics

## 1. Purpose and evidence boundary

This document identifies the source records behind the published [Memory Reader Benchmarks](memory-readers.html) dashboard and the [Stage D engineering report](../STAGE_D_LOW_IMPACT_MEMORY_INSPECTION.md).

The dashboard contains *aggregate statistics*. They are not substitutes for the individual measured trials. The authoritative raw records were generated on the validation machine under `build/benchmarks/stage-d/`, outside the Git-tracked source tree.

For public reproducibility, copy the actual records **without inventing, interpolating, or replacing individual trials** into [`data/stage-d-2026-10-22/`](data/stage-d-2026-10-22/). That directory contains its own [dataset README](data/stage-d-2026-10-22/README.md) and verification procedure.

**Completeness rule:** The dataset is publicly reproducible from archived observations only when its five actual source logs and a validated SHA-256 manifest are present alongside the dataset README. Publication of these instructions alone does not meet that criterion.

## 2. Measurement environment

| Field | Value |
| --- | --- |
| Kernel | `6.17.0-1018-oracle` |
| Operating system | Ubuntu, AArch64 / ARM64 |
| CPU | ARM Neoverse-N1, one virtual CPU |
| CPU topology | One online CPU, one thread per core |
| Memory page size | 4096 bytes |
| Contiguous fixture | 32 MiB, 8192 tracked private COW pages |
| VMA fixture, 16-page segments | 410 readable VMAs; 25.62 MiB readable; 3296 tracked COW pages |
| VMA fixture, 64-page segments | 102 readable VMAs; 25.50 MiB readable; 3264 tracked COW pages |
| Read granularity | 4, 64, and 256 KiB |
| Readers | `proc` = `pread()` on `/proc/<pid>/mem`; `vmread` = `process_vm_readv()` |
| Warm passes | Five per case after the first (cold) pass |

`system.txt` is the original operator-captured output of `date -Is`, `uname -a`, `lscpu`, and `getconf PAGESIZE`. Preserve it in the published dataset after reviewing host-specific details.

## 3. Primary trial inventory

| Original source file | Meaning | Expected primary data rows |
| --- | --- | ---: |
| `cow-repeats.txt` | Ten contiguous runs × two readers × three block sizes | **60** |
| `vma-maps-repeats.txt` | Ten runs × two VMA layouts × two readers × three block sizes | **120** |
| `cow-baseline.txt` | First contiguous baseline (supporting observation, not an eleventh replicate) | Not part of the 180-row primary series |
| `vma-probe.txt` | Maps-aware and deliberate `PROT_NONE`/hole probing for 16- and 64-page segments | Not part of the 180-row primary series |
| `system.txt` | Host/kernel/page-size information | Metadata |

Thus, **180 primary measurement rows** support the 36 aggregate values in the dashboard (three layouts × two read phases × two readers × three block sizes). Each row contains measurements of both cold and warm passes; cold and warm are **not** separate independent trials.

Do not append `cow-baseline.txt` or `vma-probe.txt` rows to the primary replicate series when recalculating its quantiles.

## 4. What was timed

- Each case used a fresh fork so its cold pass began with its own copy-on-write sharing state.
- The first read is the *cold* observation; five further read passes constitute the *warm* measurement.
- The reported rates are MiB/s of successfully read bytes in the timed read loops.
- Timing excludes fork, pagemap/PFN inspection, `smaps` and `/proc/<pid>/mem` open/close costs. Consequently, the rates are **not** application end-to-end throughput or total tracer overhead.
- The ten-run summaries report medians and interpolated P25–P75 intervals. The raw rows are required for independent verification of those aggregates; preserve the percentile convention when writing a recomputation script.
- The readers do not produce the same memory state after a cold pass: on this kernel, `vmread` unshared tracked pages, while `proc` preserved sharing. Warm-pass comparisons must be interpreted in that context.
- VMA maps-aware tests deliberately access readable ranges only. The `--probe` experiment crosses `PROT_NONE` mappings and unmapped holes, so successful byte counts differ by API; **do not interpret probe throughput as equal-workload throughput**.

## 5. Principal observations on the tested kernel

These are observations, not portable Linux API guarantees.

| Layout | Tracked COW pages | `proc` split | `vmread` split |
| --- | ---: | ---: | ---: |
| Contiguous 32 MiB | 8192 | 0 | 8192 |
| 410 VMA | 3296 | 0 | 3296 |
| 102 VMA | 3264 | 0 | 3264 |

At a 256-KiB block size in the contiguous fixture, the reported median cold throughput was 3608.45 MiB/s for `proc` versus 922.25 MiB/s for `vmread`. Median warm throughput was 3643.30 versus 4707.10 MiB/s, respectively. All other aggregate values and their P25–P75 intervals are in the dashboard and Stage D report.

The source experiment does **not** establish that one backend is universally faster, that `/proc/<pid>/mem` is side-effect-free for every mapping, or that the same COW behavior occurs on every kernel. PFN identity differences are not interchangeable with RSS/PSS or private-dirty memory accounting.

## 6. Integrity and publication rules

1. Keep the locally collected originals under `build/benchmarks/stage-d/` unchanged. Publish copies in the dataset directory.
2. Review the copies before publishing: `system.txt` contains a hostname, and raw benchmark output may contain process IDs and local paths. The benchmarks do not require application credentials.
3. If any field must be redacted, retain a private unchanged original, document the redaction in the dataset README, and hash the **actual published** bytes. Do not silently alter timing, byte counts, PFN counts, errors, or checksums.
4. Compute `SHA256SUMS` for the five published `.txt` files once they are present. Do not create or commit an empty or guessed manifest.
5. Verify 60 and 120 data records in the respective primary logs, check that every reported case has ten trials, and compare recomputed aggregates with the dashboard before marking the dataset complete.
6. Keep the unmodified source/fixture code in `tests/benchmarks/`; experiments on additional CPUs or kernels belong in separate dated datasets, not in this run's files.

## 7. Relationship to RuntimeXRay

These microbenchmarks compare low-level read mechanisms. RuntimeXRay's currently selected default is `proc`; users can opt into `vmread` with `--memory-reader proc|vmread` on `trace` and `mem`. A change of reader is not a substitute for end-to-end evidence parity, scanning-policy validation, or application overhead measurement.

For implementation rationale and test acceptance criteria, see [Stage D](../STAGE_D_LOW_IMPACT_MEMORY_INSPECTION.md) and [Stage D.5](../STAGE_D5_UNIFIED_MEMORY_READER_CONFIGURATION.md).
