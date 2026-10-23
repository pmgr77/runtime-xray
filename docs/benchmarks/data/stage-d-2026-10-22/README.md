# RuntimeXRay Stage D — Raw Dataset (2026-10-22 UTC)

This directory is the intended **Git-tracked copy** of the original Stage D memory-reader benchmark observations from the Ubuntu ARM64 validation host. The report is [DATA_PROVENANCE.md](../../DATA_PROVENANCE.md), and the interactive visualization is [memory-readers.html](../../memory-readers.html).

## Dataset contents

After importing from the validation host, this directory should contain:

| File | Role |
| --- | --- |
| `README.md` | This dataset card and import/verification procedure |
| `system.txt` | Kernel, CPU, architecture, page size, collection timestamp |
| `cow-baseline.txt` | Initial six-case contiguous baseline |
| `cow-repeats.txt` | **60** contiguous measurement rows: ten repeats × two readers × three blocks |
| `vma-maps-repeats.txt` | **120** maps-aware VMA measurement rows: ten repeats × two layouts × two readers × three blocks |
| `vma-probe.txt` | Explicit `PROT_NONE`/unmapped-hole probe output at two segment sizes |
| `SHA256SUMS` | Checksums of the five **published** source logs; generate after importing |

**Completeness rule:** Do not describe the raw dataset as published unless all five `.txt` logs have been imported, reviewed, and verified against `SHA256SUMS`.

## Import the actual records

From the RuntimeXRay repository root **on the original validation machine**:

```sh
mkdir -p docs/benchmarks/data/stage-d-2026-10-22

cp -- build/benchmarks/stage-d/system.txt \
  build/benchmarks/stage-d/cow-baseline.txt \
  build/benchmarks/stage-d/cow-repeats.txt \
  build/benchmarks/stage-d/vma-maps-repeats.txt \
  build/benchmarks/stage-d/vma-probe.txt \
  docs/benchmarks/data/stage-d-2026-10-22/
```

`cp` preserves the originals in `build/`. If any listed file is missing or empty, stop; locate the actual collection output instead of substituting a newly generated or reconstructed file.

Review the copied files before making them public. `system.txt` exposes the VM hostname and exact kernel. The benchmarking data is synthetic, but published text should not inadvertently contain unrelated machine secrets. If redaction is necessary, record exactly what was removed and preserve the private original.

## Verify the primary series

```sh
awk '$1 == "proc" || $1 == "vmread" { n++ } END { print "contiguous rows:", n; exit (n != 60) }' \
  docs/benchmarks/data/stage-d-2026-10-22/cow-repeats.txt

awk '($1 == "proc" || $1 == "vmread") && $2 == "maps" { n++ } END { print "VMA rows:", n; exit (n != 120) }' \
  docs/benchmarks/data/stage-d-2026-10-22/vma-maps-repeats.txt
```

The expected totals are 60 and 120, respectively. These checks establish only the row counts, **not** numerical parity of all medians and percentiles; an independent recomputation is still required for full auditability.

For the raw benchmark output, a method line begins with `proc` or `vmread`. The VMA maps-aware lines also carry the policy field `maps`. Do not count the `--probe` rows as part of the 180 primary observations.

When all five logs have been reviewed, create and validate the checksum manifest:

```sh
cd docs/benchmarks/data/stage-d-2026-10-22
sha256sum -- system.txt cow-baseline.txt cow-repeats.txt vma-maps-repeats.txt vma-probe.txt > SHA256SUMS
sha256sum -c SHA256SUMS
```

Run `git status --short` and inspect the staged file list before committing. Do **not** commit executable benchmark binaries from `build/`, unrelated process traces, secrets, or large generated build artifacts.

## Measurement matrix

- **Architecture:** AArch64 / ARM Neoverse-N1, one vCPU; Linux `6.17.0-1018-oracle`; 4096-byte pages.
- **Reader methods:** `proc` = `pread(/proc/<pid>/mem)`; `vmread` = `process_vm_readv()`.
- **Block sizes:** 4, 64, 256 KiB.
- **Contiguous:** 32 MiB, 8192 tracked private COW pages.
- **Fragmented:** 16 pages per segment (410 readable VMAs) and 64 pages per segment (102 readable VMAs).
- **Per case:** fresh fork, cold pass, five warm passes, one PFN-before/after comparison outside timing.
- **Primary series:** ten repeats for each method × block × layout combination.
- **Extra fixture:** `vma-probe.txt` intentionally reads across `PROT_NONE` mappings and holes; those differing read-byte totals cannot be used for equal-workload throughput comparison.

Raw records are kernel/host-specific experimental evidence. The separately published HTML graphs represent aggregated observations and should always be cited together with this dataset and its limitations.
