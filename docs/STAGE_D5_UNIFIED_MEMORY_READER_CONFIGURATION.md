# Stage D.5 — Unified Memory Reader Configuration

**RuntimeXRay design, integration and validation record**
**Updated:** 2026-10-23
**Status:** Implemented; relevant tests and full CTest reported GREEN on the ARM64 validation host.

## 1. Decision

The Linux remote-memory reader is an explicit, typed RuntimeXRay configuration choice:

| Setting | Meaning |
| --- | --- |
| `--memory-reader proc` | Use `pread()` on `/proc/<pid>/mem` |
| `--memory-reader vmread` | Use `process_vm_readv()` |
| Flag omitted | Use **`proc`** |
| Invalid or missing value | Reject with a CLI error |
| Selected reader fails | Report/handle the read failure according to the caller; **never silently switch readers** |

The CLI option applies to both the `trace` and standalone `mem` commands. It replaces the earlier experimental `RXRAY_MEMORY_READ_BACKEND` environment selector; there is no supported implicit environment override.

The choice is visible and reproducible because these two APIs are **not** observationally or semantically identical on the tested kernel. The Stage D benchmark identified both a physical COW difference and a difference reading `PROT_NONE` mappings.

The result should not be described as “proc is always faster”: the measured `proc` advantage is for cold passes in the controlled fork/COW fixtures. `vmread` had higher warm throughput at 64/256 KiB.

## 2. User-facing contract

Examples (run from the repository root):

~~~sh
# Explicit default
./build/runtimexray mem --memory-reader proc <pid>
./build/runtimexray trace --memory-reader proc --backend ptrace --scan-memory /bin/true

# Opt into the older syscall reader for comparison
./build/runtimexray mem --memory-reader vmread <pid>
./build/runtimexray trace --memory-reader vmread --backend ptrace --scan-memory /bin/true

# The parser also supports the equals form
./build/runtimexray mem --memory-reader=vmread <pid>
~~~

`<pid>` is a placeholder, not a literal shell argument.

The supported reader names are exactly `proc` and `vmread`. Both commands should display the option and the default in their help text. The common CLI parser strips recognized shared flags into `CommonOptions` rather than requiring separate, drifting parsers for each command.

Invalid names and flags lacking values should fail at argument parsing rather than falling back to a default, guessing from the environment or appearing to succeed.

## 3. Propagation model

Selection must reach *every* production userspace reader through typed configuration:

~~~mermaid
flowchart TD
    A["--memory-reader proc|vmread"] --> B["parse_common_options"]
    B --> C["CommonOptions.memory_reader"]
    C --> D["mem command"]
    C --> E["trace command / TraceConfig"]
    D --> F["MemoryReader factory"]
    E --> G["ptrace / eBPF / Tachikoma"]
    G --> F
    F --> H["ProcMem or ProcessVm reader"]
~~~

### Integration map

| Path | Relevant sources | Expected behavior |
| --- | --- | --- |
| Common parsing/default | `include/common_cli.hpp`, `src/common_cli.cpp` | Parse `--memory-reader` / `--memory-reader=`; default `ProcMem` |
| Reader types and factory | `include/memory_reader.hpp`, `src/memory_reader.cpp` | Dispatch to exactly the requested mechanism |
| Bulk scanning | `include/memory_scanner.hpp`, `src/memory_scanner.cpp` | Use the selected reader for process-memory sweeps |
| Standalone mem | `src/commands/mem_command.cpp` | Forward `CommonOptions.memory_reader` |
| Trace command | `src/commands/trace_command.cpp` | Forward the selected reader to the scan session and backend config |
| Shared trace config | `include/itrace_backend.hpp` | Carry `TraceConfig.memory_reader` |
| Ptrace backend | `src/ptrace_backend.cpp` | Apply reader to tracer-side tracee reads |
| eBPF backend | `src/ebpf_backend.cpp` | Apply reader to relevant userspace fallback/capture reads |
| Tracer internals | `include/tachikoma.hpp`, `src/tachikoma.cpp` | Use reader factory when accessing tracee memory |
| Test consumers | `tests/memory_scanner/test_memory_scanner_self.cpp` | Call explicit-backend API signatures |

This is a dependency-injection boundary, not a mutable process-wide singleton. The default is set in common options and typed configurations rather than separately in individual call sites.

### Resource lifetime

- The `ProcMem` reader owns its descriptor using RAII.
- A reader is opened for the relevant target/session and is not deliberately retained through an `execve()` image-generation change.
- After `fork()`, each target process requires correct process identity and address-space interpretation; do not reuse another process's reader merely because it inherited virtual addresses.
- VMA reads must tolerate target exit, changed mappings, partial reads and permission failures.
- Switching the backend must not change unrelated secret extraction, report generation, redaction, scan limits or lineage semantics.

The dedicated lifecycle test was committed as `357f722`, titled “test(memory): validate reader lifecycle across VMA and process transitions”.

## 4. Why no silent fallback?

Consider a target with an inherited private page:

1. `proc` attempts a read.
2. A read fails due to a target lifecycle/permission/mapping condition.
3. An implicit fallback to `vmread` would now be allowed to unshare COW pages on the validation kernel.

The apparent “same read operation” can therefore have different physical side effects. The APIs can also disagree on access to `PROT_NONE`. A silent fallback would make both the observation and reported performance hard to reproduce.

**Invariant:** the selected backend is the only backend used for that read path. The caller may report a partial result, skip an unreadable region or fail appropriately, but it must not quietly switch mechanisms.

If automatic fallback ever becomes a product requirement, it needs a separately reviewed policy, explicit visibility in evidence/logging, and new correctness tests.

## 5. Source audit

The production call-site audit was performed with commands equivalent to:

~~~sh
rg -n 'scan_memory_for_secrets\(|scan_process_for_secrets\(' src include tests
rg -n 'process_vm_readv[[:space:]]*\(' src include
rg -n -- '--memory-reader|memory_reader' src include
rg -n 'RXRAY_MEMORY_READ_BACKEND' src include tests CMakeLists.txt
~~~

Observed after the refactor:

- The actual production invocation of `::process_vm_readv` resides in `src/memory_reader.cpp`, inside its selected-reader implementation.
- `src/syscall_names.cpp` contains syscall names for observation/reporting and is not an API invocation.
- Standalone benchmark fixtures intentionally invoke both Linux mechanisms directly.
- The former `RXRAY_MEMORY_READ_BACKEND` selector was removed from the production configuration. References only in historical research are historical context, not an active interface.
- Differential COW and evidence parity scripts were updated to explicitly pass the CLI option.

Re-run this audit before merging if any further tracing path is added or changed.

## 6. Regression strategy

### 6.1 CLI dispatch and real syscall verification

`tests/test_memory_reader_cli.sh` checks the observable selection behavior, not only the parser's internal variable:

| Command | Argument | Expected reader |
| --- | --- | --- |
| `mem` | no option | `proc` |
| `mem` | `--memory-reader proc` | `proc` |
| `mem` | `--memory-reader vmread` | `vmread` |
| `trace` | no option | `proc` |
| `trace` | `--memory-reader proc` | `proc` |
| `trace` | `--memory-reader vmread` | `vmread` |
| both | unsupported value | CLI error |
| both | missing value | CLI error |

On a host with `strace` and suitable privileges, verify the actual use of `pread64` on `/proc/<pid>/mem` or `process_vm_readv`. A log line saying “selected proc” is not by itself a sufficient end-to-end dispatch assertion.

### 6.2 Differential physical COW control

`tests/test_memory_reader_cow_differential.sh` tests baseline, negative `vmread` control and positive `proc` control with genuinely observable PFNs. The two application write orders must remain independent.

The expected negative-control failure is specifically **unexpected pre-write PFN divergence**, not any arbitrary nonzero exit. Skip with 125 when essential capabilities are unavailable. This expectation is kernel-specific; a kernel that does not reproduce the side effect may need a different applicability decision.

### 6.3 Evidence parity

`tests/test_memory_reader_evidence_parity.sh` checks equivalent semantic observations for fork/exec scenarios across the two readers:

- Correct process identity and generation.
- Child evidence and old/new secret isolation.
- Bounded `InitialInspection`.
- No fabricated data-flow edge from a memory-only observation.

HMAC fingerprints are random-keyed per run: compare within-report consistency and normalized evidence claims, not raw fingerprint strings between independent trace runs.

### 6.4 Reader lifecycle

`tests/test_memory_reader_lifecycle.cpp` and its CMake registration exercise reading across mapping and process transitions. Relevant cases include error handling and reader lifetime boundaries; the test should remain active as the scanner and tracer evolve.

### 6.5 Full suite

~~~sh
cmake -S . -B build
cmake --build build -j"$(nproc)"

ctest --test-dir build --output-on-failure -j"$(nproc)"
~~~

The user reported all relevant dedicated tests and full-suite checks GREEN. Exact registered test counts depend on the local checkout and CMake configuration and are deliberately not inferred here.

## 7. Performance and security evidence

The repeat-measurement campaign on Linux `6.17.0-1018-oracle` produced:

| Metric | `proc` | `vmread` |
| --- | --- | --- |
| 32 MiB contiguous, 256 KiB, cold median | 3608.45 MiB/s | 922.25 MiB/s |
| 32 MiB contiguous, 256 KiB, warm median | 3643.30 MiB/s | 4707.10 MiB/s |
| Contiguous tracked PFN splits | 0/8192 | 8192/8192 |
| 410 VMA tracked PFN splits | 0/3296 | 3296/3296 |
| 102 VMA tracked PFN splits | 0/3264 | 3264/3264 |
| 410 VMA, 4 KiB deliberate probe | 28.81 MiB read | 25.62 MiB read |

The probe rows **must not** be used as equal-workload speed comparisons. The extra data came from `PROT_NONE` regions readable via `proc` on this kernel; neither mechanism read unmapped holes.

For full 180-row repeat measurements, distributions, assumptions, caveats and source commands, see:

- [Stage D research record](STAGE_D_LOW_IMPACT_MEMORY_INSPECTION.md)
- [Interactive benchmark page](benchmarks/memory-readers.html)

## 8. Boundaries and open work

1. Test Linux kernels/architectures with different `get_user_pages` and procfs behavior before making general claims.
2. Test actual end-to-end trace and scan overhead; read-loop benchmarks intentionally omit setup, VMA enumeration and analysis.
3. Audit new direct tracee-memory reads and make them depend on the explicit reader choice.
4. Continue VMA race, target-exit, permissions and `execve()` tests.
5. Keep 4096-byte secret-scan chunking until larger reads demonstrate evidence parity at boundaries.
6. Review whether `PROT_NONE` should ever be scanned intentionally; API capability is not a policy decision.
7. Publish raw benchmark logs and machine metadata alongside the public HTML for independent statistical reproduction.

## 9. Stage D.5 acceptance

| Requirement | Result |
| --- | --- |
| `proc` default for trace and mem | Implemented |
| `vmread` explicit opt-in | Implemented |
| Both separated-argument and equals-argument CLI forms | Implemented |
| Missing/invalid option errors | Tested |
| Old environment selector retired | Implemented |
| Typed, explicit reader propagation | Implemented |
| No silent cross-backend fallback | Preserved |
| COW differential and evidence parity controls | Reported GREEN |
| VMA/process reader lifecycle regression | Reported GREEN |
| CLI syscall-dispatch regression | Reported GREEN |
| Full CTest suite | Reported GREEN |
| Updated technical evidence and benchmark visualization | Prepared |

**Conclusion:** Stage D.5 makes the memory-reader choice explicit, deterministic and testable across RuntimeXRay's supported command paths. `proc` is now the ordinary lower-impact choice on the tested platform, and `vmread` remains available for controlled comparison and future compatibility testing.
