# Security Checks in RuntimeXRay

This document describes the static security checks currently performed by RuntimeXRay on ELF binaries.

## Table of Contents
- [NX (No eXecute)](#nx-no-execute)
- [PIE (Position-Independent Executable)](#pie-position-independent-executable)
- [RELRO (RELocation Read-Only)](#relro-relocation-read-only)
- [Stack Canary](#stack-canary)

---

## NX (No eXecute)

### What it is
NX marks memory pages (especially the stack and heap) as non-executable. The CPU will refuse to execute code from these pages.

### Why it matters
Many classic buffer overflow attacks inject shellcode into the stack and then jump to it. NX makes this impossible by preventing code execution from stack/heap. Attackers must then use more complex techniques like Return-Oriented Programming (ROP).

### How we detect it
We inspect the `PT_GNU_STACK` program header. If the `PF_X` flag is not set, NX is enabled.

### Example output
```
NX: Enabled
```

---

## PIE (Position-Independent Executable)

### What it is
PIE allows an executable to be loaded at a random base address, similar to shared libraries. This is a prerequisite for full Address Space Layout Randomization (ASLR).

### Why it matters
Without PIE, the main executable is loaded at a fixed address. Attackers know exactly where every function and gadget is located, which makes exploitation much easier. PIE randomizes the base, making addresses unpredictable.

### How we detect it
We check the ELF header field `e_type`. If it is `ET_DYN`, the binary is position-independent.

### Example output
```
PIE: Enabled
```

---

## RELRO (RELocation Read-Only)

### What it is
RELRO protects the Global Offset Table (GOT) from being overwritten. Partial RELRO makes only the `.got` section read-only; Full RELRO also makes `.got.plt` read-only after all relocations are resolved.

### Why it matters
The GOT contains addresses of dynamically linked functions. Attackers often try to overwrite GOT entries to redirect calls (e.g., from `printf` to `system`). RELRO prevents such overwrites.

### How we detect it
- Partial RELRO: presence of `PT_GNU_RELRO` segment.
- Full RELRO: additionally, the dynamic section contains `DT_BIND_NOW` or `DT_FLAGS` with `DF_BIND_NOW`.

### Example output
```
RELRO: Full
```

---

## Stack Canary

### What it is
A stack canary is a random value placed between a function's local variables and the saved return address. Before returning, the function checks that the canary is unchanged. If it was overwritten (by a buffer overflow), the program aborts immediately.

### Why it matters
Canaries detect stack buffer overflows before they can alter the return address. This makes direct return-address hijacking extremely difficult.

### How we detect it
We search the symbol tables (`.dynsym` or `.symtab`) for the symbol `__stack_chk_fail`. If present, stack canary is enabled.

### Example output
```
Canary: Enabled
```

---

*Last updated: 2026-08-15*