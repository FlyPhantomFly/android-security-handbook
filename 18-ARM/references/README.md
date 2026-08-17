# 18 — ARM · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure.

ARM is unusual in this repository in one specific way: the **specification is public, complete, and
authoritative**, and it is written by the people who designed the silicon. When a disassembler, a
decompiler and a blog post disagree, the Arm Architecture Reference Manual settles it. Start there
for anything about encodings; start with AAPCS64 for anything about where arguments live.

---

## The normative sources — start here

| Resource | Why |
|---|---|
| [Arm Architecture Reference Manual for A-profile (DDI 0487)](https://developer.arm.com/documentation/ddi0487/latest) | **The authority.** Every A64 encoding, every field, every pseudocode function — including `DecodeBitMasks`, which `scripts/arm64-patch.py` transcribes. Section C4 holds the A64 encoding tables. Thousands of pages; never read it linearly |
| [Arm A64 Instruction Set Architecture — online reference (DDI 0602)](https://developer.arm.com/documentation/ddi0602/latest) | The same content as searchable HTML, one instruction per page, with the encoding diagram and the pseudocode. **This is the one to bookmark.** A single lookup takes fifteen seconds here and ten minutes in the PDF |
| [Arm ABI documents (`abi-aa` repository)](https://github.com/ARM-software/abi-aa) | The umbrella repository for every ABI document below. Rendered `.rst` and `.pdf` in one place, versioned in public |
| [AAPCS64 — Procedure Call Standard for the Arm 64-bit Architecture](https://github.com/ARM-software/abi-aa) | **The source for README §3.4.** In `abi-aa` as `aapcs64`. Short and readable: argument registers, the FP sequence, `x8` for large struct returns, the callee-saved set, and the variadic rules |
| [AAPCS32 — the 32-bit procedure call standard](https://github.com/ARM-software/abi-aa) | What you need for `armeabi-v7a`: `r0`–`r3`, `r4`–`r11` callee-saved, and the Thumb interworking rules behind README §3.13 |
| [AAELF64 — the ELF ABI for AArch64](https://github.com/ARM-software/abi-aa) | The `R_AARCH64_*` relocation numbering. Mostly [15-Native-Code](../../15-Native-Code/README.md)'s territory; here for the names you will meet in `.rela.plt` |
| [Arm Cortex-A Series Programmer's Guide for ARMv8-A (DEN 0024)](https://developer.arm.com/documentation/den0024/latest) | **The gentle introduction.** Read this before the ARM ARM, not after. Chapters on the register file, the instruction set and the exception model are the best free prose on the subject |

---

## Security features of the architecture

| Resource | Why |
|---|---|
| [Arm — speculative processor vulnerability advisory](https://developer.arm.com/Arm%20Security%20Center/Speculative%20Processor%20Vulnerability) | **Which Cortex-A cores are affected by which variant**, from Arm rather than from a news article. Covers CVE-2017-5753 (bounds-check bypass) and CVE-2017-5715 (branch target injection) as they apply to Arm |
| [Arm Security Center](https://developer.arm.com/Arm%20Security%20Center) | The index of Arm's own advisories and whitepapers, including straight-line speculation — the issue behind clang's `-mharden-sls=` flag |
| [Arm — *Providing protection for complex software* (PAC/BTI whitepaper)](https://developer.arm.com/documentation/102433/latest) | The design reasoning behind pointer authentication and branch target identification. Explains *why* the mitigations sit at the ends of gadgets rather than in the middles, which is the argument in README §3.12 |
| [Arm — Learn the architecture: Providing protection for complex software](https://developer.arm.com/documentation/102433/latest) | Task-oriented companion to the above, with the actual instruction sequences |

---

## Android specifics

| Resource | Why |
|---|---|
| [Android ABI Management](https://developer.android.com/ndk/guides/abis) | Which ABIs exist, how a device chooses one, what `abiFilters` does. **Read this before deciding which `lib/<abi>/` to analyse** |
| [NDK guides](https://developer.android.com/ndk/guides) | The toolchain layout, and where `-fstack-protector-strong` and `-mbranch-protection=` are actually configured |
| [Android — Control Flow Integrity](https://source.android.com/docs/security/test/cfi) | Platform CFI on Android, and its relationship to the indirect-call shapes in README §3.8 |
| [Android — Shadow Call Stack](https://source.android.com/docs/security/test/shadow-call-stack) | **Why `x18` is reserved** on Android (README §3.1), and what breaks if a hooking framework clobbers it |
| [Android — Memory Tagging Extension](https://source.android.com/docs/security/test/memory-safety/arm-mte) | MTE, Armv8.5, and the manifest opt-in. The heap side belongs to 19-Memory |
| [Android — debugging native crashes and tombstones](https://source.android.com/docs/core/tests/debug/native-crash) | How to read the register dump and backtrace in README §5.8, field by field |
| [Support 16 KB page sizes](https://developer.android.com/guide/practices/page-sizes) | The `-Wl,-z,max-page-size=16384` flag `examples/build-arm-fixtures.sh` passes, and why |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | The primary source for any CVE you intend to cite. **Check here rather than remembering an identifier** |

---

## AOSP source

Read on [cs.android.com](https://cs.android.com/). [07-AOSP](../../07-AOSP/README.md) is the
navigation technique. **File paths are stable; line numbers are not, and none are cited anywhere in
this chapter.**

### Bionic — the C library and the linker

| Path | What is in it |
|---|---|
| `bionic/libc/platform/bionic/tls_defines.h` | `TLS_SLOT_STACK_GUARD`. **This is where the `40` in `ldr x8, [x20, #40]` comes from** — slot 5, eight bytes per slot |
| `bionic/libc/private/bionic_tls.h` | The per-thread `bionic_tls` structure that hangs off the TLS array |
| `bionic/libc/bionic/__stack_chk_fail.cpp` | What happens on a canary mismatch: `async_safe_fatal`, then `SIGABRT` |
| `bionic/libc/bionic/libc_init_common.cpp` | Where the guard value is seeded, from `AT_RANDOM` in the auxiliary vector |
| `bionic/libc/bionic/pthread_internal.h` | `pthread_internal_t`, holding the per-thread TLS array that `TPIDR_EL0` points into |
| `bionic/libc/SYSCALLS.TXT` | **The syscall table, per architecture.** `getpid` is 172 on arm64 and 20 on arm — this file is why |
| `bionic/libc/tools/gensyscalls.py` | The generator that turns that table into `mov w8, #N` / `svc #0` stubs |
| `bionic/libc/arch-arm64/syscalls/` | The generated stubs. Read two or three to internalise the syscall convention |
| `bionic/linker/linker.cpp`, `bionic/linker/linker_relocate.cpp` | Symbol resolution and the relocation loop that fills the GOT slots the PLT stubs read |
| `bionic/linker/linker_soinfo.cpp` | `find_symbol_by_name` and the namespace lookup order |
| `bionic/linker/arch/arm64/begin.S` | The linker's own AArch64 entry point. Some of the clearest hand-written A64 in AOSP |

### ART — where much of the AArch64 you meet is generated

| Path | What is in it |
|---|---|
| `art/compiler/optimizing/code_generator_arm64.cc` | The optimising compiler's AArch64 backend, one `Visit` method per HIR instruction. **This is what generates the code in an `.oat` file** |
| `art/compiler/utils/arm64/assembler_arm64.h`, `.cc` | ART's AArch64 assembler, built on Linaro's `vixl` |
| `art/runtime/arch/arm64/quick_entrypoints_arm64.S` | Hand-written trampolines between managed and native code. Shows *complete* register save/restore sequences, which compilers only ever emit partially |
| `art/runtime/arch/arm64/asm_support_arm64.h` | **Which registers ART reserves.** `x19` holds the current `Thread*` in generated code |
| `art/runtime/arch/arm64/registers_arm64.h` | ART's names for the AArch64 registers |

### Debuggerd and unwinding — where a tombstone comes from

| Path | What is in it |
|---|---|
| `system/core/debuggerd/handler/debuggerd_handler.cpp` | The fatal-signal handler installed in every app process |
| `system/core/debuggerd/libdebuggerd/tombstone.cpp` | Tombstone text formatting — the register dump layout in README §5.8 |
| `system/core/debuggerd/libdebuggerd/tombstone_proto.cpp` | The protobuf the text is rendered from |
| `system/unwinding/libunwindstack/` | The unwinder: `x29` frame-pointer chains plus `.eh_frame` DWARF |

---

## OWASP MASVS and MASTG

| Identifier | Why it maps here |
|---|---|
| [MASVS-CODE-4](https://mas.owasp.org/MASVS/) | Input validation. README §5.3.1's sign-extension class is only visible at the instruction level — `ldrsb` plus a signed branch |
| [MASVS-CRYPTO-1, MASVS-CRYPTO-2](https://mas.owasp.org/MASVS/) | Correct cryptography. §3.14 identifies the primitive from `aese`/`sha256h`; §3.10 pattern 10 finds the key in a `movk` chain |
| [MASVS-RESILIENCE-1](https://mas.owasp.org/MASVS/) | Platform integrity. Root checks implemented as raw syscalls, §5.3.3 |
| [MASVS-RESILIENCE-2](https://mas.owasp.org/MASVS/) | Anti-debugging. `brk`, `ptrace` self-attach, `mrs CNTVCT_EL0` timing, §3.12 and §5.7 |
| [MASVS-RESILIENCE-3](https://mas.owasp.org/MASVS/) | Anti-tampering. **§5.4 is the attack these controls exist to catch** |
| [MASVS-RESILIENCE-4](https://mas.owasp.org/MASVS/) | Obfuscation. §6.7 on what survives it at instruction level |
| [MASTG — reverse engineering and tampering](https://mas.owasp.org/MASTG/) | The test procedures this chapter's techniques implement |
| [MASTG — Android anti-reversing defences](https://mas.owasp.org/MASTG/) | Where `svc`, `brk` and timing checks are catalogued as controls rather than as bugs |

---

## Tools

| Resource | Why |
|---|---|
| [`llvm-objdump` command guide](https://llvm.org/docs/CommandGuide/llvm-objdump.html) | Every flag used in README §8: `-d`, `--no-show-raw-insn`, `--start-address`, `-s -j`, `-S` |
| [`llvm-readelf` command guide](https://llvm.org/docs/CommandGuide/llvm-readelf.html) | `--dyn-syms`, `--symbols`, `--notes`, `-l`, `-h` |
| [`llvm-strip` / `llvm-nm` command guides](https://llvm.org/docs/CommandGuide/) | The rest of the NDK's binutils |
| [Capstone disassembly engine](https://www.capstone-engine.org/) | What Frida's `Instruction.parse` uses, and what radare2 and many others use. Useful when you want to write your own analysis in Python |
| [Frida — JavaScript API reference](https://frida.re/docs/javascript-api/) | `Instruction`, `Interceptor`, `Memory.protect`, `NativePointer.writeByteArray`, `Process.enumerateModules` |
| [Frida — Stalker](https://frida.re/docs/stalker/) | Instruction-level tracing. The most direct application of everything in this chapter, and the reason [53-Frida](../../53-Frida/README.md) cites it |
| [Ghidra](https://ghidra-sre.org/) | The decompiler. [57-Ghidra](../../57-Ghidra/README.md) owns the workflow; this chapter is what you use when it fails |
| [`vixl` — Arm's runtime assembler and simulator](https://github.com/Linaro/vixl) | What ART's AArch64 assembler is built on. Also a genuinely good reference implementation of A64 encoding, in readable C++ |
| [Compiler Explorer](https://godbolt.org/) | Type C, pick `armv8-a clang`, and watch the assembly change as you edit. **The single fastest way to build intuition** for why the compiler chose what it chose |

---

## Further reading

| Resource | Why |
|---|---|
| Arm — *Learn the architecture* series, on `developer.arm.com` | Short, official, task-oriented guides: the memory model, the exception model, PAC/BTI, SVE. Free, and better written than most books |
| Arm — *Armv8-A instruction set architecture* overview guides | The bridge between the Programmer's Guide and the full ARM ARM |
| Google Project Zero's public research on Android and Arm | Worked exploitation write-ups where instruction-level detail is the point. Read them for method, not for recipes, and note how much of each one is the arithmetic in README §6.6 |
| The Linux kernel's `arch/arm64/` tree | When you need to know what the kernel does with a fault, an exception level, or a system register. `arch/arm64/kernel/entry.S` is the counterpart to Bionic's syscall stubs |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [01-Computer-Science-Basics](../../01-Computer-Science-Basics/README.md) | Hex, endianness, stack frames — the prerequisites this chapter assumes and does not re-teach |
| [13-ART](../../13-ART/README.md) | The runtime that generates a large fraction of the AArch64 in a running app |
| [15-Native-Code](../../15-Native-Code/README.md) | **Owns the ELF container** — sections, segments, relocations, PLT/GOT as a *format*. This chapter owns the instructions inside them |
| [16-JNI](../../16-JNI/README.md) | **Owns the JNI convention.** This chapter owns the ABI beneath it: `JNIEnv*` in `x0` is AAPCS64, not JNI |
| [17-Libraries](../../17-Libraries/README.md) | Which library you are reading and why. Its x86-versus-ARM table cites this chapter for the `TPIDR_EL0` half, which is README §3.11 |
| [37-RootDetection](../../37-RootDetection/README.md) | The detection catalogue whose native implementations have exactly the shapes in README §3.10 |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What obfuscation does to those shapes, and what survives it |
| [53-Frida](../../53-Frida/README.md) | The instruction set Stalker recompiles and `Arm64Writer` emits |
| [57-Ghidra](../../57-Ghidra/README.md) | **Owns the decompiler workflow.** Its §6.6 "survival subset" of ARM64 points here for the full treatment |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The command index |
| [79-Glossary](../../79-Glossary/README.md) | AArch64, AAPCS64, canary, PLT, GOT, register — defined there |

### Referenced as plain text in the chapter body, and all now written

[19-Memory](../../19-Memory/README.md) (heap layout, MTE, Scudo) ·
[38-TamperDetection](../../38-TamperDetection/README.md) (integrity checks that survive a byte
patch) · [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) ·
[52-StaticAnalysis](../../52-StaticAnalysis/README.md) · [58-IDA](../../58-IDA/README.md) ·
[59-radare2](../../59-radare2/README.md) · [65-Hooking](../../65-Hooking/README.md) ·
[67-BypassingProtections](../../67-BypassingProtections/README.md) ·
[68-ReverseEngineering](../../68-ReverseEngineering/README.md) ·
[69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) ·
[70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md)

---

## This chapter's own files

| File | What it is |
|---|---|
| [`examples/patterns.c`](../examples/patterns.c) | One small C function per recurring AArch64 shape. **Every listing in README §3.10 came from compiling this** |
| [`examples/licence-check.c`](../examples/licence-check.c) | The deliberately patchable target: four functions of escalating patch difficulty, ending with one that cannot be usefully patched at all |
| [`examples/licence-runner.c`](../examples/licence-runner.c) | An Android command-line executable that `dlopen`s the library by path, so a patch can be *proven* rather than asserted |
| [`examples/build-arm-fixtures.sh`](../examples/build-arm-fixtures.sh) | Builds all seven fixtures with the NDK — three AArch64 variants, the `-marm`/`-mthumb` pair, the patch target and its runner — and prints the Thumb-bit comparison |
| [`scripts/arm64-patch.py`](../scripts/arm64-patch.py) | Maps virtual address to file offset via the program headers, resolves symbols, assembles a small verified patch vocabulary, and shows before and after. Standard library only; no NDK required |
| [`scripts/find-check-shapes.py`](../scripts/find-check-shapes.py) | Triage: sweeps `.text` for check-shaped functions and ranks them. A reading list, never a finding |
| [`scripts/dump-function.js`](../scripts/dump-function.js) | Frida: disassemble a function as it exists **in memory**, print its AAPCS64 argument registers on entry and `x0` on exit, and save the live bytes for import into Ghidra |
| [`cheatsheet.md`](../cheatsheet.md) | Dense lookup: registers, condition codes, shapes, verified encodings, byte signatures, commands |
| [`mindmap.md`](../mindmap.md) | The whole chapter as one Mermaid mind map |
| [`faq.md`](../faq.md) | Twenty-eight questions learners actually ask, including the ones that feel too basic to ask |
| [`labs/lab-01-read-your-first-disassembly.md`](../labs/lab-01-read-your-first-disassembly.md) | Read a function and say what it does; see one source compiled five ways |
| [`labs/lab-02-patch-the-licence-check.md`](../labs/lab-02-patch-the-licence-check.md) | Four bytes, three verifications, and the inlining trap |
| [`labs/lab-03-runtime-truth.md`](../labs/lab-03-runtime-truth.md) | Memory versus the file: ASLR, live disassembly, in-memory patching |
| [`labs/lab-04-ctf-four-decisions.md`](../labs/lab-04-ctf-four-decisions.md) | **CTF.** Four flags, four techniques, no decompiler, no device |
