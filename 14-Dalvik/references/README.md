# 14 — Dalvik and Smali · References

Annotated. Each entry says *why* you would open it, so you can choose the right one under time
pressure.

This chapter has an unusual property: its subject has a **normative published specification**, a
**generated implementation** and a **deleted historical implementation**, and all three are public.
When the specification and the runtime appear to disagree, the runtime is what executes on the device.

---

## 1. The normative specification — start here

| Resource | Why you would open it |
|---|---|
| [**Dalvik bytecode**](https://source.android.com/docs/core/runtime/dalvik-bytecode) | **The opcode reference.** Every instruction with its exact syntax and semantics. This is the page §3.10 of the chapter is checked against. Bookmark it |
| [**Instruction formats**](https://source.android.com/docs/core/runtime/instruction-formats) | The `NAx` naming scheme decoded, with the bit layout of every format. Read it when you are decoding an instruction from raw bytes and need to know which nibble is which |
| [Dalvik Executable format](https://source.android.com/docs/core/runtime/dex-format) | The container the instructions live in. Owned by [12-DEX-Internals](../../12-DEX-Internals/README.md), listed here because the three pages are read together |

Those three pages are the ground truth for the whole instruction reference. If this chapter and one of
them ever disagree, the page is right and the chapter is wrong.

---

## 2. AOSP — the instruction set as it exists today

Read on [cs.android.com](https://cs.android.com/) for search, or
[android.googlesource.com](https://android.googlesource.com/) for exact branch/tag control. See
[07-AOSP](../../07-AOSP/README.md) for the navigation technique.

### Repository `platform/art`

| Path | Open it when |
|---|---|
| **`libdexfile/dex/dex_instruction_list.h`** | **You need certainty about an opcode.** One macro-expanded table: opcode number, enum name, mnemonic string, format, index type, verification flags. This is what the runtime is compiled from, so it is definitionally correct. It also answers "does this opcode exist on this Android version?" in seconds — just switch branches |
| `libdexfile/dex/dex_instruction.h`, `.cc` | Operand extraction: how the runtime pulls `vA`, `vB`, the literal and the index out of the code units |
| `libdexfile/dex/dex_file_structs.h` | The `code_item` your instructions live inside |
| `art/runtime/verifier/method_verifier.cc` | **Why your patch was rejected.** The data-flow verification that produces `VerifyError`, including the register-type lattice and the `move-result` adjacency check |
| `art/runtime/interpreter/` | How ART executes the instructions today, for comparison with Dalvik's `mterp` |

### Repository `platform/dalvik` — the tooling side, still maintained

| Path | Open it when |
|---|---|
| **`opcode-gen/bytecode.txt`** | You want the **single text file the tooling's opcode tables are generated from**. Elegant piece of engineering: one source, and the C headers, the tables and the published documentation all derive from it, which is why they have never drifted |
| `opcode-gen/opcode-gen`, `opcode-gen.awk`, `regen-all`, `README.txt` | The generator itself |
| `libdex/DexOpcodes.h`, `.cpp` | The generated opcode enums and name tables `dexdump` uses |
| `libdex/InstrUtils.h`, `.cpp` | Instruction width and format tables — what you need to walk an instruction stream without decoding it |
| `libdex/DexFile.h` | `DEX_MAGIC`, `DEX_OPT_MAGIC`, and the `DexOptHeader` structure quoted in §3.16 |
| `libdex/DexOptData.cpp`, `.h` | Reading the optimised sections of an ODEX |
| `libdex/OptInvocation.cpp` | How the flattened `data@app@…@classes.dex` cache filename was built |
| `dexdump/dexdump.cpp` | A complete, readable reference disassembler. Diff against it when your own decoding disagrees with a tool |

---

## 3. AOSP — the deleted Dalvik VM

**These paths only exist on branches up to and including `kitkat-release`.** Browse
[android.googlesource.com/platform/dalvik](https://android.googlesource.com/platform/dalvik/) and
change the branch selector; on `android10-release` and later the `vm/` directory is gone.

### The interpreter

| Path | Why |
|---|---|
| **`vm/mterp/README.txt`** | The interpreter design in its authors' own words: the fixed-size handler areas, the `table-start + opcode * handler-size` dispatch, and the portable-versus-fast split. Short, and the best primary source on how a real production bytecode interpreter is built |
| `vm/mterp/config-*` | Per-architecture lists of which opcodes have hand-written assembly handlers |
| `vm/mterp/out/InterpC-*.c`, `InterpAsm-*.S` | The generated interpreter actually compiled into `libdvm.so` |
| `vm/interp/Interp.cpp`, `Interp.h`, `InterpDefs.h` | Interpreter entry, exception dispatch, the `FINISH` macro |
| `vm/interp/Stack.cpp` | Frame setup and teardown — the register array of §2.4, allocated |

### The trace JIT

| Path | Why |
|---|---|
| **`vm/interp/Jit.cpp`**, `Jit.h` | Profiling counters, threshold, trace selection, the translation lookup table, and trace chaining. The place to read if you want to understand what a trace JIT actually is |
| `vm/compiler/Compiler.cpp`, `.h` | The compiler thread's main loop and the work queue |
| `vm/compiler/Frontend.cpp` | Trace descriptor to intermediate representation |
| `vm/compiler/Dataflow.cpp`, `SSATransformation.cpp` | The analysis, such as it was |
| `vm/compiler/Loop.cpp` | The only loop optimisation there was |
| `vm/compiler/Ralloc.cpp` | Register allocation — trace-local, which is the design's central limitation |
| **`vm/compiler/InlineTransformation.cpp`** | The inliner. Read it to see how little inlining a trace JIT can do, which is the honest answer to "why was it only 2–5× faster than interpretation" |
| `vm/compiler/codegen/arm/`, `vm/compiler/template/` | Native code emission and the hand-written assembly templates |

### Verification, optimisation, memory

| Path | Why |
|---|---|
| `vm/analysis/` | The bytecode verifier and the `dexopt` optimiser, including quickening |
| `vm/alloc/` | The mark-and-sweep heap that ART's compacting collector replaced |
| `vm/oo/` | Object model, class linking, vtable construction — the ancestor of ART's `ClassLinker` |
| `vm/native/` | JNI implementations of the core library's native methods |

### The original design documents

`dalvik/docs/` survives on **every** branch, including current ones. These are 2008-era HTML documents
and they are still the clearest explanation of several things nothing else explains.

| Document | Why |
|---|---|
| **`docs/dexopt.html`** | Why install-time optimisation is device-specific, what quickening does, and why the dependency table exists. The direct ancestor of ART's VDEX |
| **`docs/verifier.html`** | What the verifier checks and why, written before anyone had a reason to obscure it |
| `docs/dalvik-constraints.html`, `docs/java-constraints.html` | Enumerated constraints a valid DEX must satisfy. Effectively a checklist of everything a malformed-DEX test corpus should try to violate |
| `docs/embedded-vm-control.html` | Every `dalvik.vm.*` property and `-X` flag, documented. The source for §3.20 |
| `docs/hello-world.html` | Writing Dalvik bytecode **by hand**, from scratch. Charming, and genuinely instructive if you want to feel the instruction set rather than read about it |
| `docs/debugger.html`, `docs/debugmon.html` | JDWP and the debug monitor |
| `docs/heap-profiling.html` | hprof, and how Dalvik heap dumps differ from JVM ones |
| `docs/porting-guide.html`, `docs/porting-proto.c.txt` | What porting the VM to a new architecture involved — which explains why nobody wanted to do it again for ARM64 |
| `docs/java-bytecode.html` | JVM bytecode notes, kept for the `dx` translation side |

---

## 4. Tooling

| Tool | Use | Source |
|---|---|---|
| **`smali` / `baksmali`** | The assembler and disassembler. Also ships `dexlib2`, a genuinely good DEX read/write library you can build tooling on | https://github.com/google/smali |
| **`apktool`** | Full APK decode and rebuild, including binary XML and resources. The normal patching path | https://apktool.org/ |
| `jadx` | Java decompilation with a Smali pane beside it. `--show-bad-code` keeps methods it failed on | https://github.com/skylot/jadx |
| `dexdump` | `-d` for disassembly with hex code units beside the mnemonics — the best tool for hand-decoding | Android SDK build-tools |
| `vdexExtractor` | **Unquickening** for DEX pulled from Android 8–10 devices | https://github.com/anestisb/vdexExtractor |
| `zipalign`, `apksigner` | Alignment and signing. Always in that order | Android SDK build-tools |
| `R8` / `D8` | The compiler that emits the bytecode you are reading. Useful when you need to know *why* a construct was generated a particular way | https://r8.googlesource.com/r8 |
| `androguard` | Python DEX/APK analysis library, if you want programmatic access without writing a parser | https://github.com/androguard/androguard |
| `dexlib2` (standalone) | Java/Kotlin DEX manipulation. The right answer when `grep` is not enough and a full framework is too much | part of the `smali` project |

### Chapter tooling

| File | Purpose |
|---|---|
| [`scripts/smali_stats.py`](../scripts/smali_stats.py) | Instruction-frequency profile and obfuscation heuristics across a decoded APK. **`--heuristics` is the one to run first** on an unfamiliar app |
| [`scripts/smali_frame.py`](../scripts/smali_frame.py) | Computes the register frame of a method — the `p`-to-`v` mapping, wide pairs, and the hazards that break patches. `--check` scans a whole tree |
| [`scripts/smali-hunt.sh`](../scripts/smali-hunt.sh) | Runs the whole §6.7 grep catalogue against a decoded APK and groups the output |
| [`scripts/trace-method.js`](../scripts/trace-method.js) | Frida: hook methods you located in Smali, print arguments, return value and caller |
| [`examples/Pinner.smali`](../examples/Pinner.smali) | The annotated pinning class from §6.2, with the finding worked through |
| [`examples/PatchCookbook.smali`](../examples/PatchCookbook.smali) | Nine patches, each with the original, the patched form, the register accounting and the specific trap |
| [`examples/InstructionTour.smali`](../examples/InstructionTour.smali) | One class exercising every instruction family, annotated line by line |
| [`examples/Target.java`](../examples/Target.java) | The Java source the labs build and disassemble |

---

## 5. Security research

| Resource | Why |
|---|---|
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | **Where to source a real CVE identifier** for a runtime or verifier issue, rather than recalling one. Searchable by release |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | High-quality research on runtime, parser and verifier bugs |
| [Android VRP rules](https://bughunters.google.com/about/rules/android-friends) | What Google treats as reportable in this area |

> **Note on CVE citation.** This chapter names **CVE-2017-13156 (Janus)** because it is precisely the
> "two parsers, one file" pattern the chapter teaches, and it names **CVE-2013-4787 ("Master Key")**
> only to correct its frequent misattribution to Dalvik — it is a ZIP-parsing bug and belongs to
> [10-APK-Internals](../../10-APK-Internals/README.md). Everything else is described as a *class* of
> issue. A misattributed CVE in a client deliverable is worse than no citation.

---

## 6. OWASP

| Resource | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | **MASVS-RESILIENCE** (the whole chapter: obfuscation quality, anti-tamper, integrity), **MASVS-CODE** (hardcoded secrets, debug artefacts in release), **MASVS-CRYPTO** (key material in array payloads) |
| [MASTG](https://mas.owasp.org/MASTG/) | The reverse-engineering and tampering procedures. Cite these by name rather than by test ID — the identifiers have been renumbered between MASTG versions |

---

## 7. Talks, papers and long-form

| Work | Why |
|---|---|
| Dan Bornstein, *Dalvik VM Internals*, Google I/O 2008 | The original design rationale, from the designer: why a register machine, why one constant pool, why memory-mappable. The primary source for §1.1 and §2.2 |
| Ben Cheng and Bill Buzbee, *A JIT Compiler for Android's Dalvik VM*, Google I/O 2010 | The trace JIT explained by the people who built it, including the memory argument for traces over methods |
| Google I/O 2014, *The ART runtime* | The replacement, and the case made for it at the time |
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | The deepest published treatment of the runtime and its context. Volume on the userspace runtime is the relevant one |
| *Android Security Internals* — Nikolay Elenkov | The security model this bytecode executes inside |
| *Decompiling Android* — Godfrey Nolan | Dated, and written around the format rather than around a tool, which is why it aged better than most |
| *Engineering a Compiler* — Cooper and Torczon | Not Android-specific. If §2.2's stack-versus-register argument interested you, this is where the general theory is |

---

## 8. Related chapters

| Chapter | Relationship |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | The container, and **signing** — why re-signing makes your patched app a different application, and why v2+ signatures killed Janus |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | The concept layer: managed runtimes, Zygote, class loaders. Read before this chapter |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | **The byte-level format.** Where each instruction's *encoding* is dissected. This chapter owns the *meaning* |
| [13-ART](../../13-ART/README.md) | The modern runtime that executes this bytecode. Where quickening, VDEX and entrypoint patching are covered |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What is done to the Smali you just learned to read, and why semantics always survive it |
| [53-Frida](../../53-Frida/README.md) | The dynamic counterpart. Frida to find, Smali to fix |
| [57-Ghidra](../../57-Ghidra/README.md) | Where `.method … native` leads once logic has left the DEX |
| [04-Java](../../04-Java/README.md) | The source language whose constructs the §6.1 recognition table maps back to |
| [05-Kotlin](../../05-Kotlin/README.md) | And the other one — coroutines, `data class`, `object`, extension functions, all visible in Smali |
| [34-Cryptography](../../34-Cryptography/README.md) | What to do with the key material you find in `fill-array-data` |
| [37-RootDetection](../../37-RootDetection/README.md) | The single most commonly patched class of check |
| [49-KeyStore](../../49-KeyStore/README.md) | Where a key should have been instead of in a `const-string` |
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | `mmap`, which is why DEX is uncompressed and shared |
| [07-AOSP](../../07-AOSP/README.md) | How to navigate the source trees cited throughout section 3 |
