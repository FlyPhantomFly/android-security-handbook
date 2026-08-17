# 65 — Hooking · References

Annotated. Every entry says why it is here and what it is good for, so you can decide whether to open
it. Entries marked **normative** are the source of truth for a claim made in this chapter.

---

## 1. AOSP source

Paths are stable; line numbers are not, and none are quoted.

| Path | What to read it for |
|---|---|
| `art/runtime/art_method.h` | **Normative.** Declares `entry_point_from_quick_compiled_code_` inside `PtrSizedFields`. This pointer is the entire managed-hook mechanism. Note that the field's *offset* depends on pointer size and on the ART version, which is why hard-coding it is the biggest source of breakage in public tooling |
| `art/runtime/art_method-inl.h` | The accessors, including the pointer-size handling that makes the offset device-dependent |
| `art/runtime/entrypoints/quick/quick_trampoline_entrypoints.cc` | The trampolines an entry point can hold — resolution, interpreter bridge, JNI bridge. Knowing these values is how you tell "hooked" from "not yet compiled" |
| `art/runtime/jni/jni_internal.cc` | **Normative** for `JNI::RegisterNatives`. Shows that the runtime copies the function pointer into its own `ArtMethod`, which is why rewriting the caller's array *after* registration accomplishes nothing |
| `libnativehelper/include_jni/jni.h` | `JNINativeMethod`'s three fields, and the JNI function table whose entry 215 is `RegisterNatives` |
| `bionic/linker/linker.cpp` | `do_dlopen` and `call_constructors` — proof that `.init_array` runs *inside* `dlopen`, which is the timing problem in its precise form. Also `protect_relro`, the entire cost full RELRO imposes on a PLT hook |
| `bionic/linker/linker_relocate.cpp` | **Normative** for how `R_AARCH64_JUMP_SLOT` is processed and the GOT slot written. Read alongside `examples/plt-got-hook.c` |
| `bionic/linker/dlfcn.cpp` | `__loader_dlopen` — the outer edge of the window in which you can still be early |
| `bionic/linker/arch/arm64/begin.S` | The linker's own entry, and where `/system/bin/linker64 <exe>` starts when you use the execution workaround |

---

## 2. Architecture and ABI

| Source | Why |
|---|---|
| **Arm Architecture Reference Manual for A-profile (DDI 0487)** | **Normative** for every encoding in this chapter, for the `adrp` immediate's meaning, for branch ranges, and for the cache-maintenance requirement in README §3.5.4. If a claim here disagrees with the ARM ARM, the ARM ARM is right |
| **Procedure Call Standard for the Arm 64-bit Architecture (AAPCS64)** | **Normative** for `x16`/`x17` as IP0/IP1 and the linker-veneer clobber licence. This is *the* justification for using `x16` in a prologue patch, and it is worth reading the exact wording once |
| **ELF for the Arm 64-bit Architecture (AAELF64)** | Relocation type numbering. `R_AARCH64_JUMP_SLOT` = 1026 (`0x402`), `R_AARCH64_GLOB_DAT` = 1025 (`0x401`) — both confirmed against a real library in this chapter |
| **System V ABI, Generic ELF specification** | `DT_JMPREL`, `DT_PLTRELSZ`, `DT_STRTAB`, `DT_SYMTAB` semantics; the `Elf64_Rela` layout |
| **Arm BTI / PAC guidance (Arm developer documentation)** | Why `bti c` matters to a prologue patch, and why displacing a `paciasp` without its `autiasp` crashes |

---

## 3. Kernel and libc interfaces

| Source | Why |
|---|---|
| `mmap(2)` | **Normative** for `MAP_FIXED_NOREPLACE` versus `MAP_FIXED`, and for the fact that a plain hint is advisory — which this chapter measured the hard way |
| `mprotect(2)` | Page-granular permission changes; the `W`-then-`X` pattern that avoids requesting both at once |
| `dl_iterate_phdr(3)` | Enumerating loaded modules and finding `PT_DYNAMIC` without parsing `/proc/self/maps` |
| `dlopen(3)`, `dlsym(3)`, `dladdr(3)` | `dladdr` is the standard way to ask "does this pointer belong to a real module?", which is the standard PLT-hook detection |
| GCC/Clang `__builtin___clear_cache` documentation | What the builtin emits, and why calling it is not optional even when omitting it appears to work |

---

## 4. Tooling

| Tool | Why |
|---|---|
| **Frida** — `Interceptor`, `NativeCallback`, `Module.enumerateImports` | The reference implementation of everything in README §3.5. Its `Interceptor` is a relocating inline hooker; when it refuses a function, it met an instruction its relocator could not move. Owned by [53-Frida](../../53-Frida/README.md) |
| **frida-gum** | The C library beneath Frida. Its AArch64 relocator and writer are the best-documented production implementation of the relocation problem, and reading them next to `examples/trampoline-hook.c` shows exactly what a real engine adds: veneering, thread safety, per-module page pools |
| **Dobby** | A compact standalone AArch64/ARM/x86 inline hooking library. Useful specifically because it is small enough to read end to end |
| **SHADOWHOOK** (ByteDance) | Android-focused inline hooking with an explicit design document about safety and unhooking. Worth reading for its treatment of the thread-safety problem this chapter's engine deliberately does not solve |
| **And64InlineHook** | An older, very small AArch64 hooker. Its `adrp`/`adr`/`b`/`ldr`-literal fixups are the same cases README §3.5.3 enumerates |
| **LLVM binutils** (`llvm-objdump`, `llvm-readelf`, `llvm-nm`) | Ship with the NDK. Every static measurement in this chapter used them |
| **Ghidra / IDA** | For recognising an already-hooked prologue in a memory dump — see README §6.3 |

---

## 5. Literature and background

| Source | Why |
|---|---|
| **Detours** (Microsoft Research technical report) | The original systematic treatment of trampoline hooking. x86, and decades old, but the taxonomy — target, trampoline, detour — is the vocabulary everything since uses |
| **Dynamic binary instrumentation literature** (Pin, DynamoRIO, Valgrind design papers) | The other end of the same spectrum: instead of patching individual functions, translate the whole program. Explains the trade-off — DBI never has a relocation problem because it never leaves an instruction where it found it |
| **PLT/GOT hooking write-ups for Android** | The technique README §3.6 implements directly from the ELF structures. Reading one alongside `examples/plt-got-hook.c` is the fastest way to confirm the mechanism is not library-specific |
| **Xposed framework design notes** | The historical `hookMethodNative` approach — copy the `ArtMethod`, set `kAccNative`, redirect the entry to a single generic dispatcher, and set `kAccCompileDontBother` so the JIT does not overwrite it. **[64-Xposed](../../64-Xposed/README.md)** owns it in full: the `app_process` replacement and why it needed no injection technique at all, `XposedBridge.jar` on the boot class path, the Dalvik `nativeFunc` ancestor, the module format, the EdXposed/Riru interlude, the five forces that ended it, and — measured across 237 real APKs — the **detection surface that outlived the framework**. The one-line summary remains in [13-ART](../../13-ART/README.md)'s framework table |
| **LSPosed** | The modern Zygisk-based successor: the same entry-point replacement, injected into Zygote so it applies to every process. **[63-LSPosed](../../63-LSPosed/README.md)** owns it in full — the Zygisk callbacks LSPosed actually uses, the `XposedBridge` API surface, per-application scope, LSPlant's **backup method** (the managed-layer counterpart of this chapter's trampoline, §3.10 there), module development end to end, and a measured account of what a detector can and cannot see. See [62-Magisk](../../62-Magisk/README.md) for the injection half |

---

## 6. OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-RESILIENCE-1** | Anti-tampering — the control an inline hook is aimed at, and the one a self-checksum implements |
| **MASVS-RESILIENCE-2** | Anti-debugging and runtime integrity |
| **MASVS-RESILIENCE-3** | Detecting and responding to an instrumented environment |
| **MASVS-RESILIENCE-4** | Obfuscation — raises the cost of *target selection*, not of *mechanism* |
| **MASVS-CRYPTO-2** | Key management. Hooking demonstrates the gap between "the key cannot be extracted" and "the key cannot be misused" |
| **MASTG** — Android anti-reversing test procedures | Where hooking is the tool rather than the subject |

> The MASVS-RESILIENCE family is explicitly scoped to threat models that include a **compromised
> device**, and is explicitly *additive* to the other control families rather than a substitute for
> them. Reporting "this app can be hooked" against an app with no resilience requirement is noise.
> Report what the hook proved.

---

## 7. Files in this chapter

| File | What it is |
|---|---|
| [`../README.md`](../README.md) | The chapter |
| [`../cheatsheet.md`](../cheatsheet.md) | Hook-type table with prerequisites, detectability and failure modes; verified arm64 encodings; measured facts |
| [`../mindmap.md`](../mindmap.md) | The whole chapter as one map, plus a decision flowchart |
| [`../faq.md`](../faq.md) | Twenty questions, including "what IS a hook" and "why do I need root" |
| [`../examples/libguard.c`](../examples/libguard.c) | The hook target. Its prologue's third instruction is an `adrp`, which is the point |
| [`../examples/trampoline-hook.c`](../examples/trampoline-hook.c) | **The chapter's spine.** A complete hand-written inline hook with `adrp` relocation, no Frida, no root |
| [`../examples/plt-got-hook.c`](../examples/plt-got-hook.c) | PLT/GOT slot swap, walking `DT_JMPREL` directly |
| [`../examples/libinline.c`](../examples/libinline.c) | A target whose check function is exported *and* inlined away |
| [`../examples/hook-that-fails.c`](../examples/hook-that-fails.c) | A correct hook on a function nobody calls, and the fix |
| [`../examples/build-hook-fixtures.sh`](../examples/build-hook-fixtures.sh) | Builds everything outside the repository; `--run` pushes and executes |
| [`../scripts/hookability.py`](../scripts/hookability.py) | Static hook-point analyser: room, PC-relative instructions, branches into the patch region, caller count |
| [`../scripts/hook-surface.sh`](../scripts/hook-surface.sh) | Inventory of a library's hookable surface: imports, RELRO, exports, JNI, anti-tamper leads |
| [`../scripts/layer-compare.js`](../scripts/layer-compare.js) | Frida harness applying the same interception at four layers side by side. **Not executed** — the device had no `frida-server`; its header says so |
| [`../labs/lab-01-the-five-hook-types.md`](../labs/lab-01-the-five-hook-types.md) | Taxonomy made concrete |
| [`../labs/lab-02-write-an-inline-hook-by-hand.md`](../labs/lab-02-write-an-inline-hook-by-hand.md) | The spine, as a lab |
| [`../labs/lab-03-where-hooks-fail.md`](../labs/lab-03-where-hooks-fail.md) | Four correct hooks that accomplish nothing |
| [`../labs/lab-04-ctf-the-honest-trampoline.md`](../labs/lab-04-ctf-the-honest-trampoline.md) | CTF: three layered defences, one hook type that walks past all of them |
| [`../labs/libvault.c`](../labs/libvault.c) | The CTF target (contains instructor notes) |
| [`../labs/vault-runner.c`](../labs/vault-runner.c) | The CTF harness |
| [`../labs/build-ctf.sh`](../labs/build-ctf.sh) | Builds the CTF outside the repository |

---

## 8. Related chapters

| Chapter | Relationship to hooking |
|---|---|
| [01-Computer-Science-Basics](../../01-Computer-Science-Basics/README.md) | Calling conventions, stack frames and function calls from first principles. This chapter is where that material is put to work |
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | The six-layer `stat` example: every layer is a place you could intervene, and choosing among them is this chapter's skill |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | Where the managed layer sits in the process |
| [13-ART](../../13-ART/README.md) | **Owns** `ArtMethod` and `entry_point_from_quick_compiled_code_`. Points here for native inline hooking. Its four-cause table for hook failure is cited, not restaged |
| [15-Native-Code](../../15-Native-Code/README.md) | Building the `.so` you will hook, and shipping sources rather than binaries |
| [16-JNI](../../16-JNI/README.md) | **Owns** `RegisterNatives` and the JNI method table — hook type 5 |
| [17-Libraries](../../17-Libraries/README.md) | `.init_array` ordering, measured. The source of the timing problem |
| [18-ARM](../../18-ARM/README.md) | **Owns** the instruction set and every verified patch encoding. §5.4's "a patch that provably works, against a function that provably no longer matters" is the same finding this chapter's Lab 03 restages for hooks |
| [19-Memory](../../19-Memory/README.md) | Page permissions, mappings, and what `mprotect` actually changes |
| [37-RootDetection](../../37-RootDetection/README.md) | The most commonly hooked thing on Android |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Self-integrity checks — what they cost an attacker, and why the CTF's checksum is beatable |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Attacks target selection, not mechanism |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Finding the hook point before you install the hook |
| [53-Frida](../../53-Frida/README.md) | **Owns** Frida as a tool. This chapter owns what it is doing underneath, and deliberately does not depend on it |
| [57-Ghidra](../../57-Ghidra/README.md) | "What you do with an address once you have found it" — this chapter is the answer |
| [62-Magisk](../../62-Magisk/README.md) | Zygisk: the Android replacement for `LD_PRELOAD`, and `hookJniNativeMethods()` |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | **Owns** anti-hooking detection and its defeat. This chapter owns the mechanism; that one owns the arms race |
| [63-LSPosed](../../63-LSPosed/README.md) | The managed-layer hooking framework in current use. Its §3.10 draws the symmetry that is the best single cross-reference from this chapter: an inline hook needs a **trampoline** because the function's first bytes were overwritten; a managed hook needs a **backup method** because the method's dispatch slot was — *if you want to call through, you must keep a copy of what you destroyed* |
| [64-Xposed](../../64-Xposed/README.md) | The historical framework: the `app_process` replacement, `hookMethodNative`, and why classic Xposed is the one framework in this family that needed **none** of this chapter's five hook types to get its code into a process — it replaced the program instead. Its §2.4 maps that contrast onto §3.17's taxonomy |
| [66-Instrumentation](../../66-Instrumentation/README.md) | The platform's own supported way to get code into a process: a test APK whose `<instrumentation targetPackage>` names the victim, delivered by `am instrument`, running at the target's UID before its `Application.onCreate()`. It **measured** that the gate is the signing relationship and not `android:debuggable`, contrary to the usual claim. The cleanest way to state the boundary is that hooking changes what a **method does** while instrumentation changes what the **process contains** — so a stored decision falls to 66 with three lines of reflection, and a recomputed one needs this chapter's machinery. They compose: 66 is a delivery vehicle that can load a `.so` and then use everything here |
