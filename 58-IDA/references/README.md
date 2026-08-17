# 58 — IDA · References

Annotated. Each row says **what the link is good for**, not just what it is.

> **Provenance.** The vendor pages below are the source of every documentation-derived claim in this
> chapter — the licensing tiers, the debugger server names and port, the microcode maturity levels,
> the IDAPython 9.0 removals, and the cloud/Lumina data statements. They were retrieved in **August
> 2026**. Product tiers and prices change; **re-check any row before quoting it at a purchasing
> decision.**
>
> IDA is **not installed** on the machine where this chapter was written. Nothing on these pages was
> exercised here. The chapter's opening callout lists exactly which claims are measured and which are
> documentation-derived.

---

## Hex-Rays — product and licensing

| Link | Open it when |
|---|---|
| <https://hex-rays.com/ida-pro> | You need the edition matrix: which disassemblers and how many decompilers each tier includes. **The source of the chapter's §1.3 table** |
| <https://hex-rays.com/ida-free> | Somebody tells you to "just use IDA Free" for Android. The limitations are stated in Hex-Rays' own words: x86 only, cloud decompiler, **no IDAPython** |
| <https://hex-rays.com/ida-home> | Evaluating the cheapest route to ARM-64. Note the cloud-decompiler statement |
| <https://hex-rays.com/decompiler> | The decompiler is a separate product. Which architectures exist, and what "twin" decompilers means |
| <https://hex-rays.com/faqs/what-is-hex-rays-change-of-licensing-model> | Why perpetual licences stopped at 9.0, if you hold an older one |
| <https://hex-rays.com/faqs/which-information-does-ida-share-with-cloud-services> | **Before you decompile a client's binary.** The statement quoted in §3.11 |

> **The single highest-value row in this table** is the third one, and the reason is in §3.11: IDA
> Home, IDA Classroom and **IDA Pro Essential** decompile in the cloud. Under a typical mobile NDA that
> is a contract question, not a security one, and it is the most expensive thing in this chapter to
> discover late.

---

## Hex-Rays — documentation

| Link | Open it when |
|---|---|
| <https://docs.hex-rays.com/> | The documentation hub. **Start here** — deep links move between major versions and 404 quietly |
| <https://docs.hex-rays.com/user-guide/debugger/remote-debugging> | Deploying `android_server`. The source of the server binary names, the default port **23946**, and the `-p`/`-i`/`-P`/`-v`/`-t`/`-K` options in §3.9 |
| <https://docs.hex-rays.com/core/debugger/tutorials/remote-debugging-with-ida-pro> | The same, as a walkthrough |
| <https://docs.hex-rays.com/core/decompiler> | The decompiler user guide, including the microcode view and how to move between maturity levels |
| <https://docs.hex-rays.com/core/decompiler/how-tos/microcode-view> | The microcode view specifically — `Ctrl+Shift+F8`, and the `>` / `<` navigation |
| <https://docs.hex-rays.com/9.1/getting-started/licensing> | Named, computer and floating licence mechanics; which server components need their own licence |
| <https://docs.hex-rays.com/release-notes/9_0> | What changed in 9.0. Read it before assuming any pre-9.0 workflow still applies |
| <https://docs.hex-rays.com/sitemap.md> | When a deep link 404s, which happens often. Faster than searching |

---

## Hex-Rays — the APIs

| Link | Open it when |
|---|---|
| <https://python.docs.hex-rays.com/> | **The IDAPython API reference.** The authority for every script in [`../scripts/`](../scripts/), and the thing to check before believing a snippet from a blog |
| <https://cpp.docs.hex-rays.com/> | The C++ SDK reference. `hexrays.hpp` is here, including the `mba_maturity_t` enum whose members §3.4 quotes |
| <https://docs.hex-rays.com/developer-guide/idapython/idapython-porting-guide-ida-9> | **Read before running any script written before 9.0.** `ida_struct` and `ida_enum` were removed; `get_inf_structure()` was removed |
| <https://hex-rays.com/blog/ida-9-0-sdk-idapython-porting-guides> | The same changes, with the reasoning |
| <https://docs.hex-rays.com/developer/idapython/idapython-getting-started> | Your first script. Shorter than it looks |
| <https://hex-rays.com/blog/> | Where new decompiler and microcode capabilities are explained first, usually with a worked example |
| <https://community.hex-rays.com/> | Where behaviour questions get answered, including the cloud-decompiler thread cited in §3.11 |

### The SDK headers worth reading

Not links — files, if you have a licence. Their reference pages are on `cpp.docs.hex-rays.com`.

| Header | Why |
|---|---|
| `hexrays.hpp` | The whole decompiler API: `mba_t`, `minsn_t`, `mop_t`, `cfunc_t`, `cinsn_t`, `cexpr_t`, `ctree_visitor_t`, `mba_maturity_t`. **The one header to read** if you intend to do anything beyond reading pseudocode |
| `netnode.hpp` | The storage primitive everything in the database is built from |
| `typeinf.hpp` | Types and prototypes — and, from 9.0, structures and enums |
| `funcs.hpp` | `func_t`, `FUNC_NORET`, function boundaries |
| `bytes.hpp` · `ua.hpp` · `xref.hpp` | Per-byte flags · one decoded instruction · cross-references |
| `loader.hpp` · `idp.hpp` · `dbg.hpp` | Loader · processor module · debugger interfaces |

---

## The free alternatives — read these before spending anything

| Link | Why |
|---|---|
| [57-Ghidra](../../57-Ghidra/README.md) | **The FOSS decompiler competitor, and the chapter this one is written against.** Free, local, scriptable, good ARM-64 decompilation. Its §3.16 lists honestly where IDA is better; this chapter honours that list rather than contradicting it |
| <https://ghidra-sre.org/> | Ghidra's home |
| <https://github.com/NationalSecurityAgency/ghidra/releases> | The builds. Note the JDK each release requires |
| <https://ghidra.re/ghidra_docs/api/> | Ghidra's Program API Javadoc — the counterpart to `python.docs.hex-rays.com` |
| [59-radare2](../../59-radare2/README.md) | Fast, scriptable, composable, zero cost, and it runs on the phone. The right tool for the triage step this chapter tells you to do first |
| <https://github.com/google/binexport> | BinExport — exports IDA **and Ghidra** databases into BinDiff's format |
| <https://github.com/joxeankoret/diaphora> | Diaphora — open-source binary diffing, IDA-specific, actively maintained |

---

## Binary diffing and patch analysis

| Link | Why |
|---|---|
| <https://www.zynamics.com/software.html> | BinDiff. Free, and the fastest route from "a patch exists" to "here is what it fixed" |
| <https://github.com/joxeankoret/diaphora> | Diaphora, when you want the diff inside IDA with decompiler-aware heuristics |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | The discipline this tooling serves, and the one place in this chapter where IDA's ecosystem has no free equivalent of the same maturity |

---

## JNI, ELF and ARM — the substrate under everything here

| Link | Covers |
|---|---|
| <https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/jniTOC.html> | The JNI specification. The mangling rules the demangler in [`../scripts/02-ida-android-annotate.py`](../scripts/02-ida-android-annotate.py) implements, and the fixed ordering of `JNINativeInterface` that makes an offset table valid across Android versions |
| <https://developer.android.com/training/articles/perf-jni> | Android's JNI rules: references, threading, and what native code must not do |
| <https://developer.android.com/ndk/guides> | NDK guides, including `extractNativeLibs` |
| <https://developer.android.com/ndk/guides/abis> | The ABI table. Which directory names exist and what each means |
| <https://refspecs.linuxfoundation.org/elf/elf.pdf> | The ELF specification — sections, segments, the dynamic table, relocations |
| <https://github.com/ARM-software/abi-aa> | **AAPCS64.** The calling convention every argument-recovery guess assumes. Read it once and a lot of decompiler behaviour stops being mysterious |
| <https://developer.arm.com/documentation/ddi0487/latest> | The ARM Architecture Reference Manual. The authority when a disassembly surprises you |
| <https://developer.arm.com/documentation/den0024/latest> | The Cortex-A programmer's guide — a readable introduction to AArch64 |

---

## AOSP

Paths, not links; browse them on <https://cs.android.com/>. See
[07-AOSP](../../07-AOSP/README.md) for the navigation technique. No line numbers are quoted anywhere in
this chapter — file paths are stable, line numbers are not.

| Path | Why |
|---|---|
| `libnativehelper/include_jni/jni.h` | **The header to parse into a type library.** `JNINativeInterface` in its specification-mandated order |
| `art/runtime/jni/jni_internal.cc` | The implementation of every `JNIEnv` function, including `RegisterNatives` |
| `art/runtime/java_vm_ext.cc` | Library loading and `JNI_OnLoad` invocation |
| `bionic/linker/linker.cpp` | Mapping, relocation and `.init_array` — what IDA seeds its analysis from |
| `bionic/linker/linker_soinfo.cpp` | `soinfo`, for a library dumped from memory whose headers you must rebuild |
| `bionic/libc/include/dlfcn.h` | `dlopen` and `dlsym` prototypes |

---

## OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-CODE** | Binary-level code quality and the mitigations chapter 15 checks for |
| **MASVS-RESILIENCE** | Anti-tampering, obfuscation, integrity, debugger and root detection. **The standard against which "the app is obfuscated" is judged** |
| **MASVS-CRYPTO** | Where a key recovered from a `.so` maps |
| **MASVS-STORAGE** | Where a native-derived key protecting local data lands |
| <https://mas.owasp.org/MASTG/techniques/android/> | The Android technique catalogue, including native reverse engineering |
| <https://mas.owasp.org/MASTG/> | The testing guide, with concrete procedures |

Cite the identifier in the finding. "The library contains an embedded HMAC key" is an observation;
mapping it to a control is what makes it something a programme can track and fix.

---

## This chapter's own files

| File | What it is | Executed? |
|---|---|---|
| [`../examples/01-session-target.c`](../examples/01-session-target.c) | The reversing target. Every construct is deliberate and documented in its header | Compiles clean under `-Wall -Wextra` |
| [`../examples/02-crcutil.c`](../examples/02-crcutil.c) · [`.h`](../examples/02-crcutil.h) | The static-archive half — the FLIRT target | Same |
| [`../examples/03-ground-truth-aarch64.md`](../examples/03-ground-truth-aarch64.md) | **The answer key.** Every measured listing, address, byte and count | n/a |
| [`../examples/build.sh`](../examples/build.sh) | Builds everything **out of tree** and regenerates the ground truth | **Executed** |
| [`../scripts/01-make-flirt-pat.py`](../scripts/01-make-flirt-pat.py) | FLAIR `.pat` generator from an `ar` archive or ELF object | **Executed.** CRC column structurally right, numerically unconfirmed |
| [`../scripts/02-ida-android-annotate.py`](../scripts/02-ida-android-annotate.py) | IDAPython: JNI naming, non-returning marking, import prototypes, indirect-call inventory, Frida offset map | **Reviewed, not executed.** Its pure-Python demangler *was* executed, 6/6 assertions |
| [`../scripts/03-ida-batch-triage.sh`](../scripts/03-ida-batch-triage.sh) | Portfolio sweep with two backends | llvm backend **executed**; IDA backend reviewed |
| [`../scripts/04-android-server-preflight.sh`](../scripts/04-android-server-preflight.sh) | Debugger preconditions, named separately so a failure identifies itself | Preflight **executed** on API 35; deploy reviewed |
| [`../labs/`](../labs/) | Four labs, the last a CTF. **All work without an IDA licence** | n/a |

---

## Related chapters

### Prerequisites

| Chapter | What it owns that this chapter assumes |
|---|---|
| [15-Native-Code](../../15-Native-Code/README.md) | ELF structure, `.dynsym` versus `.symtab`, relocations, what survives stripping |
| [16-JNI](../../16-JNI/README.md) | The `JNIEnv` model, registration, and the mangling rules |
| [17-Libraries](../../17-Libraries/README.md) | `dlopen`, linker namespaces, `.init_array` |
| [18-ARM](../../18-ARM/README.md) | **The disassembly.** Instruction encodings, AAPCS64, `adrp`/`movk`, the address arithmetic, and patching |
| [19-Memory](../../19-Memory/README.md) | `/proc/<pid>/maps` and page protections — how you find the runtime base |
| [57-Ghidra](../../57-Ghidra/README.md) | **The decompiler workflow.** P-Code, type propagation, `JNIEnv` retyping, `RegisterNatives` recovery, headless scripting |
| [68-ReverseEngineering](../../68-ReverseEngineering/README.md) | **The method.** The investigation loop, the evidence ladder, the residue. IDA is a Tier 3/Tier 4 instrument on that ladder |

### Companions

| Chapter | Why |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | Where `lib/<abi>/` sits and what `extractNativeLibs` changes |
| [22-SELinux](../../22-SELinux/README.md) | Why `setenforce 0` invalidates the thing you were measuring |
| [37-RootDetection](../../37-RootDetection/README.md) · [38-TamperDetection](../../38-TamperDetection/README.md) | What the checks you find in a `.so` actually are, with measured base rates — including that only 1 of 18 real APKs imports `ptrace`, and that a JDWP debugger does not set `TracerPid` |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What degrades the decompiler, and what a microcode plugin addresses |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) · [53-Frida](../../53-Frida/README.md) | The other half of the loop. 53 is the tool you pair with this one |
| [56-JADX](../../56-JADX/README.md) | The Java side, and the measured case where decompiled Java returns 100 while the bytecode returns 105 |
| [59-radare2](../../59-radare2/README.md) | The command-line alternative: fast triage, scripting, and it runs on the phone |
| [60-ADB](../../60-ADB/README.md) | `adb forward`, `run-as`, and why `shell` is not an app |
| [65-Hooking](../../65-Hooking/README.md) | What you do with an address once you have it, including GOT hooking — cheap here because this library's own calls are PLT-routed |
| [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) | Where native RE is not optional, and where §5.2's disposable-VM discipline is mandatory |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | Memory-safety bug classes and patch diffing |

---

## Ethics

Analyse binaries you wrote, applications you own, or targets you have written permission to examine.
Reverse engineering may be restricted by licence terms and by law in your jurisdiction independently of
your intent, and the fact that a technique is documented here is not authorisation. See
[00-Introduction](../../00-Introduction/README.md).

**This chapter will not link to, describe, or hint at licence circumvention, cracked builds, or key
generators for IDA or any other commercial tool.** The legitimate routes are IDA Free (x86 only), IDA
Home, IDA Classroom's educational licensing, a commercial IDA Pro plan, and
[Ghidra](../../57-Ghidra/README.md) — which for Android arm64 work is not a consolation prize but a
genuinely good tool that happens to cost nothing.
