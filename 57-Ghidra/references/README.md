# 57 — Ghidra · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

---

## Ghidra — official

| Link | Open it when |
|---|---|
| https://ghidra-sre.org/ | Project home page; feature overview and the cheat sheet |
| https://github.com/NationalSecurityAgency/ghidra | Source, issue tracker, and the discussions where developers answer behaviour questions |
| https://github.com/NationalSecurityAgency/ghidra/releases | The builds. **Check which JDK version each release requires before downloading** |
| https://ghidra.re/ghidra_docs/api/ | **The Program API Javadoc.** The reference for every script you write. Bookmark `ghidra.program.model.listing.Function` and `ghidra.program.model.symbol.SymbolTable` |
| https://ghidra.re/courses/ | The official course material, with exercises. Genuinely good, and free |
| https://ghidra-sre.org/CheatSheet.html | Keyboard shortcuts. Print it |
| https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs | In-tree documentation, including the SLEIGH language reference |
| https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs/GhidraClass | The slide decks from the official training, including the advanced scripting class |

---

## Ghidra internals — worth reading, not just linking

Reading a little of this is what turns "the decompiler said so" into "I know why it said so".

| Path in the source tree | What it explains |
|---|---|
| `Ghidra/Features/Decompiler/src/decompile/cpp/` | The decompiler itself, in C++. Start with `funcdata.cc` (the per-function state), `ruleaction.cc` (the simplification rules that turn P-Code into C-like expressions) and `typeop.cc` |
| `Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc` | The ordered list of transformation passes — effectively the decompiler's pipeline written down |
| `Ghidra/Processors/AARCH64/data/languages/AARCH64*.sinc` | The SLEIGH specification for ARM64. Read the definition of one instruction and P-Code stops being abstract |
| `Ghidra/Processors/ARM/data/languages/` | The 32-bit ARM and Thumb specifications, relevant for `armeabi-v7a` targets |
| `Ghidra/Framework/SoftwareModeling/` | The program model: `Function`, `Symbol`, `DataType`, `Listing`, `Memory` — the classes your scripts manipulate |
| `Ghidra/Features/Base/ghidra_scripts/` | Bundled example scripts. The fastest way to learn the API is to read `ExportFunctionInfoScript.java` and `FindPotentialDecompilerProblemsScript.java` before writing your own |
| `Ghidra/Features/VersionTracking/` | The binary-diffing machinery, and its correlator implementations |
| `Ghidra/Features/FileFormats/` | The loaders, including the ELF loader that decides your image base and processor |

---

## JNI — the specification you are reading against

| Link | Covers |
|---|---|
| https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/jniTOC.html | **The JNI specification.** The authoritative source for the order of `JNINativeInterface`, which is what makes the offset table in §3.8 stable |
| https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html | Every JNI function with its exact signature — what you need when setting a function signature by hand |
| https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/types.html | Type signature encoding (`[B`, `Ljava/lang/String;`, `(Ljava/lang/String;I)Z`) |
| https://developer.android.com/training/articles/perf-jni | Android's JNI rules: local versus global references, threading, `RegisterNatives`, and the mistakes that abort the process |
| https://github.com/Ayrx/JNIAnalyzer | **Publishes `jni_all.gdt`** — the prepared Ghidra type archive that solves the `JNIEnv` problem in thirty seconds. Also ships a Ghidra script that applies JNI types and attempts registration recovery |

---

## Android native code

| Link | Covers |
|---|---|
| https://developer.android.com/ndk/guides | NDK guides — build system, ABI management, C++ library selection |
| https://developer.android.com/ndk/guides/abis | The ABI table. Which `lib/<abi>/` directory names exist and which devices load which |
| https://developer.android.com/guide/topics/manifest/application-element#extractNativeLibs | What `extractNativeLibs="false"` actually changes (where the library lives, not whether it is readable) |
| https://developer.android.com/ndk/guides/stable_apis | Which system libraries an NDK build may link against — narrows the set of imports you will see |
| https://source.android.com/docs/core/architecture/vndk | Vendor NDK, relevant when analysing system libraries rather than app libraries |

---

## AOSP — the runtime side of what you are decompiling

Read these on [cs.android.com](https://cs.android.com/); see [07-AOSP](../../07-AOSP/README.md) for the
navigation technique.

| Path | Open it when |
|---|---|
| `art/runtime/jni/jni_internal.cc` | You want the implementation behind a `JNIEnv` function — including `RegisterNatives`, `FindClass` and `GetStringUTFChars`. **The C++ behind the table Ghidra shows you** |
| `art/runtime/java_vm_ext.cc` | You need the library-loading path: how `JNI_OnLoad` is found and invoked, and how `JavaVM` is handed out |
| `libnativehelper/include_jni/jni.h` | **Android's own `jni.h`.** The definitive `JNINativeInterface` field order for the platform — verify offsets against this rather than against a desktop JDK |
| `art/runtime/native_bridge_art_interface.cc` | The native bridge, for targets whose ABI does not match the device |
| `art/runtime/art_method.cc` | How ART resolves a `native` method to its implementation, statically or dynamically |
| `bionic/linker/linker.cpp` | How a `.so` is loaded, relocated, and initialised — including when `.init_array` runs |
| `bionic/linker/linker_soinfo.cpp` | `soinfo`, the linker's per-library structure. Relevant when you dump a library from memory and need its real base |
| `bionic/linker/linker_namespaces.cpp` | Linker namespaces — why an app cannot `dlopen` an arbitrary path |

---

## ELF, ARM, and the ABI

| Link | Covers |
|---|---|
| https://refspecs.linuxfoundation.org/elf/elf.pdf | The ELF specification: section headers, program headers, the dynamic table, symbol tables |
| https://github.com/ARM-software/abi-aa | The ARM ABI documents. **AAPCS64 is the calling convention Ghidra assumes** — read it when parameters appear in the wrong places |
| https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst | ELF for AArch64: relocation types, which matters when you dump from memory |
| https://developer.arm.com/documentation/ddi0487/latest | The ARM Architecture Reference Manual — the authority when Ghidra's disassembly surprises you |
| https://developer.arm.com/documentation/den0024/latest | ARM Cortex-A programmer's guide — a readable introduction to AArch64 before tackling the ARM ARM |
| https://developer.arm.com/documentation/102374/latest | AArch64 instruction set overview, short and practical |

---

## OWASP

| Identifier | Relevance |
|---|---|
| MASVS-CODE | Code quality and binary protections — the control group a "hard-coded key in a native library" finding maps to |
| MASVS-RESILIENCE | Anti-tampering, obfuscation and integrity. The standard against which "the app is obfuscated" is judged, and the reason "we obfuscated it" is not a control |
| https://mas.owasp.org/MASTG/techniques/android/ | The Android technique catalogue, including native reverse engineering procedures |
| https://mas.owasp.org/MASTG/ | The testing guide |
| https://mas.owasp.org/MASVS/ | The verification standard |

Cite MASVS identifiers in findings. "The library contains an embedded HMAC key" is an observation;
mapping it to a control makes it something a programme can track, prioritise and close.

---

## Community tooling

| Project | What it gives you | Note |
|---|---|---|
| `Ayrx/JNIAnalyzer` | `jni_all.gdt` plus a script that applies JNI types automatically | The single most useful third-party addition for Android work |
| `mandiant/Ghidrathon` | Run CPython 3 scripts in Ghidra instead of Jython 2.7 | Unlocks the modern Python ecosystem — `capstone`, `requests`, `yara` — inside your analysis |
| `GhidraJupyter/ghidra-jupyter-kotlin` | Drive a Ghidra project from a Jupyter notebook | Excellent for exploratory analysis where you iterate on a query |
| Ghidra Server (bundled) | Multi-user shared projects | For a team analysing one large binary together |
| `cyberkaida/reverse-engineering-assistant` | LLM-assisted analysis over a Ghidra project | Treat output as hypotheses; the caveats in §10 apply doubly |
| Lighthouse-style coverage loaders | Import runtime coverage and colour executed functions | Pair with [53-Frida §7.9](../../53-Frida/README.md#79-stalker-in-practice-when-instruction-level-tracing-is-worth-it) — coverage tells you *which* functions to read |
| `NationalSecurityAgency/ghidra` `ghidra_scripts` | The bundled scripts | Read before writing your own; several do most of what you need |

> **A word on third-party scripts.** A Ghidra script runs with your user's privileges and full
> filesystem access. Read it before running it, the same way you would read a shell script you found
> online.

---

## Related chapters in this repository

### Prerequisites

| Chapter | Why |
|---|---|
| [15-Native-Code](../../15-Native-Code/README.md) | ELF structure, symbols, relocations, sections — what Ghidra's loader reads and what `readelf` tells you |
| [16-JNI](../../16-JNI/README.md) | The `JNIEnv` model, static and dynamic registration, and the calling convention. **Read before §3.8** |
| [17-Libraries](../../17-Libraries/README.md) | `dlopen`, linker namespaces, `.init_array`, and how a library actually gets into a process |
| [18-ARM](../../18-ARM/README.md) | The instruction set you will read, and AAPCS64 |
| [19-Memory](../../19-Memory/README.md) | Page protections and `/proc/<pid>/maps` — how you find the runtime base |
| [68-ReverseEngineering](../../68-ReverseEngineering/README.md) | The discipline this chapter is one tool within |

### Companions

| Chapter | Why |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | Where `lib/<abi>/` sits and what `extractNativeLibs` changes |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The Java half of the boundary, and where `native` declarations live |
| [40-Obfuscation](../../40-Obfuscation/README.md) | String encryption, control-flow flattening, packers — exactly what degrades decompiler output |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | The other half of the loop |
| [53-Frida](../../53-Frida/README.md) | **The tool you pair with Ghidra.** §7.4 for recovering dynamic JNI at runtime, §7.8 for calling a function you found, §7.9 for coverage that tells you which functions to read |
| [56-JADX](../../56-JADX/README.md) | Where you find the `native` declarations that tell you what to look for |
| [58-IDA](../../58-IDA/README.md) | The commercial alternative, and when it is worth it |
| [59-radare2](../../59-radare2/README.md) | The command-line alternative, and when it is faster |
| [65-Hooking](../../65-Hooking/README.md) | What you do with an address once you have found it |
| [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) | The discipline where native RE is not optional |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | Memory-safety bug classes — what you are hunting once the code is readable |

---

## How to read a Ghidra problem

Not a link, but the most-used reference in this file.

| What you see | What it means |
|---|---|
| `FUN_00103a10` | Stripped binary, no name. Normal. Recover meaning from exports, strings and runtime |
| `undefined8 uVar1;` | No type inferred yet. Set the function signature |
| `(**(code **)(*(long *)param_1 + 0x548))(...)` | A JNI call with `JNIEnv` undefined. Define it |
| `__stack_chk_fail` | Stack protector. Ignore it |
| `halt_baddata()` | Ghidra disassembled data as code. Clear and re-examine the region |
| Instructions that look random | Wrong processor, wrong base, or ARM-vs-Thumb confusion. Re-import |
| `Decompilation failed: timeout` | Enormous, probably obfuscated function. Raise the timeout, or read the graph |
| `CONCAT44`, `SUB84`, `ZEXT48` | Ghidra modelling sub-register access. Usually a type problem you can fix |
| `in_x28`, `unaff_x19` | A register used without a visible definition — often a calling-convention mismatch |
| No `Java_*` in Exports | Dynamic registration. `RecoverRegisterNatives.py` |
| Analysis never finishes | Too little heap. `VMARGS=-Xmx8G` in `launch.properties` |
