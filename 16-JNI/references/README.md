# 16 — JNI · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure.

---

## 1. The normative specification

JNI is a **Java platform specification**, not an Android one. When an Android document and the JNI
specification disagree about mangling, descriptors, the function table order, or the reference rules,
**the specification is authoritative** and Android implements it.

| Document | Open it when |
|---|---|
| **Java Native Interface Specification** — *Design Overview* | You want the rationale: why `JNIEnv` is per thread, why references are indirect, why the API looks the way it does |
| **JNI Specification** — *Types and Data Structures* | You need the exact type descriptor grammar, the `jvalue` union, or the primitive type mapping |
| **JNI Specification** — *JNI Functions* | The definitive list, **in order**, of every function in `JNINativeInterface`. This is the ground truth behind the index table in [`../cheatsheet.md`](../cheatsheet.md) §12 |
| **JNI Specification** — *Resolving Native Method Names* | The mangling scheme: the `Java_` prefix, the escape table, the short/long name rule. Everything in [§3.5](../README.md#35-name-mangling--the-complete-rules) is checkable here |
| **JNI Specification** — *Exceptions* | The list of functions that are legal while an exception is pending — the whole recovery vocabulary |
| **JNI Specification** — *Local and Global References* | The 16-reference guarantee, `EnsureLocalCapacity`, `PushLocalFrame`/`PopLocalFrame` semantics |
| **The Java Virtual Machine Specification, Chapter 4** | The descriptor grammar JNI reuses. Read it if you want the formal production rules rather than the table |

Published by Oracle as part of the Java SE documentation set. Search for "Java Native Interface
Specification" plus the chapter name rather than for a URL — the hosting path has moved several times
and will move again.

> **Why this matters more than it looks.** The mangling and descriptor rules are the two things this
> chapter's readers most often get subtly wrong, and they are the two things the specification states
> exactly. If you are about to put a symbol name in a report, check it here rather than against a
> blog post.

---

## 2. Official Android documentation

| Document | Open it when |
|---|---|
| **JNI tips** (Android developer guide) | The single most useful Android-specific page. Covers `JNIEnv` per thread, local versus global references, thread attachment, `extractNativeLibs`, UTF-8 versus modified UTF-8, and a FAQ that answers most `UnsatisfiedLinkError` questions |
| **NDK guides — ABI management** | Which ABIs exist, what ships, and why an app with only `arm64-v8a` will not run on your x86 emulator |
| **NDK guides — CMake / ndk-build** | Building the examples in [`../examples/`](../examples/README.md) |
| **`javac -h`** (JDK tool documentation) | Generating JNI headers, and the ground truth for what a symbol should be called. The modern replacement for `javah` |
| **Android Studio — Debug your native code** | LLDB attachment for [§7.7](../README.md#77-strace-ltrace-logcat-and-lldb) |
| **Application Sandbox** (Android security docs) | Why the JNI boundary is *not* a privilege boundary — the point of [§5.1](../README.md#51-the-thesis-stated-exactly) |

---

## 3. AOSP source

Read on [cs.android.com](https://cs.android.com/), which gives cross-references and history. See
[07 AOSP](../../07-AOSP/README.md) for the navigation technique.

> Cite **paths**, never line numbers. The paths below have been stable for years; line numbers change
> every release, and a report that quotes one ages badly.

### The files that matter most

| Path | Open it when |
|---|---|
| `art/runtime/jni/jni_internal.cc` | You want to know what a `JNIEnv` function *actually does* — every one of the ~230 is implemented here. **The single most important file in this chapter.** |
| `art/runtime/jni/java_vm_ext.cc` | Library loading, the loaded-library table keyed by ClassLoader, and `FindCodeForNativeMethod` — the `dlsym` lookup behind static registration |
| `art/runtime/jni/check_jni.cc` | You met a CheckJNI abort and want to know precisely which rule fired and what else it checks |
| `art/runtime/art_method.cc`, `.h` | `JniShortName()` and `JniLongName()` — ART's own mangling — plus `RegisterNative`/`UnregisterNative` |
| `art/runtime/jni/jni_env_ext.h`, `.cc` | What a `JNIEnv*` really points at on ART: the function-table pointer first, then per-thread state |

### Reference tables and the runtime

| Path | Covers |
|---|---|
| `art/runtime/indirect_reference_table.h`, `.cc` | Global and weak-global tables, and the handle encoding that makes a `jobject` not an address |
| `art/runtime/jni/local_reference_table.h` | The dedicated local reference table on recent releases |
| `art/runtime/entrypoints/quick/quick_trampoline_entrypoints.cc` | The generic JNI trampoline: the transition described in [§3.22](../README.md#322-the-managed-to-native-transition-inside-art) |
| `art/runtime/jni_id_type.h` | Why a `jmethodID` is usually an `ArtMethod*` and when it is not |
| `art/runtime/native/java_lang_Runtime.cc` | The native side of `Runtime.nativeLoad` |

### The Java side

| Path | Covers |
|---|---|
| `libcore/ojluni/src/main/java/java/lang/System.java` | `loadLibrary`, `load`, `mapLibraryName` |
| `libcore/ojluni/src/main/java/java/lang/Runtime.java` | `loadLibrary0` — the ClassLoader association and the path search |

### Helpers every framework native uses

| Path | Covers |
|---|---|
| `libnativehelper/include_jni/jni.h` | AOSP's copy of the JNI header — the authoritative `JNINativeInterface` field order for the platform you are testing |
| `libnativehelper/include/nativehelper/JNIHelp.h` | `jniThrowException`, `jniRegisterNativeMethods` |
| `libnativehelper/include/nativehelper/ScopedLocalRef.h` | The RAII local-reference wrapper. **Name this in a remediation** for platform C++ code |
| `libnativehelper/include/nativehelper/ScopedUtfChars.h` | The RAII string wrapper — release on every path, including error paths |
| `libnativehelper/include/nativehelper/ScopedPrimitiveArray.h` | `ScopedByteArrayRO` and friends |
| `system/core/libnativeloader/` | The linker-namespace policy applied to app `dlopen`, i.e. the API-24+ restrictions |
| `bionic/linker/` | The dynamic linker itself. Chapter 15 (`15-Native-Code/`) owns this |

---

## 4. OWASP

| Identifier | Why it applies |
|---|---|
| **MASVS-CODE-4** — input validation | The core control for [§5.2](../README.md#52-vulnerability-class-1--the-java-check-that-the-native-code-does-not-honour) and [§5.6](../README.md#56-vulnerability-class-5--string-length-confusion). Validation must happen where the data is *used*, in native code |
| **MASVS-CODE-2** — up-to-date third-party components | Bundled `.so` files are the least-audited dependency in most apps |
| **MASVS-CODE-3** — build hardening | Canaries, RELRO, PIE, fortify. Owned by chapter 15's checklist; it is what stands between an overflow and code execution |
| **MASVS-RESILIENCE-2/-3/-4** — anti-tampering, anti-hooking, obfuscation | Why native code exists in many apps, and why `RegisterNatives` is used |
| **MASVS-STORAGE-1/-2** — sensitive data | Secrets moved into native code are still in memory at the JNI boundary |
| **MASTG** — *Testing for Memory Corruption Bugs (Android)* | The direct procedure for [§5.2](../README.md#52-vulnerability-class-1--the-java-check-that-the-native-code-does-not-honour) through [§5.6](../README.md#56-vulnerability-class-5--string-length-confusion) |
| **MASTG** — *Make Sure That Free Security Features Are Activated* | The native hardening check |
| **MASTG** — reverse engineering native code; dynamic analysis | The techniques in [§6](../README.md#6-reverse-engineering-perspective) and [§7](../README.md#7-dynamic-analysis) |

Chapter [71 OWASP-Mobile](../../71-OWASP-Mobile/README.md) holds the full mapping.

---

## 5. Tools

| Tool | Use it for |
|---|---|
| **Frida** (<https://frida.re>) | Everything in [§7](../README.md#7-dynamic-analysis). The docs' *JavaScript API* page is the reference for `Interceptor`, `Module` and `Java.vm` |
| **Ghidra** (<https://ghidra-sre.org>) | Decompiling the recovered functions. Chapter [57](../../57-Ghidra/README.md) is the workflow |
| **JNIAnalyzer** (<https://github.com/Ayrx/JNIAnalyzer>) | A prepared Ghidra type archive (`jni_all.gdt`) containing `JNIEnv`, `JNINativeInterface`, `JNINativeMethod` and the rest. The fastest route to a readable decompilation |
| **jadx** (<https://github.com/skylot/jadx>) | Reading the Java side: which methods are `native`, and their signatures |
| **apktool** (<https://apktool.org>) | Smali, for harvesting descriptors and spotting `@CriticalNative` annotations |
| **binutils / LLVM** `nm`, `readelf`, `strings`, `objdump` | The static enumeration in [§8.4](../README.md#84-from-the-shared-object). On a Mac use `gnm`/`gstrings`, or the NDK's `llvm-*` |
| **The Android NDK** | `jni.h` itself, and the cross-compilers for [`../examples/`](../examples/README.md) |

---

## 6. Talks and research

Search by topic rather than by URL — conference hosting moves, and a dead link in a reference list is
worse than no link.

- **Native code reverse engineering on Android** — Black Hat and DEF CON mobile tracks have covered
  `RegisterNatives` recovery, packer unpacking, and JNI-level hooking repeatedly.
- **Frida internals and the Java/native bridge** — the maintainers' own talks are the best source.
- **Android media-stack memory safety** (the Stagefright family and its successors) — the canonical
  worked example of *managed code as a thin transport for attacker bytes into a native parser*. Note
  that these are bugs in the parsers, not in JNI; see the honesty note below.
- **Rust in the Android platform** — Google's own writing on native memory-safety defect rates is the
  best available data on why this chapter's bug classes matter at scale.

> **A deliberate omission: there are no JNI-specific CVE identifiers in this chapter.** When a
> memory-safety bug is found in native Android code, the CVE is filed against the *component* — a
> media parser, an image decoder, a font shaper — not against the bridge. The bridge is how the
> untrusted data reached the vulnerable parser; it is not the vulnerable code. Quoting a CVE as "a
> JNI vulnerability" would be inaccurate, and this repository does not invent or misattribute
> identifiers. For third-party `.so` files, cite the CVEs published against *that library and
> version*, from its own advisory — a citation you can defend. See
> [§5.10](../README.md#510-real-vulnerabilities-honestly-described).

---

## 7. This chapter's own artefacts

| File | What it does |
|---|---|
| [`../scripts/jni_mangle.py`](../scripts/jni_mangle.py) | Mangle, demangle, parse descriptors, and print the `args[]` layout. `--selftest` runs the README's worked examples |
| [`../scripts/dump-registernatives.js`](../scripts/dump-registernatives.js) | Recover dynamically registered natives at runtime: name, signature, module+offset |
| [`../scripts/jni-arg-tracer.js`](../scripts/jni-arg-tracer.js) | Hook by symbol or module+offset and decode arguments from a signature |
| [`../scripts/jni-triage.sh`](../scripts/jni-triage.sh) | The whole of [§8.5](../README.md#85-a-complete-triage-sequence) as one command, ending in the static/dynamic diff |
| [`../examples/README.md`](../examples/README.md) | Build instructions for all five graded examples |
| [`../cheatsheet.md`](../cheatsheet.md) | Every table, including the complete 233-entry `JNINativeInterface` index |
| [`../faq.md`](../faq.md) | Twenty-three questions, including the ones people do not like to ask |

---

## 8. Related chapters

| Chapter | Relationship |
|---|---|
| `15-Native-Code/` | The ELF container, sections, symbols, relocations and the native hardening checklist — the box this chapter's functions ship in. Read alongside |
| [13-ART](../../13-ART/README.md) | `ArtMethod`, entry points, and the runtime side of the reference tables. Its §3.23 is this chapter seen from the runtime |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | `ACC_NATIVE`, `encoded_method` with `code_off = 0`, and the MUTF-8 decoder |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | `load` / `loadLibrary` in the ClassLoader model |
| [17-Libraries](../../17-Libraries/README.md) | Packaging, ABI splits, `extractNativeLibs`, linker namespaces, third-party SDK fingerprinting |
| [04-Java](../../04-Java/README.md) | Reflection — the mechanism that bypasses the Java-side wrapper |
| [03-Programming-Fundamentals](../../03-Programming-Fundamentals/README.md) | Pointers, buffers, integer overflow, and what memory safety means |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | Why "it is in native code" is not a privilege boundary |
| [34-Cryptography](../../34-Cryptography/README.md) | The keys that materialise in the clear at this boundary |
| [37-RootDetection](../../37-RootDetection/README.md) | A working `RegisterNatives` root check in `examples/native_root_check.c`, and native checks generally |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Anti-analysis that runs inside `JNI_OnLoad`, before any app code |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Why the JNI boundary is plaintext, and packers that stage libraries at runtime |
| [49-KeyStore](../../49-KeyStore/README.md) | The correct place for a secret, as opposed to a `.so` |
| [53-Frida](../../53-Frida/README.md) | The instrumentation API. This chapter supplies the model that makes a native hook readable |
| [57-Ghidra](../../57-Ghidra/README.md) | Retyping `JNIEnv` and recovering registration tables in the decompiler. Its §3.8 tells readers to read this chapter first |
| [65-Hooking](../../65-Hooking/README.md) | Hooking from first principles across the managed and native layers |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | Defeating the checks that live behind this bridge |
