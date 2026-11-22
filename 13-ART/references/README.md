# 13 — ART · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

---

## Primary source — AOSP

Read these on [cs.android.com](https://cs.android.com/), which gives you cross-references and history.
See [07-AOSP](../../07-AOSP/README.md) for the navigation technique.

### The files that matter most

| Path | Open it when |
|---|---|
| `art/runtime/art_method.h` | You need the exact `ArtMethod` field order for the release you are testing. **The single most important file in this chapter.** |
| `art/runtime/art_method.cc` | You want to see `SetEntryPointFromQuickCompiledCode` and how the runtime itself rewrites the hook target |
| `art/runtime/class_linker.cc` | You want `LinkCode` — the function that decides a method's initial entry point |
| `art/runtime/oat.h` | You are parsing an OAT header by hand, or need the current OAT version constant |
| `art/runtime/oat_file.h`, `oat_file.cc` | You need the OAT validation chain, or `OatDexFile`/`OatClass` layout |
| `art/runtime/vdex_file.h` | You are extracting DEX from a VDEX and need the section layout |
| `art/runtime/class_status.h` | You met a `ClassStatus` value in `oatdump` output and need its meaning |
| `art/runtime/instrumentation.h`, `.cc` | You are implementing or defeating deoptimization |
| `art/runtime/entrypoints/quick/quick_trampoline_entrypoints.cc` | You are classifying an entry point value and need to know what each trampoline does |

### Subsystems

| Path | Covers |
|---|---|
| `art/runtime/mirror/` | `Object`, `Class`, `String`, `Array` — the C++ views of managed objects |
| `art/runtime/mirror/object.h` | The object header: `klass_` and the multi-purpose `monitor_` word |
| `art/runtime/mirror/class.h` | vtable, IfTable, `methods_` array — what you walk to find an `ArtMethod` |
| `art/runtime/gc/heap.cc` | Heap construction and the space layout from §3.21 |
| `art/runtime/gc/collector/concurrent_copying.cc` | The default collector; read this to understand why objects move |
| `art/runtime/gc/space/` | `ImageSpace`, `RegionSpace`, `LargeObjectSpace`, `ZygoteSpace` |
| `art/runtime/jit/jit.cc` | JIT policy and hotness thresholds |
| `art/runtime/jit/jit_code_cache.cc` | The dual RW/RX mapping that satisfies W^X |
| `art/runtime/interpreter/` | Switch interpreter, `mterp`, `nterp` |
| `art/runtime/jni/jni_internal.cc` | The JNI function table implementation |
| `art/runtime/indirect_reference_table.h` | Local/global/weak reference tables — why `jobject` is not an address |
| `art/dex2oat/dex2oat.cc` | The AOT compiler driver and its command line |
| `art/compiler/optimizing/` | The optimizing compiler, including the inliner that breaks your hooks |
| `art/oatdump/oatdump.cc` | The tool you use constantly; reading it tells you what else it can print |
| `art/profman/profman.cc` | Profile format and manipulation |
| `art/libartservice/`, `art/artd/` | The Android 12+ ART Service that replaced much of `installd`'s role |
| `art/openjdkjvmti/` | JVMTI implementation — the basis of class redefinition |

### Framework side

| Path | Covers |
|---|---|
| `frameworks/base/services/core/java/com/android/server/art/` | `ArtManagerLocal` — how `PackageManagerService` requests dexopt |
| `frameworks/base/services/core/java/com/android/server/pm/dex/` | Dexopt policy and the reasons behind each compilation trigger |
| `libcore/` | The Java standard library implementation ART executes |

---

## Official documentation

| Resource | Why |
|---|---|
| [ART and Dalvik](https://source.android.com/docs/core/runtime) | The canonical overview; start here if you want Google's own framing |
| [Configuring ART](https://source.android.com/docs/core/runtime/configure) | Every `dalvik.vm.*` property and what it does |
| [Implementing the JIT compiler](https://source.android.com/docs/core/runtime/jit-compiler) | The JIT architecture and profile-guided compilation loop |
| [Dex format](https://source.android.com/docs/core/runtime/dex-format) | The DEX specification — cross-reference with [12-DEX-Internals](../../12-DEX-Internals/README.md) |
| [ART Mainline module](https://source.android.com/docs/core/ota/modular-system/art) | Why ART internals differ between devices on the same Android release |
| [Baseline Profiles](https://developer.android.com/topic/performance/baselineprofiles/overview) | The developer-facing side of profile-guided compilation |
| [App startup performance](https://developer.android.com/topic/performance/vitals/launch-time) | Useful context for why the compilation design is the way it is |
| [Android behaviour changes](https://developer.android.com/about/versions) | Check before asserting any version-dependent ART behaviour |

---

## Tooling

| Tool | Where | Use |
|---|---|---|
| `oatdump` | `/apex/com.android.art/bin/oatdump` | Dump OAT headers, per-method native code, VDEX, images; export DEX |
| `profman` | `/apex/com.android.art/bin/profman` | Dump and manipulate profiles |
| `dexdump`, `dexlist` | `/apex/com.android.art/bin/` | DEX inspection on-device |
| `dex2oat64` | `/apex/com.android.art/bin/` | The compiler itself; readable `--help` |
| [Frida](https://frida.re/docs/android/) | host + device | The tool that operationalises §3.17 |
| [Frida Java API](https://frida.re/docs/javascript-api/#java) | docs | `Java.use`, `Java.choose`, `Java.enumerateClassLoaders` |
| [jadx](https://github.com/skylot/jadx) | host | Decompile the DEX you extract from a VDEX |
| [baksmali/smali](https://github.com/google/smali) | host | Disassemble DEX when the decompiler fails |
| [vdexExtractor](https://github.com/anestisb/vdexExtractor) | host | Unquickening for Android 8–10 VDEX files |
| Memory Analyzer (MAT) | host | Analyse `.hprof` heap dumps after `hprof-conv` |

---

## Security research

| Resource | Why |
|---|---|
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Monthly. The authoritative record of runtime vulnerabilities. Read for the *pattern* of which subsystems recur |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | The highest-quality public research on Android runtime and JIT bugs |
| [Android VRP rules](https://bughunters.google.com/about/rules) | What Google considers a reportable runtime vulnerability, and the severity model |

> **Note on CVE citation.** This chapter deliberately describes runtime vulnerability *classes* rather
> than naming specific identifiers, because ART bugs are numerous and version-specific and a
> misattributed CVE in a client report is worse than no citation. When you need a specific reference,
> pull it from the bulletin for the affected release rather than from memory or a blog post.

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | MASVS-RESILIENCE covers anti-tampering and anti-hooking, which is where ART knowledge is applied |
| [MASTG](https://mas.owasp.org/MASTG/) | Reverse engineering and tampering techniques; the runtime-manipulation tests map directly onto §3.17 |
| MASTG test apps (UnCrackable series) | The canonical practice targets — see [80-Appendix](../../80-Appendix/README.md) |

---

## Books and long-form

| Work | Why |
|---|---|
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | The deepest published treatment of Android's low-level runtime; occasionally idiosyncratic, unmatched on detail |
| *Android Security Internals* — Nikolay Elenkov | Best structural account of the security model ART sits inside; dated in specifics |
| *The Garbage Collection Handbook* — Jones, Hosking, Moss | If you want to genuinely understand §3.21 rather than memorise it |
| *Virtual Machines* — Smith & Nair | The general theory behind interpretation, JIT and deoptimization |

---

## Conference talks worth finding

Search for these topics rather than specific URLs, since hosting moves:

- ART internals and hooking mechanics — Black Hat and DEF CON mobile tracks
- Android runtime exploitation — OffensiveCon
- Frida internals and the Java bridge — various; the maintainers' own talks are the best source
- Deoptimization and JIT security — academic venues (USENIX Security, NDSS)

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | The concept layer this chapter implements — read first |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The byte format ART consumes |
| [14-Dalvik](../../14-Dalvik/README.md) | The predecessor, and the full Smali reference |
| [16-JNI](../../16-JNI/README.md) | The native bridge behind §3.23 |
| [19-Memory](../../19-Memory/README.md) | Process memory layout, heap scanning, `/proc/<pid>/maps` |
| [22-SELinux](../../22-SELinux/README.md) | Why `dex2oat` running in its own domain is a real trust property |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Packers, and DEX dumping using the ClassLoader hooks from this chapter |
| [53-Frida](../../53-Frida/README.md) | The tool that operationalises §3.17 |
| [63-LSPosed](../../63-LSPosed/README.md) | Persistent hooking via the same entry-point mechanism |
| [65-Hooking](../../65-Hooking/README.md) | Hooking from first principles across managed and native layers |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Anti-hooking and anti-debug, all of which interact with ART's execution model |
