# 40 — Obfuscation · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

---

## Primary source — AOSP

Read these on [cs.android.com](https://cs.android.com/), which gives cross-references and history. See
[07-AOSP](../../07-AOSP/README.md) for navigation technique.

### Class loading — where a packer's payload enters the runtime

| Path | Open it when |
|---|---|
| `libcore/dalvik/src/main/java/dalvik/system/BaseDexClassLoader.java` | You need `pathList` and `findClass` — the funnel every application class resolution passes through. **The most useful single file for unpacking work.** |
| `libcore/dalvik/src/main/java/dalvik/system/DexPathList.java` | You are reading a `ClassLoader.toString()` dump and need to interpret `dexElements` |
| `libcore/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java` | The constructor that takes plaintext DEX in a `ByteBuffer` — the modern packer's handover point |
| `libcore/dalvik/src/main/java/dalvik/system/DexClassLoader.java`, `PathClassLoader.java` | The classic loaders, and what `optimizedDirectory` actually does |
| `libcore/dalvik/src/main/java/dalvik/system/DexFile.java` | The Java/native boundary for DEX opening |
| `art/runtime/native/dalvik_system_DexFile.cc` | The JNI implementations behind the above; where to look when a Java-level hook is bypassed |
| `art/runtime/class_linker.cc` | `DefineClass` — the deepest "this class now exists" point in the runtime |

### DEX format — what your memory carver must satisfy

| Path | Open it when |
|---|---|
| `art/libdexfile/dex/dex_file.h` | The header layout, magic and version constants your validator checks |
| `art/libdexfile/dex/dex_file_loader.cc` | The runtime's own validation logic — a reference for what is *actually* enforced versus what the spec says |
| `art/libdexfile/dex/compact_dex_file.h` | You carved something starting `cdex` and need to know why `jadx` will not read it |
| `art/libdexfile/dex/dex_file_verifier.cc` | You are studying anti-tool tricks and want to know exactly how permissive the platform parser is |

### Framework — how a packer's stub gets control

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/app/ActivityThread.java` | `handleBindApplication` — where `<application android:name>` is instantiated |
| `frameworks/base/core/java/android/app/LoadedApk.java` | `makeApplication` and the `mClassLoader` field a packer replaces reflectively |
| `frameworks/base/core/java/android/app/ContextImpl.java` | The `mPackageInfo` field that leads to `LoadedApk` |
| `frameworks/base/core/java/android/app/Application.java` | `attach(Context)` — hidden, and called reflectively by every packer stub |
| `bionic/linker/linker.cpp` | How `.init_array` is executed during `dlopen`, and why it precedes `JNI_OnLoad` |

---

## Official documentation

| Resource | Why |
|---|---|
| [Shrink, obfuscate, and optimize your app](https://developer.android.com/build/shrink-code) | The developer-facing view of R8. Read it to understand what your target's build almost certainly did |
| [Keep rules and `-keep` syntax](https://developer.android.com/build/shrink-code#keep-code) | You are assessing coverage, which means assessing keep rules |
| [Dalvik Executable format](https://source.android.com/docs/core/runtime/dex-format) | The DEX specification. The header offsets your carver validates come from here |
| [Application Signing](https://source.android.com/docs/security/features/apksigning) | Needed the moment you repackage anything |
| [Restrictions on non-SDK interfaces](https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces) | Hidden-API enforcement from API 28 — why some reflective packer tricks stopped working |
| [ProGuard manual](https://www.guardsquare.com/manual/home) | The rules language, still the reference even for R8 |
| [R8 repository and release notes](https://r8.googlesource.com/r8) | Behaviour of `android.enableR8.fullMode` and the optimisations that make output confusing |
| [Android behaviour changes](https://developer.android.com/about/versions) | Check before asserting anything version-dependent in a report |

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | The standard your client's requirements are probably derived from |
| [MASVS-RESILIENCE](https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/) | The category obfuscation sits in. Note the framing: *resilience*, not *security* — that distinction is this chapter's whole argument, and it is in the standard |
| [MASTG](https://mas.owasp.org/MASTG/) | Test procedures |
| [MASTG Android reverse-engineering and tampering](https://mas.owasp.org/MASTG/techniques/android/) | Concrete techniques mapping onto §6 and §7 |
| MASTG UnCrackable series | Canonical practice targets. Levels 1–4 walk almost exactly the ladder in this chapter — see [80-Appendix](../../80-Appendix/README.md) |

---

## Tooling

| Tool | Where | Use |
|---|---|---|
| [jadx](https://github.com/skylot/jadx) | host | Primary decompiler. `--deobf` for illegal identifiers, `--show-bad-code` when it gives up, `-J-Xmx8g` for oversized methods |
| [apktool](https://apktool.org/) | host | Resource decoding, manifest, and Smali round-tripping for patching |
| [smali / baksmali](https://github.com/google/smali) | host | Far more tolerant than `jadx`. Where you go when the decompiler fails |
| [Frida](https://frida.re/docs/android/) | host + device | Everything in §7. Spawn-gate: `-f pkg --pause` |
| [Frida JavaScript API](https://frida.re/docs/javascript-api/) | docs | `Java.enumerateClassLoaders`, `Java.classFactory.loader`, `Memory.scanSync`, `Interceptor` |
| [frida-dexdump](https://github.com/hluwa/frida-dexdump) | host | The mature memory-scanning DEX dumper whose approach §3.7.3 describes |
| [Objection](https://github.com/sensepost/objection) | host | Faster than writing hooks for routine exploration |
| [Ghidra](https://ghidra-sre.org/) | host | Native analysis. Start with Imports and `JNI_OnLoad` |
| [aapt2](https://developer.android.com/tools/aapt2) | host | Platform-accurate manifest and resource dumping — `aapt2 dump xmltree` reads what `apktool` sometimes cannot |
| [apksigner / zipalign](https://developer.android.com/tools) | host | Required after any repackaging |
| [dex2jar](https://github.com/pxb1988/dex2jar) | host | Second opinion when `jadx` output looks wrong; disagreement between decompilers is itself information |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | host | Lead generation and coverage. Verify every hit dynamically |
| [Chapter scripts](../scripts/) | host + device | `frida-string-decryptor.js`, `frida-classloader-dump.js`, `frida-dexdump-lite.js`, `apk-obfuscation-triage.sh`, `annotate-smali-strings.py` |

---

## Commercial protection vendors

Listed so you can find *their own* documentation, which is frequently the most accurate public
description of what their product does to an APK. Read them as vendor claims, not as fact.

| Vendor | Products | Why you would read them |
|---|---|---|
| Guardsquare | ProGuard, DexGuard, AppSweep | The ProGuard manual is the reference for keep-rule syntax regardless of which tool a target used |
| Licel | DexProtector | Public documentation describes the general packing and encryption model |
| Promon | SHIELD | RASP framing; useful for understanding what a runtime-protection product claims to detect |
| Appdome | no-code protection platform | Their feature list maps closely to the artefacts you will observe |
| Digital.ai (formerly Arxan) | App Protection | Native hardening and integrity webs; the marketing describes the technique categories |
| Qihoo 360, Bangcle, Tencent, Ijiami | regional packers | Documentation is often Chinese-language; the artefacts in §3.7.4 are more useful than the marketing |

> **Warning**
> Do not write a vendor's name into a client report without a positive, defensible identification.
> Products change, libraries get renamed, and vendors ship different tiers to different customers. The
> useful output of identification is not the name — it is the answer to "has anyone published a general
> method for this shape".

---

## Research and long-form

| Resource | Why |
|---|---|
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | Occasional deep Android runtime work; the methodology is worth reading even when the subject is not obfuscation |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Read for the *pattern* of which subsystems recur, not to memorise identifiers |
| Academic work on control-flow flattening and deobfuscation | Search terms: "control flow flattening deobfuscation", "opaque predicate detection", "symbolic deobfuscation". The LLVM/native literature is far more mature than the DEX literature |
| Malware analysis writeups of Android packers | The malware community publishes the most detailed public unpacking work, because they meet packers constantly. See [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) |

| Work | Why |
|---|---|
| *Surreptitious Software* — Collberg & Nagra | The academic foundation of obfuscation, watermarking and tamper-proofing. The taxonomy in §3 of this chapter descends from this book |
| *Android Security Internals* — Nikolay Elenkov | Best structural account of the platform the protections run on; dated in specifics |
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | The linker, ELF loading and `.init_array` behaviour in depth |
| *Practical Binary Analysis* — Dennis Andriesse | Native-side techniques that transfer directly once logic moves into a `.so` |

> **Note on CVE citation.** This chapter deliberately describes vulnerability *classes* rather than
> naming identifiers. Obfuscation is not itself a vulnerability class, and the bugs that hide behind it
> are ordinary application bugs; a misattributed CVE in a client report is worse than no citation. When
> you need a specific reference, pull it from the bulletin for the affected release.

---

## Conference talks worth finding

Search for the topic rather than a URL, since hosting moves.

- Android packer unpacking and generic DEX dumping — Black Hat and DEF CON mobile tracks, and the
  Chinese security conference circuit where most packer research originates
- Frida internals and the Java bridge — the maintainers' own talks are the best source
- Commercial RASP evaluation — OWASP AppSec and local chapter talks, which tend to be more honest about
  efficacy than vendor material
- Deobfuscation with symbolic execution — academic venues (USENIX Security, NDSS, DIMVA)
- Mobile app hardening from the defender's side — fintech and gaming engineering blogs, which are
  unusually candid about the economics

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | The container: zip structure, signing blocks, appended data |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The header fields your memory carver validates; lab 04 there is the direct companion to §3.7.3 |
| [13-ART](../../13-ART/README.md) | How DEX enters the runtime; `scripts/dump-loaded-dex.js` is the hardened general-purpose loader dumper |
| [14-Dalvik](../../14-Dalvik/README.md) | The full Smali instruction reference you need for §6.3 |
| [15-Native-Code](../../15-Native-Code/README.md) · [16-JNI](../../16-JNI/README.md) | The layer logic migrates to, and why the JNI boundary is plaintext |
| [18-ARM](../../18-ARM/README.md) | Reading and patching what Ghidra shows you |
| [19-Memory](../../19-Memory/README.md) | Process memory layout and `/proc/<pid>/maps` — what the DEX sweep enumerates |
| [34-Cryptography](../../34-Cryptography/README.md) | Why "the key is in the binary" is a different situation from key mismanagement |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | Where a `NEEDED libssl.so` finding leads |
| [37-RootDetection](../../37-RootDetection/README.md) | The layering fact this chapter and that one both depend on: a Java hook cannot see a native call |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Signature verification — mandatory reading before you repackage anything |
| [39-EmulatorDetection](../../39-EmulatorDetection/README.md) | The sibling runtime control |
| [41-ProGuard](../../41-ProGuard/README.md) · [42-R8](../../42-R8/README.md) | The tools your target almost certainly used, in detail |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) · [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | The general methodologies §7 and §8 specialise |
| [53-Frida](../../53-Frida/README.md) | How the hooks work internally |
| [56-JADX](../../56-JADX/README.md) · [57-Ghidra](../../57-Ghidra/README.md) · [59-radare2](../../59-radare2/README.md) | Tool-specific workflow |
| [65-Hooking](../../65-Hooking/README.md) | Hooking from first principles, managed and native |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | Anti-debug, anti-Frida and the general bypass methodology |
| [68-ReverseEngineering](../../68-ReverseEngineering/README.md) | The parent methodology §6.1 specialises |
| [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) | Where packers are met most often, and where the best unpacking writeups live |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Full MASVS mapping |
