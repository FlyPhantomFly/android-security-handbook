# 11 — Android Runtime · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

Implementation-level sources (OAT format, `ArtMethod`, GC, `dex2oat`) are catalogued in
[13-ART/references](../../13-ART/references/README.md) and not duplicated here.

---

## Primary source — AOSP

Read on [cs.android.com](https://cs.android.com/), which gives cross-references and history. See
[07-AOSP](../../07-AOSP/README.md) for the navigation technique.

### Class loading — the core of this chapter

| Path | Open it when |
|---|---|
| `libcore/ojluni/src/main/java/java/lang/ClassLoader.java` | You want the parent-delegation loop in `loadClass` verbatim |
| `libcore/dalvik/src/main/java/dalvik/system/BaseDexClassLoader.java` | You need to know what every Android DEX loader has in common |
| `libcore/dalvik/src/main/java/dalvik/system/PathClassLoader.java` | Understanding how the app's own APK is loaded |
| `libcore/dalvik/src/main/java/dalvik/system/DexClassLoader.java` | Investigating file-based dynamic loading |
| `libcore/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java` | **Investigating a packer.** The constructor you hook |
| `libcore/dalvik/src/main/java/dalvik/system/DelegateLastClassLoader.java` | You met inverted delegation and want to confirm the semantics |
| `libcore/dalvik/src/main/java/dalvik/system/DexPathList.java` | Tracing exactly how `findClass` searches |
| `libcore/dalvik/src/main/java/dalvik/system/DexFile.java` | The Java-to-native boundary for DEX handling |
| `art/runtime/native/dalvik_system_DexFile.cc` | The JNI implementation behind `DexFile` |

### Framework — how an app process starts

| Path | Covers |
|---|---|
| `frameworks/base/core/java/android/app/ActivityThread.java` | `main()`, `handleBindApplication`, `makeApplication` — the app process entry point |
| `frameworks/base/core/java/android/app/LoadedApk.java` | `getClassLoader()` — where the app's loader is constructed |
| `frameworks/base/core/java/android/app/ApplicationLoaders.java` | The loader cache and construction policy |
| `frameworks/base/core/java/android/app/Application.java` | `attachBaseContext` and `onCreate` — the earliest app code |
| `frameworks/base/core/java/com/android/internal/os/ZygoteInit.java` | Preloading and the fork model |
| `frameworks/base/core/java/com/android/internal/os/Zygote.java` | The fork itself, and the seccomp filter applied to the child |

### Runtime enforcement

| Path | Covers |
|---|---|
| `art/runtime/class_linker.cc` | Turning a DEX class definition into a live `mirror::Class` |
| `art/runtime/hidden_api.cc` | Non-SDK interface classification and enforcement |
| `art/runtime/verifier/method_verifier.cc` | Bytecode verification — read this before calling it a sandbox |
| `art/runtime/runtime.cc` | Runtime construction and global state |
| `libcore/ojluni/src/main/java/java/lang/reflect/Method.java` | `invoke` — the reflection sink worth hooking |

---

## Official documentation

| Resource | Why |
|---|---|
| [ART and Dalvik](https://source.android.com/docs/core/runtime) | Google's own overview; the canonical framing |
| [Configuring ART](https://source.android.com/docs/core/runtime/configure) | Every `dalvik.vm.*` property |
| [ART Mainline module](https://source.android.com/docs/core/ota/modular-system/art) | Why runtime internals differ across devices on one Android release |
| [Restrictions on non-SDK interfaces](https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces) | The hidden-API lists, and the `hidden_api_policy` setting |
| [Dex format](https://source.android.com/docs/core/runtime/dex-format) | Cross-reference with [12-DEX-Internals](../../12-DEX-Internals/README.md) |
| [Android behaviour changes](https://developer.android.com/about/versions) | Check before asserting version-dependent runtime behaviour |
| [Play policy: device and network abuse](https://support.google.com/googleplay/android-developer/answer/9888379?hl=en) | The rules on downloading and executing code — relevant to §5.4 |

---

## Tooling

| Tool | Use |
|---|---|
| [Frida — Java API](https://frida.re/docs/javascript-api/#java) | `Java.enumerateClassLoaders`, `Java.classFactory.loader`, `Java.choose` |
| [Frida — Android guide](https://frida.re/docs/android/) | Spawn vs attach, gadget, setup |
| [jadx](https://github.com/skylot/jadx) | Reading the stub and the recovered payload |
| [baksmali / smali](https://github.com/google/smali) | When the decompiler fails on deliberately malformed DEX |
| `aapt2 dump xmltree` | Reading `<application android:name>` — always step one |
| `ent` or `binwalk -E` | Entropy analysis of `assets/` to spot encrypted payloads |
| `strace -f -e trace=openat,mmap` | Watching DEX files being opened and mapped |

### Chapter scripts

| Script | Purpose |
|---|---|
| [`scripts/runtime-recon.js`](../scripts/runtime-recon.js) | Enumerate loaders and runtime state |
| [`scripts/find-dynamic-loading.py`](../scripts/find-dynamic-loading.py) | Cross-reference dynamic loading against external-storage use |
| [`scripts/dexopt-inspect.sh`](../scripts/dexopt-inspect.sh) | Report and change compilation state |
| [`examples/hook-classloaders.js`](../examples/hook-classloaders.js) | Capture dynamically loaded DEX |
| [`../13-ART/scripts/dump-loaded-dex.js`](../../13-ART/scripts/dump-loaded-dex.js) | Hardened version with a memory-sweep fallback |

---

## Security research

| Resource | Why |
|---|---|
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Monthly. Read for the *pattern* of which subsystems recur |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | The highest-quality public Android runtime research |
| [Android VRP rules](https://bughunters.google.com/about/rules) | What Google treats as a reportable runtime vulnerability |

> **Note on CVE citation.** This chapter describes runtime vulnerability *classes* rather than naming
> identifiers, because runtime bugs are numerous and version-specific and a misattributed CVE in a
> client report is worse than no citation. Pull specifics from the bulletin for the affected release.

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | MASVS-CODE covers dynamic code loading and code integrity |
| [MASTG](https://mas.owasp.org/MASTG/) | Reverse engineering and tampering procedures |
| MASTG test apps (UnCrackable series) | Practice targets — see [80-Appendix](../../80-Appendix/README.md) |

---

## Books and long-form

| Work | Why |
|---|---|
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | Deepest published treatment of the low-level runtime and process model |
| *Android Security Internals* — Nikolay Elenkov | Best structural account of the security model the runtime sits inside |
| *Virtual Machines* — Smith & Nair | The general theory: interpretation, JIT, deoptimization |
| *Inside the Java Virtual Machine* — Bill Venners | Dated but still the clearest explanation of class loading and delegation |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The byte format this runtime consumes |
| [13-ART](../../13-ART/README.md) | The implementation: OAT, VDEX, `ArtMethod`, GC, entry points |
| [14-Dalvik](../../14-Dalvik/README.md) | The predecessor, and the full Smali reference |
| [06-Android-Architecture](../../06-Android-Architecture/README.md) | Zygote and the boot process in context |
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | Process creation, UID assignment, app identity |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The boundaries the runtime does *not* provide |
| [22-SELinux](../../22-SELinux/README.md) | The MAC layer that constrains even root |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Packers, and the unpacking methodology this chapter enables |
| [53-Frida](../../53-Frida/README.md) | The instrumentation these techniques depend on |
| [65-Hooking](../../65-Hooking/README.md) | Hooking across managed and native layers |
