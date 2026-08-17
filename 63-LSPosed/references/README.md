# 63 — LSPosed · References

Annotated. Every entry says why it is here and what it is good for, so you can decide whether to open
it. Entries marked **normative** are the source of truth for a claim made in this chapter.

---

## 1. AOSP source

Paths are stable; line numbers are not, and none are quoted anywhere in this chapter.

| Path | What to read it for |
|---|---|
| `frameworks/base/core/java/com/android/internal/os/Zygote.java` | **Normative.** Declares `nativeForkAndSpecialize` and `nativeSpecializeAppProcess` — the two functions every application launch on the device passes through, and therefore the narrowest waist in the whole system. This is why Zygisk hooks exactly these two |
| `frameworks/base/core/jni/com_android_internal_os_Zygote.cpp` | **Normative** for the injection point. The `JNINativeMethod` table registered in `register_com_android_internal_os_Zygote` is what a `RegisterNatives` hook rewrites, and `SpecializeCommon` is where the child drops uid, transitions SELinux domain and installs seccomp. `preAppSpecialize` runs before that block and `postAppSpecialize` after it — the entire privilege story in one function |
| `frameworks/base/core/java/com/android/internal/os/ZygoteInit.java` | `main` and `forkSystemServer`. The `system_server` path, which is how a manager daemon gets into the platform process |
| `frameworks/base/core/java/com/android/internal/os/ZygoteConnection.java` | Where a fork request arriving on `/dev/socket/zygote` becomes a call to `forkAndSpecialize`. Useful when you want to see what the argument list actually contains |
| `frameworks/base/services/java/com/android/server/SystemServer.java` | `main` and `run`, and the three service phases. `PackageManagerService` comes up in the bootstrap phase, which is why a manager living here has the package database available very early |
| `frameworks/base/cmds/app_process/app_main.cpp` | **The contrast that defines this chapter.** This is the source of `/system/bin/app_process`, the binary classic Xposed replaced. On an LSPosed device it is byte-identical to stock. Also cited by [62-Magisk](../../62-Magisk/README.md) for the same reason |
| `art/runtime/art_method.h` | **Normative.** Declares `entry_point_from_quick_compiled_code_` inside `PtrSizedFields`. Every hook a module installs ends up writing this pointer. Owned by [13-ART](../../13-ART/README.md) |
| `art/runtime/art_method-inl.h` | The accessors, including the pointer-size handling that makes the field's offset device-dependent. This is why hard-coding it is the largest source of breakage in public tooling |
| `art/runtime/instrumentation.cc` | Deoptimisation. The mechanism a hooking engine drives so that a hook fires on a method the compiler inlined into its callers — the same machinery a debugger uses for a breakpoint |
| `art/runtime/jit/jit.cc` | The JIT, which compiles a hot method and writes a **new** entry point over yours. Any engine must mark the method so this does not happen |
| `art/runtime/entrypoints/quick/quick_trampoline_entrypoints.cc` | **Normative** for what an entry point may legitimately hold — resolution trampoline, interpreter bridge, generic JNI trampoline. Knowing these is how you tell "hooked" from "not compiled yet", which is exactly what a detector needs |
| `art/runtime/class_linker.cc` | Class and method resolution |
| `libcore/dalvik/src/main/java/dalvik/system/BaseDexClassLoader.java` | The loader shape a module's DEX ends up behind |
| `libcore/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java` | Loading DEX from a `ByteBuffer`. Read alongside [22-SELinux](../../22-SELinux/README.md)'s measurement that modern app domains lost `file:execute_no_trans` on `app_data_file` — that constraint is why this class exists and why packers and frameworks alike use it |
| `libcore/dalvik/src/main/java/dalvik/system/DexPathList.java` | Where a loader's DEX paths live, which is what makes "a foreign class loader names the module APK" true |
| `frameworks/base/core/java/android/app/LoadedApk.java` | `getClassLoader` — the origin of the object a module receives as `lpparam.classLoader` |
| `frameworks/base/core/java/android/app/ActivityThread.java` | `handleBindApplication` — where the `Application` is instantiated and `attachBaseContext` runs, i.e. the first moment a module can obtain a `Context` |

---

## 2. Projects

> **⚠️ These are other people's repositories.** Paths and file names inside them are data, not
> promises made by this chapter. Nothing under `63-LSPosed/` corresponds to them.

| Project | Why |
|---|---|
| **LSPosed** — https://github.com/LSPosed/LSPosed | The framework itself. Read the Zygisk module entry (`onLoad`, `preAppSpecialize`, `postAppSpecialize`) for the concrete use of the API described in README §3.2, and the `lspd` daemon for scope storage and `system_server` injection |
| **LSPlant** — https://github.com/LSPosed/LSPlant | **The single most instructive thing in this list.** LSPosed's ART hooking engine, as a standalone library: backup-method creation, entry-point swap, deoptimisation, and offset derivation at runtime. Read it next to [`65-Hooking/examples/trampoline-hook.c`](../../65-Hooking/examples/trampoline-hook.c) — the same problem, *keep a way to call the original*, solved once with a trampoline page and once with a synthetic method |
| **libxposed** — https://github.com/libxposed | The newer, cleaner API surface. Modules may target it or the classic `de.robv` API; LSPosed reads both |
| **Magisk** — https://github.com/topjohnwu/Magisk | Zygisk. Owned by [62-Magisk](../../62-Magisk/README.md); read it for the injection half, not for LSPosed |
| **Xposed (classic)** — rovo89's framework and `XposedBridge` | Historical. The `app_process` replacement and `hookMethodNative`. Owned by [64-Xposed](../../64-Xposed/README.md) |
| **YAHFA** | An earlier ART hooking engine, used by EdXposed. Read it for the per-Android-version `ArtMethod` offset tables — the maintenance burden that motivated runtime derivation |
| **SandHook** | The other EdXposed engine, notable because it also does genuine **native inline hooking** of compiled method bodies, i.e. [65-Hooking](../../65-Hooking/README.md)'s hook type 2 applied to JIT/AOT output |
| **Riru** | The pre-Zygisk injection substrate. Worth one read to understand why "hijack a library Zygote already loads" was the state of the art before Magisk built it in |

---

## 3. Tooling

| Tool | Why |
|---|---|
| **`d8`** (Android SDK build-tools) | Class files to DEX. `lib/d8.jar` is the portable entry point; the `.bat`/shell wrappers are not always both present. Note it refuses an output path that is not a directory, a `.zip` or a `.jar` |
| **`baksmali`** | DEX to smali. **Ground truth** — smali cannot disagree with the bytecode because it *is* the bytecode. Chapter 56 measured decompiled Java silently disagreeing with its own DEX; that failure mode does not exist here |
| **`dexdump`** (build-tools) | Quick type-reference and call-site extraction. Ships next to `d8` and is almost never on `PATH` |
| **jadx** | The right tool for *reading* somebody else's module. Deliberately not used inside this chapter's build script — a build script should not depend on a tool that checks for updates over the network |
| **apktool** | A real AXML decode, which is what you need for the exact value of `xposedscope`. `detect-xposed-module.py` does a string scan instead and says so |
| **Frida** | The exploration half of "explore with Frida, ship with LSPosed". Owned by [53-Frida](../../53-Frida/README.md) |
| **`adb`** | Everything in README §7 |

---

## 4. Standards and specifications

| Source | Why |
|---|---|
| **Android — Verified Boot / dm-verity** | The constraint that killed classic Xposed. A modified `/system` fails verification, and LSPosed's whole architecture is a response to that |
| **Android — package visibility (API 30+)** | Why `pm.getPackageInfo("org.lsposed.manager")` can throw `NameNotFoundException` for a package that is plainly installed, which breaks the most-copied detection check independently of everything else |
| **Android — ART and Mainline modules** | Why `ArtMethod`'s layout is not a constant across devices reporting the same Android release |
| **Android — application and process lifecycle** | What Zygote is, when a process is created, and the ordering `initZygote` / `handleLoadPackage` / `attachBaseContext` / `ContentProvider.onCreate` / `Application.onCreate` |
| **RFC 2606** | Reserves `.invalid`. Every network endpoint in this chapter's example code uses it, so nothing can ever resolve |
| **RFC 6749 / RFC 7519** | Not directly used here, but relevant when a module's target is an auth flow — see [45-OAuth](../../45-OAuth/README.md) and [46-Tokens](../../46-Tokens/README.md) |

---

## 5. OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-RESILIENCE-1** | Anti-tampering. A module modifies no file, so file-integrity controls are structurally blind to it |
| **MASVS-RESILIENCE-2** | Anti-debugging and runtime integrity. There is no `ptrace` attach to detect |
| **MASVS-RESILIENCE-3** | Detection of an instrumented environment. README §5.5 is the honest version of this control, including which published checks are measurably broken |
| **MASVS-RESILIENCE-4** | Obfuscation. Raises the cost of *target selection* on both sides, and changes nothing about mechanism |
| **MASVS-CRYPTO-2** | Key management. A module makes "the key cannot be extracted" and "the key cannot be misused" visibly different claims |
| **MASVS-PLATFORM-1** | IPC. A module scoped to `android` sits inside the platform's IPC and sees all of it |
| **MASTG** — Android anti-reversing test procedures | Where a module is the tool rather than the subject |

> The MASVS-RESILIENCE family is explicitly scoped to threat models that include a **compromised
> device**, and is explicitly *additive* to the other control families rather than a substitute for
> them. Reporting "this app does not detect LSPosed" against an app with no resilience requirement is
> noise. Report what the module proved, and rate the server-side consequence.

---

## 6. Files in this chapter

| File | What it is |
|---|---|
| [`../README.md`](../README.md) | The chapter |
| [`../cheatsheet.md`](../cheatsheet.md) | The API surface, the diagnostic order, the device commands, and every measured figure in one place |
| [`../mindmap.md`](../mindmap.md) | The chapter as one map, plus the instrument-choice and hook-did-not-fire decision diagrams |
| [`../faq.md`](../faq.md) | Twenty-five questions, including "does a module run as root" and "why is `su -c` failing" |
| [`../examples/README.md`](../examples/README.md) | How the flat example files map onto a real Android project, and the Gradle and ProGuard configuration |
| [`../examples/VaultUnlockModule.java`](../examples/VaultUnlockModule.java) | **The flagship module.** Both entry points and the whole API surface a real module uses, heavily commented |
| [`../examples/LateClassHookModule.java`](../examples/LateClassHookModule.java) | Hooking a class that does not exist yet — the class-loader problem, with the one-shot guard and the negative-result report |
| [`../examples/AndroidManifest.xml`](../examples/AndroidManifest.xml) | The four `<meta-data>` elements, annotated with how each is commonly got wrong |
| [`../examples/xposed_init`](../examples/xposed_init) | The entry-class list |
| [`../scripts/build-xposed-module.sh`](../scripts/build-xposed-module.sh) | Compiles a module to DEX offline with a generated stub API, excludes the stub from the DEX exactly as `compileOnly` would, and disassembles the result. Produced every listing in README §6 |
| [`../scripts/lsposed-footprint.sh`](../scripts/lsposed-footprint.sh) | Device posture and footprint, probed from **root, shell and an app uid** side by side. Read-only; installs and changes nothing |
| [`../scripts/detect-xposed-module.py`](../scripts/detect-xposed-module.py) | Static triage of a module APK. Standard library only, no network. Flags privileged scope loudly and labels its target extraction as leads rather than findings |
| [`../scripts/detect-lsposed.js`](../scripts/detect-lsposed.js) | Frida agent: the four in-process signals, reported as a vector rather than a verdict. **Not executed against a live LSPosed install** — its header says so |
| [`../labs/lab-01-mapping-the-injection-chain.md`](../labs/lab-01-mapping-the-injection-chain.md) | Measure your own device's substrate, and build the app that closes the `run-as` gap |
| [`../labs/lab-02-your-first-module.md`](../labs/lab-02-your-first-module.md) | The lab application and a module, end to end, offline |
| [`../labs/lab-03-scope-timing-and-failure.md`](../labs/lab-03-scope-timing-and-failure.md) | Five correct-looking modules that accomplish nothing, and the order that finds each |
| [`../labs/lab-04-ctf-the-invisible-module.md`](../labs/lab-04-ctf-the-invisible-module.md) | CTF: four layered defences, one approach that walks past all of them |

---

## 7. Related chapters

| Chapter | Relationship to LSPosed |
|---|---|
| [13-ART](../../13-ART/README.md) | **Owns** `ArtMethod`, `entry_point_from_quick_compiled_code_`, and the four causes of hook failure. Its framework table already names LSPosed; this chapter is what that row expands into |
| [62-Magisk](../../62-Magisk/README.md) | **Owns** root, the module system and **Zygisk's injection mechanism**, including `preAppSpecialize`/`postAppSpecialize`, `connectCompanion` and DenyList. This chapter owns what LSPosed *does with* that API |
| [65-Hooking](../../65-Hooking/README.md) | **Owns** hooking from first principles. LSPosed is its hook type 1, delivered using types 3 and 5. Its §3.10 backup-versus-trampoline symmetry is the single best cross-chapter comparison here |
| [53-Frida](../../53-Frida/README.md) | **Owns** Frida as a tool. Its FAQ 24 already compares Frida with LSPosed; this chapter's §7.9 extends that table with the cases that decide real engagements rather than repeating it |
| [64-Xposed](../../64-Xposed/README.md) | The historical framework in depth: `app_process` replacement, the boot class path, `hookMethodNative`. This chapter explains only as much as makes LSPosed's design legible |
| [16-JNI](../../16-JNI/README.md) | **Owns** `RegisterNatives` and the `JNINativeMethod` table — the mechanism Zygisk uses on Zygote's fork functions |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | Zygote as a runtime construct, and why apps are forked rather than `exec`'d |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The format a module ships and an analyst reads |
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | Application startup, and where `handleLoadPackage` sits in it |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | Why a module *inside* the sandbox is not stopped by it |
| [22-SELinux](../../22-SELinux/README.md) | Why `/sys/fs/selinux/policy` is `0444` and still unreadable from an app, and why `InMemoryDexClassLoader` exists |
| [37-RootDetection](../../37-RootDetection/README.md) | The general detection taxonomy this chapter's §5.5 specialises to a hooking framework |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Tamper class T-B: runtime instrumentation leaves **nothing** in the APK. LSPosed is the persistent form of it |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | **Owns** the anti-hooking arms race and its cost model. This chapter owns the artefacts; that one owns what to do about them |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What obfuscation does to target selection — on the module and on its target |
| [42-R8](../../42-R8/README.md) | Why a module needs `-keep` on its entry classes, and why R8's `SourceFile` behaviour matters when reading somebody else's module |
| [49-KeyStore](../../49-KeyStore/README.md) | Non-exportable is not non-usable — the claim a module makes concrete |
| [34-Cryptography](../../34-Cryptography/README.md) | Already carries the `SecretKeySpec` hook in Xposed form, and defers here |
| [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) | Why the signing-oracle receiver in README §9.4 needs a permission |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | "A sweep produces leads, not findings" — the discipline `detect-xposed-module.py` inherits |
| [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | Why server-verified attestation is the only control that survives an in-process attacker |
