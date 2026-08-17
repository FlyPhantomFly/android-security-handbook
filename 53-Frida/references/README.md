# 53 — Frida · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

---

## Official Frida documentation

| Link | Open it when |
|---|---|
| https://frida.re/docs/home/ | You want the conceptual overview, or the installation matrix |
| https://frida.re/docs/android/ | You are setting up a device for the first time |
| https://frida.re/docs/javascript-api/ | **The reference you will use daily.** `Interceptor`, `Stalker`, `Memory`, `Module`, `Process`, `Thread`, `NativeFunction` |
| https://frida.re/docs/javascript-api/#java | The Java bridge specifically: `Java.use`, `Java.perform`, `Java.choose`, `Java.registerClass` |
| https://frida.re/docs/gadget/ | You are embedding the gadget in an APK and need the exact config schema |
| https://frida.re/docs/frida-trace/ | You want the `frida-trace` include/exclude syntax and handler format |
| https://frida.re/docs/stalker/ | You are writing a `transform` callback and need the iterator contract |
| https://frida.re/docs/messages/ | You are designing the `send`/`recv`/`rpc` protocol between agent and host |
| https://frida.re/news/ | A release changed something and you need to know what |

> **Version note.** The JavaScript API page reflects the *current* release. Frida 17 reorganised the
> `Module` API (`Module.findExportByName(null, x)` became `Module.getGlobalExportByName(x)`, per-module
> lookup moved to `Process.getModuleByName(m).getExportByName(x)`). If a documented call does not exist
> in your build, check which major version you are on before assuming the docs are wrong.

---

## Frida releases and binaries

| Link | Contains |
|---|---|
| https://github.com/frida/frida/releases | `frida-server-<ver>-android-{arm64,arm,x86_64,x86}.xz` and `frida-gadget-<ver>-android-<abi>.so.xz`. **The version must equal your `frida --version` output exactly.** |
| https://pypi.org/project/frida/ | The Python bindings — the same API the CLI tools use |
| https://pypi.org/project/frida-tools/ | `frida`, `frida-ps`, `frida-trace`, `frida-apk`, `frida-discover` |
| https://www.npmjs.com/package/frida-compile | Bundles a TypeScript agent into one `_agent.js` with source maps |
| https://www.npmjs.com/package/@types/frida-gum | TypeScript definitions — the fastest way to discover the API surface |

---

## Frida source — worth reading, not just linking

Reading these is what turns Frida from magic into mechanism. They are all on GitHub under
`https://github.com/frida/`.

| Repository | What is in it, and why you would read it |
|---|---|
| `frida-core` | **The injector.** `linjector` implements the `ptrace`/`mmap`/`dlopen` sequence described in §3.2. Also the spawn implementation, the agent bootstrap, and the wire protocol. Read this to understand what "attach" actually costs. |
| `frida-gum` | **The instrumentation engine.** `Interceptor`, `Stalker`, the per-architecture code writers (`Arm64Writer`, `ThumbWriter`), the backtracers, and the relocators. Read `gum/backend-arm64/gumstalker-arm64.c` if you want to know how Stalker really works. |
| `frida-java-bridge` | **The entire Java side.** `lib/android.js` contains the `ArtMethod` manipulation, the class factory, `Java.choose`'s heap walk, and the version-specific offset tables. This is the single most instructive file for understanding §3.9. |
| `frida-python` | The host bindings — `Device`, `Session`, `Script`, child gating, RPC marshalling |
| `frida-node` | The same for a JavaScript host, if you prefer Node to Python |
| `frida-tools` | The CLI implementations, including how `frida-trace` generates handlers |

---

## AOSP — what Frida reaches into

Read these on [cs.android.com](https://cs.android.com/), which gives cross-references and history.
See [07-AOSP](../../07-AOSP/README.md) for the navigation technique.

### The runtime

| Path | Open it when |
|---|---|
| `art/runtime/art_method.h` | You need the exact `ArtMethod` field order for the release under test. **The structure every Java hook modifies.** |
| `art/runtime/art_method.cc` | You want `SetEntryPointFromQuickCompiledCode` and `Invoke` |
| `art/runtime/modifiers.h` | You met an access-flag bit (`kAccNative`, `kAccCompileDontBother`) and need its meaning |
| `art/runtime/instrumentation.h`, `.cc` | You are using or defeating `Java.deoptimizeEverything()` |
| `art/runtime/class_linker.cc` | You want to know when a class becomes visible to `Java.use` |
| `art/runtime/entrypoints/quick/quick_trampoline_entrypoints.cc` | You are classifying an entry-point value and need to know what each trampoline does |

### JNI

| Path | Open it when |
|---|---|
| `art/runtime/jni/jni_internal.cc` | You need the implementation of a `JNIEnv` function — including `RegisterNatives`, which `native-tracer.js` hooks |
| `art/runtime/java_vm_ext.cc` | You are attaching a native thread to the VM, or want `JNI_GetCreatedJavaVMs` |
| `art/runtime/indirect_reference_table.h` | You are reasoning about why a raw `jobject` is not a stable address |

### Class loading

| Path | Open it when |
|---|---|
| `libcore/dalvik/src/main/java/dalvik/system/BaseDexClassLoader.java` | You are enumerating loaders and want to understand `DexPathList` |
| `libcore/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java` | You are dealing with a packer that never writes DEX to disk |
| `libcore/ojluni/src/main/java/java/lang/ClassLoader.java` | You are hooking `loadClass` to catch a class as it appears |

### Linker and process startup

| Path | Open it when |
|---|---|
| `bionic/linker/linker.cpp`, `linker_namespaces.cpp` | You need to know why `dlopen("/data/local/tmp/x.so")` from an app fails |
| `bionic/libc/bionic/android_dlopen_ext.cpp` | You are following the bootstrapper's call |
| `frameworks/base/core/java/com/android/internal/os/ZygoteInit.java` | You want the fork path that `-f` intercepts |
| `frameworks/base/core/java/android/app/ActivityThread.java` | You want `handleBindApplication` — the boundary spawn holds before |

---

## Official Android documentation

| Link | Covers |
|---|---|
| https://source.android.com/docs/core/runtime | ART design, compilation, and the runtime's own view of itself |
| https://source.android.com/docs/core/runtime/configure | Compiler filters and `dalvik.vm.*` properties — the `-m verify` reference |
| https://developer.android.com/training/articles/perf-jni | JNI rules, including the ones a native hook must respect |
| https://developer.android.com/privacy-and-security/security-config | Network security configuration — the pinning layer with no app code to hook |
| https://developer.android.com/tools/adb | `adb` reference, including `cmd package compile` |
| https://developer.android.com/google/play/integrity | What Play Integrity actually attests, and why a client-side hook does not change the server's view |

---

## OWASP

| Identifier | Relevance |
|---|---|
| MASVS-RESILIENCE | The control group covering anti-tampering, anti-hooking and obfuscation. Read it to understand what a client is *allowed* to claim |
| MASVS-NETWORK | TLS and pinning requirements — the standard a pinning finding is written against |
| MASTG (Testing Guide) | Concrete test procedures, many of which are Frida-based |
| https://mas.owasp.org/MASTG/techniques/android/ | The Android technique catalogue: reverse engineering, tampering, dynamic analysis |
| https://mas.owasp.org/MASVS/ | The verification standard itself |

Use MASVS identifiers in reports. "Client-side authorisation decision" is an observation; mapping it to
a MASVS control turns it into a finding a programme can track.

---

## Community tooling

| Project | What it gives you | Caution |
|---|---|---|
| `sensepost/objection` | A ready-made Frida agent plus a REPL: pinning bypass, KeyStore dump, filesystem browsing, memory search. Excellent for reconnaissance. See [54-Objection](../../54-Objection/README.md) | It is a large agent; it changes more of the process than a targeted script |
| `iddoeldor/frida-snippets` | A large catalogue of short, task-specific snippets | Snippets, not a library — read before running |
| `Ch0pin/medusa` | A modular framework organised by capability, with a menu-driven interface | Same caution as any third-party agent |
| Frida Codeshare (`frida --codeshare <user>/<script>`) | Community scripts, one command away | **This executes someone else's JavaScript inside your target.** Read it first. Same trust decision as `curl \| sh` |
| `frida/frida-trace` handlers | Hot-reloading handler files generated per traced function | Editing them while tracing is the intended workflow |

---

## Related chapters in this repository

### Prerequisites — read these before this chapter's §7

| Chapter | Why |
|---|---|
| [13-ART](../../13-ART/README.md) | **§3.15–§3.17 are the mechanism behind every Java hook.** Also compiler filters, inlining, and the four hook-failure causes |
| [15-Native-Code](../../15-Native-Code/README.md) | ELF, symbols, relocations — what `Module.findExportByName` is actually searching |
| [16-JNI](../../16-JNI/README.md) | The calling convention every native JNI hook sees: `args[0]` is `JNIEnv*` |
| [17-Libraries](../../17-Libraries/README.md) | `dlopen`, linker namespaces, why an app cannot load an arbitrary `.so` |
| [19-Memory](../../19-Memory/README.md) | Page protections and `/proc/<pid>/maps` — what `Process.enumerateRanges` reports |
| [18-ARM](../../18-ARM/README.md) | The instruction set Stalker recompiles and `Arm64Writer` emits |

### Applications

| Chapter | Why |
|---|---|
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | Every layer `ssl-pinning-bypass.js` addresses, and why one is not enough |
| [37-RootDetection](../../37-RootDetection/README.md) | The checks `root-detection-bypass.js` neutralises, from the defender's side |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Why re-signing for gadget mode has a cost |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Packers, `InMemoryDexClassLoader`, and DEX dumping — the ClassLoader problem's origin |
| [42-R8](../../42-R8/README.md) | Build-time inlining, the failure mode no runtime trick recovers |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | The adversarial back-and-forth in full |

### Adjacent tools

| Chapter | Why |
|---|---|
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | The discipline this chapter serves |
| [54-Objection](../../54-Objection/README.md) | Frida packaged as a ready-made agent |
| [56-JADX](../../56-JADX/README.md) | Where you find the class names you hook |
| [57-Ghidra](../../57-Ghidra/README.md) | Where you take the `module+offset` values Stalker and `native-tracer.js` produce |
| [60-ADB](../../60-ADB/README.md) | `cmd package compile`, proxy settings, pulling artefacts |
| [62-Magisk](../../62-Magisk/README.md) | Root, and running `frida-server` persistently |
| [63-LSPosed](../../63-LSPosed/README.md) | The same hooking mechanism applied from Zygote, when Frida's injection is the problem |
| [65-Hooking](../../65-Hooking/README.md) | Hooking from first principles across every layer |

---

## How to read a Frida error message

Not a link, but the highest-value reference in this file.

| Message fragment | It means |
|---|---|
| `unable to connect to remote frida-server` | The server is not running, is the wrong ABI, or SELinux blocked it |
| `please ensure that major versions match` | Host and device Frida versions differ |
| `Failed to attach: unable to access process with pid N` | Not root, or `ptrace_scope` is restricted |
| `java.lang.ClassNotFoundException` | Wrong `ClassLoader` — enumerate them |
| `has more than one overload` | Use `.overload(...)`; list `.overloads` first |
| `expected a pointer` | You passed a number or string where a `NativePointer` was needed — wrap in `ptr()` |
| `Module.findExportByName is not a function` | Frida 17 API reorganisation |
| `a thread ... making JNI calls without being attached` | Java code outside `Java.perform` — this aborts the process |
| `Process crashed: SIGSEGV` right after attach | Anti-debug, or a wrong `NativeFunction` signature |
| `Script is destroyed` | The session detached — check whether the app died |
| No message at all, hook never fires | **Not an error.** Read §7.4 |
