# 81 — Android Runtime Internals · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure. The two platform pages that anchor the chapter are the runtime overview and the DEX format.

---

## Primary source — Android runtime

| Link | Open it when |
|---|---|
| [Android runtime and Dalvik](https://source.android.com/docs/core/runtime) | You need the platform's own map of ART, dexopt and the runtime's place in the system |
| [DEX format](https://source.android.com/docs/core/runtime/dex-format) | You are reading a DEX by hand, parsing `method_ids`, or explaining what ART loads and verifies |
| [Configure ART](https://source.android.com/docs/core/runtime/configure) | You need compiler filters, `dalvik.vm.*` properties or dexopt configuration |
| [ART Service](https://source.android.com/docs/core/runtime/configure/art-service) | You are testing Android 14+ and need to know who owns app dexopt |
| [JIT compiler](https://source.android.com/docs/core/runtime/jit-compiler) | You need profiles, hotness or the JIT code cache |
| [Boot image profiles](https://source.android.com/docs/core/runtime/boot-image-profiles) | You are explaining why the boot image contains some methods and not others |

---

## AOSP source

Read these on [cs.android.com](https://cs.android.com/) for cross-references and history. See
[07-AOSP](../../07-AOSP/README.md) for the navigation technique.

| Path | Open it when |
|---|---|
| `art/runtime/art_method.h` | You need the exact `ArtMethod` layout for the release you are testing |
| `art/runtime/art_method.cc` | You want to see how the runtime itself sets and clears entrypoints |
| `art/runtime/class_linker.cc` | You are tracing loading, linking, verification and initial entrypoints |
| `art/runtime/instrumentation.cc` | You are implementing or defeating deoptimization |
| `art/runtime/hidden_api.cc` | You need the non-SDK access decision, not a summary of it |
| `art/runtime/interpreter/mterp/nterp.cc` | You are checking whether `nterp` is eligible in a given state |
| `art/runtime/jit/jit.cc`, `jit_code_cache.cc` | You are investigating JIT compilation or code-cache movement |
| `art/runtime/native/dalvik_system_ZygoteHooks.cc` | You are tracing ART's pre/post-fork coordination |
| `frameworks/base/core/java/com/android/internal/os/ZygoteInit.java` | You are tracing preload and the accept loop |
| `frameworks/base/core/java/android/os/ZygoteProcess.java` | You are tracing the request side of specialization |
| `frameworks/base/core/java/com/android/internal/os/Zygote.java` | You need the managed `forkAndSpecialize` entry points |
| `frameworks/base/core/jni/com_android_internal_os_Zygote.cpp` | You are tracing the native identity transition |
| `system/core/rootdir/init.zygote64.rc` | You need the zygote service definition |
| `frameworks/base/cmds/app_process/app_main.cpp` | You are tracing the first native instructions of zygote |

---

## Zygisk and ZygiskNext

| Link | Open it when |
|---|---|
| [Magisk Zygisk API](https://github.com/topjohnwu/Magisk/blob/master/native/src/core/zygisk/api.hpp) | You are writing a module and need the callbacks, options and companion API |
| [ZygiskNext](https://github.com/Dr-TSNG/ZygiskNext) | You need the standalone implementation's requirements and licence boundary |
| [ZygiskNext API header](https://github.com/Dr-TSNG/ZygiskNext/blob/main/zygisk_next_api.h) | You are using the native extension API for init-oriented processes |
| [ZygiskNext basics and FAQ](https://github.com/Dr-TSNG/ZygiskNext/wiki/Basics-&-FAQ) | You need DenyList semantics, root requirements or ABI support |
| [ZygiskNext releases](https://github.com/Dr-TSNG/ZygiskNext/releases) | You are checking a compatibility claim such as Android 16 QPR2 |
| [ZygiskNextModuleSample](https://github.com/5ec1cff/ZygiskNextModuleSample) | You want a working example of the native extension API |

> **Warning**
> ZygiskNext is closed-source from `v4-0.9.2`. The public repository is the API and documentation,
> not the loader. Do not present an old source snapshot as the current implementation.

---

## Vector and LSPosed

| Link | Open it when |
|---|---|
| [Vector](https://github.com/JingMatrix/Vector) | You need the current framework, its supported versions and its module model |
| [Vector `.gitmodules`](https://github.com/JingMatrix/Vector/blob/master/.gitmodules) | You need the exact LSPlant, Dobby, LSPlt and libxposed dependencies |
| [Vector `module.cpp`](https://github.com/JingMatrix/Vector/blob/master/zygisk/src/main/cpp/module.cpp) | You are tracing per-app or `system_server` injection |
| [Vector daemon configuration](https://github.com/JingMatrix/Vector/tree/master/daemon/src/main/kotlin/org/matrix/vector/daemon/data) | You are tracing scope and module selection |
| [Vector dex2oat wrapper](https://github.com/JingMatrix/Vector/blob/master/dex2oat/README.md) | You are investigating inlining and OAT metadata |
| [Vector changelog](https://github.com/JingMatrix/Vector/blob/master/zygisk/changelog.md) | You need the rename, API 102 or hot-reload details |
| [LSPosed](https://github.com/LSPosed/LSPosed) | You are reading the historical framework this chapter's Vector section continues |
| [libxposed API](https://github.com/libxposed/api) | You are writing a module against the modern API rather than the legacy one |

---

## LSPlant and native hooking

| Link | Open it when |
|---|---|
| [LSPlant](https://github.com/LSPosed/LSPlant) | You need the API contract and supported Android versions |
| [LSPlant `lsplant.cc`](https://github.com/LSPosed/LSPlant/blob/master/lsplant/src/main/jni/lsplant.cc) | You want the trampoline and `ArtMethod` surgery |
| [LSPlant `art_method.cxx`](https://github.com/LSPosed/LSPlant/blob/master/lsplant/src/main/jni/art/runtime/art_method.cxx) | You need flags, entrypoints and version-specific helpers |
| [LSPlant JIT integration](https://github.com/LSPosed/LSPlant/blob/master/lsplant/src/main/jni/art/runtime/jit/jit.cxx) | You are investigating JIT compilation and code-cache movement |
| [LSPlant API documentation](https://lsposed.org/LSPlant/namespacelsplant.html) | You need the exact `Init`, `Hook`, `Unhook`, `Deoptimize` signatures |
| [Dobby](https://github.com/jmpews/Dobby) | You are working on the inline-hook layer beneath LSPlant |

---

## Security and standards

| Link | Open it when |
|---|---|
| [OWASP MASVS](https://mas.owasp.org/MASVS/) | You need the resilience and platform controls |
| [OWASP MASTG](https://mas.owasp.org/MASTG/) | You need Android testing techniques and demos |
| [Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts) | You are reasoning about device integrity evidence |
| [Android version codes](https://developer.android.com/reference/android/os/Build.VERSION_CODES) | You need the API-level reference |
| [Android 16 QPR2](https://developer.android.com/about/versions/16/qpr2) | You are checking a claim about the 36.1 minor release |

---

## Related chapters

| Chapter | Why it is relevant |
|---|---|
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | The concept-level runtime, zygote and class loading |
| [13-ART](../../13-ART/README.md) | The deep ART implementation this chapter extends |
| [16-JNI](../../16-JNI/README.md) | The native bridge used by every module |
| [25-Binder](../../25-Binder/README.md) | The IPC used by Vector's daemon and companions |
| [62-Magisk](../../62-Magisk/README.md) | Root, Zygisk and the module lifecycle |
| [63-LSPosed](../../63-LSPosed/README.md) | The framework that became Vector |
| [64-Xposed](../../64-Xposed/README.md) | The original global hook framework |
| [65-Hooking](../../65-Hooking/README.md) | The hook taxonomy this chapter applies to ART |
