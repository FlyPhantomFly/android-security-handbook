# 64 — Xposed · References

Annotated. Every link resolves; every claim's provenance is stated.

---

> **Provenance — read this before citing anything from here.**
>
> **Classic Xposed is not installed on the machine or the device this chapter was written on, and it
> could not be.** The only device attached was an `sdk_gphone16k_x86_64` AVD, Android 15 / API 35,
> where the framework's last supported release (API 27) is seven versions behind and where `/` is
> mounted `ro` with `veritymode=enforcing`.
>
> So this chapter contains **no invented Xposed installation, no fabricated module-loading log, and
> no session transcript.** The split is:
>
> | Claim class | Status |
> |---|---|
> | The **absence** of every classic artefact, from three vantages; `app_process`'s identity and size; the mount and verity state | **Measured** on that AVD — README §7.2 |
> | The **corpus sweep**: 237 APKs, per-signature counts, both false-positive classes, the STORED/DEFLATED split | **Measured** — README §8 |
> | The **module build**: compilation, DEX size, type references, string constants, Smali | **Measured** on the host — README §6 |
> | `hookMethodNative`'s internals, the installer's procedure, `xposed.prop`'s fields, EdXposed/Riru/TaiChi internals | **Documentation-derived** from the frameworks' published designs and the AOSP they manipulated |
> | Every script in [`../scripts/`](../scripts/) | **Executed**, except [`detect-classic-xposed.js`](../scripts/detect-classic-xposed.js) which is **reviewed, not executed** — `frida-server` does not load on API 35 here. Each script's header states its own status |
>
> If you have a device on which classic Xposed genuinely runs and something in this chapter is wrong,
> **the device is right.** Write it down. This repository would rather ship a labelled gap than an
> unlabelled invention.

---

## The frameworks

| Project | What to read it for |
|---|---|
| **Xposed** — rovo89's framework and `XposedBridge` | The subject. Its published API reference is still what module authors read in 2026, and it describes a framework nobody can install. The `de.robv.android.xposed` package name is his |
| **XposedBridge** — the Java half | The `XC_MethodHook` contract, `XposedHelpers`, and `handleHookedMethod` — the single dispatcher whose control flow *is* the API's semantics (README §3.6) |
| **EdXposed** — ElderDrivers | The Riru-era successor. Proved the API and the injection mechanism are separable, which is what made the system-modifying route redundant |
| **Riru** — RikkaW | The substrate EdXposed used: replace a library Zygote already loads, and the linker pulls you in for free. Superseded by Zygisk |
| **YAHFA** — "Yet Another Hook Framework for ART" | A per-target trampoline plus a backup `ArtMethod`. Read for the contrast with `hookMethodNative`'s struct-copy backup, and for the per-Android-version offset tables that API 29 made undefinable |
| **SandHook** | Two modes, and the second is the interesting one: a genuine **native inline hook** of the compiled method body — [65-Hooking](../../65-Hooking/README.md)'s hook type 2 applied to JIT/AOT output |
| **LSPosed** — https://github.com/LSPosed/LSPosed | The current framework. Owned by [63-LSPosed](../../63-LSPosed/README.md) |
| **LSPlant** — https://github.com/LSPosed/LSPlant | The modern engine, as a standalone library. The best available answer to "what does a managed hook actually do?", and the direct descendant of the mechanism in README §3.5 |
| **Magisk** — https://github.com/topjohnwu/Magisk | Zygisk. Owned by [62-Magisk](../../62-Magisk/README.md) |
| **VirtualXposed** / **TaiChi** | The rootless variants. Read them for what each trades away — a container changes the app's uid and identity; repackaging changes its signature (README §3.12) |

> **These paths name files in other projects' repositories, not in this one.** They are a reading
> guide. Do not treat them as files this chapter ships.

---

## AOSP — everything Xposed replaced or manipulated

Paths are stable; line numbers are not, and none are quoted anywhere in this chapter.

| Path | Why |
|---|---|
| `frameworks/base/cmds/app_process/app_main.cpp` | **The file classic Xposed replaced.** Short, and worth reading in full once — almost everything mysterious about the Android boot is in it |
| `frameworks/base/cmds/app_process/Android.bp` | How it is built, and the `app_process32`/`app_process64` split that breaks size-baseline checks |
| `frameworks/base/core/jni/AndroidRuntime.cpp` | `start` and `startVm`. **The boot class path is fixed here**, which is the mechanical reason Xposed's modification had to live in `app_process` |
| `system/core/rootdir/init.rc` | The `zygote` service definition, naming `app_process64` **by path** — which Xposed did not modify. Configuration-based integrity checks saw nothing |
| `system/core/init/init.cpp` | What `init` does with that definition |
| `art/runtime/art_method.h` | `access_flags_`, `data_`, `entry_point_from_quick_compiled_code_` — the three fields the hook touched |
| `art/runtime/art_method-inl.h` | Accessors, and the pointer-size handling that makes the offset device-dependent |
| `art/runtime/modifiers.h` | `kAccNative`, `kAccFastNative`, `kAccCompileDontBother` |
| `art/runtime/class_linker.cc` | `LinkCode` — where a method's entry point is **first** set |
| `art/runtime/jit/jit.cc` | The JIT that overwrites an entry point, and why step 4 of README §3.5 was necessary |
| `art/runtime/entrypoints/quick/quick_trampoline_entrypoints.cc` | `art_quick_generic_jni_trampoline` — a **legitimate** entry-point value, which is why "is this pointer unusual?" is the wrong question (README §6.4) |
| `art/runtime/instrumentation.cc` | Deoptimisation |
| `dalvik/vm/oo/Object.h` | The Dalvik `Method` structure and `nativeFunc`. **Not in the AOSP tree since Android 5** — half of all old Xposed material describes a runtime that no longer exists in source |
| `frameworks/base/core/java/android/app/ActivityThread.java` | `handleBindApplication`, where `handleLoadPackage` was driven from |
| `frameworks/base/core/java/android/app/LoadedApk.java` | `getClassLoader` — where `lpparam.classLoader` comes from, identically under both frameworks |
| `frameworks/base/core/java/com/android/internal/os/ZygoteInit.java` | `main`, which `XposedBridge.main` wrapped |
| `libcore/dalvik/src/main/java/dalvik/system/BaseDexClassLoader.java` | How a module's DEX is loaded when it is *not* on the boot class path — the problem classic Xposed did not have |

---

## Verified Boot and the integrity model that ended it

| Source | Why |
|---|---|
| **Android — Verified Boot and dm-verity**, official documentation | The constraint that made a system-partition install impossible. Available since 4.4, mandatory for devices launching with 7.0 |
| **Android — A/B (seamless) system updates** | Block-level OTA. Every update removed the framework |
| **Android — Project Treble** | Vendor/framework decoupling, which made per-release `app_process` ports impractical across a fragmented matrix |
| **Android — ART and Mainline modules** | Why `ArtMethod`'s layout is not determined by the OS version from API 29, and therefore why per-version offset tables stopped being well-defined |
| **Android — package visibility (API 30+)** | Independently breaks every manager-package-name detection check, even when the package is installed |
| **external/avb** in AOSP | libavb. What `vbmeta` contains and how descriptors are checked. [61-Fastboot](../../61-Fastboot/README.md) parsed a real one and recomputed its hash |

---

## OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-RESILIENCE-1** | Anti-tampering. Classic Xposed is the one framework in this family that **did** modify files — on `/system`, not in the app, so app-level integrity checks still saw nothing |
| **MASVS-RESILIENCE-2** | Anti-debugging and runtime integrity. Leaves no `TracerPid`; [38-TamperDetection](../../38-TamperDetection/README.md) measured that a JDWP debugger does not either |
| **MASVS-RESILIENCE-3** | Detection of an instrumented environment. README §5.3–§5.4 are the honest version, with numbers |
| **MASVS-RESILIENCE-4** | Obfuscation. It cannot hide a module's entry class (`assets/xposed_init`) or its target strings |
| **MASVS-PLATFORM-1** | IPC. A classic module was inside `system_server` **by default** |
| **MASVS-CRYPTO-2** | Key management. Non-exportable is not non-usable |
| **MASTG** — Android anti-reversing test procedures | Where a module is the tool rather than the subject |

> The MASVS-RESILIENCE family is explicitly scoped to threat models that include a **compromised
> device**. A finding that an application ships dead Xposed checks belongs in that section of a report
> or in no section at all.

---

## RFCs and standards

| Identifier | Why |
|---|---|
| **RFC 2606** | Reserves `.invalid`. Every network endpoint in this chapter's example code uses it, so nothing can resolve |

---

## CVEs

**None are cited, deliberately.** Classic Xposed's security story is not a vulnerability story — it
is a *design* story, and the interesting failures are architectural rather than exploitable. Inventing
a CVE identifier to decorate this section would violate this repository's accuracy rule, so the class
of issue is described in README §5.3–§5.5 instead:

- a security boundary implemented as a coding convention (§5.5);
- an integrity baseline that cannot exist (§5.4);
- a detection check whose premise expired with no expiry mechanism (§5.3).

---

## This chapter's own artefacts

| File | What it is | Status |
|---|---|---|
| [`../scripts/xposed-detection-scan.py`](../scripts/xposed-detection-scan.py) | Finds Xposed-**detection** code in APKs, with anchored signatures and both false-positive classes designed out | **Executed** against 237 APKs |
| [`../scripts/pull-apk-corpus.sh`](../scripts/pull-apk-corpus.sh) | Builds a reproducible APK corpus off a device | **Executed** — 243 listed, 237 pulled |
| [`../scripts/xposed-artefact-probe.sh`](../scripts/xposed-artefact-probe.sh) | The three-vantage artefact table: root, `shell`, app uid | **Executed** on the AVD |
| [`../scripts/build-classic-module.sh`](../scripts/build-classic-module.sh) | Compiles a classic-API module and the specimen detector to DEX offline; emits ground truth | **Executed** — JDK 24, build-tools 35.0.1 |
| [`../scripts/detect-classic-xposed.js`](../scripts/detect-classic-xposed.js) | Frida agent: four in-process signals, one of them classic-specific | **Reviewed, not executed.** `frida-server` does not link on API 35 here |
| [`../examples/ClassicXposedModule.java`](../examples/ClassicXposedModule.java) | A module written as if it were 2015 | Compiles and dexes cleanly |
| [`../examples/XposedDetector.java`](../examples/XposedDetector.java) | The eight-check specimen detector, each check carrying its verdict | Compiles; the positive control for the scanner |
| [`../examples/AndroidManifest.xml`](../examples/AndroidManifest.xml) | The four meta-data declarations, annotated | Well-formed; no `--` inside comments |
| [`../examples/xposed_init`](../examples/xposed_init) | The entry-class list | — |
| [`../labs/lab-01-the-detection-surface.md`](../labs/lab-01-the-detection-surface.md) | Measure the artefacts yourself, then sweep a corpus and adjudicate | Runs today, no LSPosed needed |
| [`../labs/lab-02-read-a-classic-module.md`](../labs/lab-02-read-a-classic-module.md) | Build a 2015-era module offline and read it out of its own DEX | Runs today, no device needed |
| [`../labs/lab-03-why-the-mechanism-broke.md`](../labs/lab-03-why-the-mechanism-broke.md) | Reproduce each of the five forces on your own device | Runs today |
| [`../labs/lab-04-ctf-the-ghost-of-app-process.md`](../labs/lab-04-ctf-the-ghost-of-app-process.md) | CTF. Four flags; Gold needs no instrumentation at all | Runs today |

---

## Related chapters

### Prerequisites

| Chapter | What it owns that this chapter assumes |
|---|---|
| [13-ART](../../13-ART/README.md) | `ArtMethod`, `access_flags_`, `entry_point_from_quick_compiled_code_`, the entry-point value table, deoptimisation, and the four causes of hook failure. **This chapter cites all of it and re-derives none** |
| [14-Dalvik](../../14-Dalvik/README.md) | The `Method` structure and `nativeFunc` that the pre-ART form of the hook manipulated |
| [65-Hooking](../../65-Hooking/README.md) | Hooking from first principles: the five interception points, trampolines, inline hooking, PLT/GOT, `RegisterNatives`. Classic Xposed is its **hook type 1 and nothing else** |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | Zygote, `fork`, and copy-on-write inheritance |
| [04-Java](../../04-Java/README.md) | Reflection, access modifiers, and why `private` is a compiler concept |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The DEX format §6 reads by hand |
| [10-APK-Internals](../../10-APK-Internals/README.md) | APK structure, and why `classes.dex` is normally stored rather than deflated — the fact §8.5's blind spot depends on |

### Companions

| Chapter | Relationship |
|---|---|
| [63-LSPosed](../../63-LSPosed/README.md) | **The successor, and the chapter to read next.** Owns Zygisk injection, per-application scope, LSPlant, the backup method, and the `XposedBridge` API surface in depth. Its §1.2 lists four problems with classic Xposed; this chapter is those four problems told forwards |
| [62-Magisk](../../62-Magisk/README.md) | **Owns** systemless root and Zygisk. Its §4.1 cites `app_main.cpp` with *"What classic Xposed replaced; see 64-Xposed"* — this chapter is that section. Its §1 mental model (graffiti versus a projector) is the contrast in one image |
| [61-Fastboot](../../61-Fastboot/README.md) | **Owns** unlocking, flashing and `vbmeta`. Measured that `--disable-verity` corrupts the image's own AVB signature, which is why the install route in §3.2 is closed rather than merely discouraged |
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | Verified Boot and the integrity model that made this framework unshippable |
| [37-RootDetection](../../37-RootDetection/README.md) · [38-TamperDetection](../../38-TamperDetection/README.md) | **Own** the general detection taxonomy this chapter's §5.3 specialises. 38's tamper class T-B — runtime instrumentation leaves **nothing** in the APK — is the general form of §5.8's last row |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | **Owns** the detection arms race and its cost model. This chapter owns the artefacts; 67 owns what happens next |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | *A sweep produces leads, not findings.* §8 inherits the discipline and reports its own false-positive rate rather than claiming precision |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What obfuscation does to a module, to its target, and — the part people miss — to a **detector**, whose path strings are constants no renamer touches |
| [53-Frida](../../53-Frida/README.md) | The other instrument, and the one that still works everywhere. §7.4's script is a Frida agent |
| [16-JNI](../../16-JNI/README.md) | `RegisterNatives` and the JNI method table — hook type 5, the mechanism Zygisk uses where Xposed replaced a binary |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | Why a module inside the sandbox is not stopped by it |
| [22-SELinux](../../22-SELinux/README.md) | Why `/data/adb` returns `EACCES` to an app even where DAC would permit it |

---

## Ethics

Everything in this chapter targets a lab application built from its own sources, or APKs pulled from a
device the author controls. Where an example needs a network endpoint it uses `.invalid`.

**Do not install classic Xposed.** It requires disabling Verified Boot, which is not reversible in
practice and which makes a subsequently relocked device a brick. If you need managed-code hooking on a
device you own, use [63-LSPosed](../../63-LSPosed/README.md) — README §7.5 maps every classic
behaviour onto a modern reproduction.

Modules that defeat licensing, payment or anti-cheat controls in shipped third-party software are out
of scope for this repository and are not here.
