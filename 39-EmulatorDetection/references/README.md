# 39 — Emulator Detection: References

Annotated. Where a claim in this chapter was **measured** rather than read, the measurement is named
so you can reproduce it rather than trust it.

---

## The devices every measurement came from

| | Physical | Emulator |
|---|---|---|
| Model | Redmi `M2101K6P` (`sweetin`) | `sdk_gphone16k_x86_64` (AVD `Pixel_6_Pro_API_35`) |
| Android / API | 11 / **30** | 15 / **35** |
| ABI | `arm64-v8a` | `x86_64` (+ `arm64-v8a` translation) |
| Kernel | 4.14.180-perf | 6.6.50-android15 |
| Build | `user` / `release-keys` | `userdebug` / `dev-keys` |
| System image | MIUI 12.5 (`V12.5.10.0.RKFINXM`) | `google_apis_ps16k`, tag `page_size_16kb` |

Two devices are not a survey. Every table in this chapter names the pair it came from, and the API
levels differ (30 vs 35), so a difference could sometimes be an API-level difference rather than an
emulator one. Where that is plausible the chapter says so rather than claiming the stronger result.

---

## AOSP source

File paths are stable across releases and are safe to cite. **Line numbers are not**, and none are
quoted anywhere in this chapter.

| Path | Why it matters here |
|---|---|
| `frameworks/base/core/java/android/os/Build.java` | Every `Build` field and the property backing it. Shows the `static final` assignment that makes fields latch at class-init |
| `frameworks/base/core/java/android/os/SystemProperties.java` | The `@hide` Java property API apps reach by reflection |
| `frameworks/base/core/jni/android_os_SystemProperties.cpp` | JNI bridge from Java down to libbase |
| `system/libbase/properties.cpp` | `android::base::GetProperty` |
| `bionic/libc/bionic/system_property.cpp` | `__system_property_get` — the libc entry point a Java hook cannot see |
| `bionic/libc/system_properties/system_properties.cpp` | The prefix trie, `__system_property_find`, `__system_property_foreach`, and the sequence-number protocol that prevents torn reads |
| `bionic/libc/include/sys/system_properties.h` | `PROP_VALUE_MAX` = **92** — the stack-buffer size that identifies a property read in a decompiler |
| `system/core/init/init.cpp` | Parses `/proc/bootconfig` and the kernel command line during first-stage init |
| `system/core/init/property_service.cpp` | Turns `androidboot.X` into `ro.boot.X`; enforces `ro.` immutability |
| `system/sepolicy/private/property_contexts` | Assigns an SELinux type per property key. The reason `boottime_prop` is invisible to `untrusted_app` |
| `device/generic/goldfish/` | The emulator's device tree: HALs for sensors, camera, GNSS, RIL |
| `device/generic/goldfish/sensors/` | The synthetic sensor HAL — structurally why all 18 AVD sensors carry an AOSP vendor string |
| `frameworks/native/services/sensorservice/SensorService.cpp` | Serves the sensor list to apps over Binder |
| `frameworks/base/core/java/android/hardware/SystemSensorManager.java` | Caches the sensor list in the app process |
| `frameworks/base/core/jni/android_hardware_SensorManager.cpp` | JNI layer for sensor enumeration |
| `libcore/ojluni/src/main/java/java/io/File.java` | `exists()` → `checkAccess` → `faccessat`, discarding `errno` |
| `libcore/luni/src/main/java/libcore/io/Linux.java` | Where `errno` is dropped, turning EACCES and ENOENT into one `false` |
| `external/qemu/` | Google's fork of QEMU that the emulator is built from |

Browse at <https://cs.android.com/> or <https://android.googlesource.com/>.

---

## Official Android documentation

| Link | Note |
|---|---|
| <https://developer.android.com/studio/run/emulator> | The emulator itself; AVD configuration |
| <https://developer.android.com/studio/run/emulator-commandline> | Console and command line — how to change the MCC/MNC that the telephony signal reads |
| <https://developer.android.com/reference/android/os/Build> | Field reference. Note which are `static final` |
| <https://developer.android.com/reference/android/hardware/SensorManager> | `getSensorList(TYPE_ALL)`, the source of the best Java-reachable signal |
| <https://developer.android.com/training/package-visibility> | The API 30 filtering that silently broke every package-count check written before 2020 |
| <https://developer.android.com/google/play/integrity> | Play Integrity. **Read the server-side verification section**, which is the part that decides whether it is worth anything |
| <https://developer.android.com/privacy-and-security/security-key-attestation> | Hardware key attestation and the certificate extension carrying the security level |
| <https://developer.android.com/guide/practices/page-sizes> | 16 KB page sizes — the cause of the pre-`main` SIGSEGV documented in §3 of the labs |
| <https://developer.android.com/reference/android/telephony/TelephonyManager> | Which methods need `READ_PRIVILEGED_PHONE_STATE`, i.e. why the IMEI check has been dead since API 29 |

---

## OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-RESILIENCE-1** | The app validates the integrity of the platform it runs on. Emulator detection is one input |
| **MASVS-RESILIENCE-4** | Anti-tampering and anti-instrumentation. The environment half is here; the rest is [38-TamperDetection](../../38-TamperDetection/README.md) |
| **MASVS-PRIVACY-1** | Data minimisation. The evidence set gathered here is a high-entropy device fingerprint — see README §5.1 |
| MASTG, "Testing Emulator Detection" (Android) | The procedure. README §7 is a longer version |

- MASVS — <https://mas.owasp.org/MASVS/>
- MASVS-RESILIENCE — <https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/>
- MASTG Android RESILIENCE tests — <https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/>

> **MASTG test identifiers drift**
> The MASTG has been reorganised more than once and test numbers have moved between schemes. Cite the
> **test title** alongside any number and check it against the current MASTG before it goes in a
> report. The MASVS control identifiers are stable; the MASTG numbers are not.

---

## Tooling

| Tool | Use here |
|---|---|
| [QEMU](https://www.qemu.org/) | What the emulator is |
| [Frida](https://frida.re/) | Tracing and hooking. See [53-Frida](../../53-Frida/README.md) |
| [Magisk](https://github.com/topjohnwu/Magisk) | `resetprop` — the only way to change a `ro.` property, and the reason `ro.` immutability is not a security boundary |
| [jadx](https://github.com/skylot/jadx) | DEX to Java. See [56-JADX](../../56-JADX/README.md) |
| [apktool](https://apktool.org/) | Smali and resources |
| [radare2](https://rada.re/) | `axt` on `sym.imp.__system_property_get` lists every call site at once |
| [Ghidra](https://ghidra-sre.org/) | Native checks. See [57-Ghidra](../../57-Ghidra/README.md) |
| Android NDK | Building the chapter's native probe for both ABIs |
| LLVM binutils (`llvm-readelf`) | `--dyn-syms` to find `__system_property_get`, which survives string encryption |

---

## This chapter's own instruments

Everything below was written for this chapter, run against both devices, and produced the numbers in
the tables.

| File | What it does |
|---|---|
| [`examples/emu_probe.c`](../examples/emu_probe.c) | Native probe. Reads properties via libc, walks the whole property trie with `__system_property_foreach`, and reports `errno` so `ENOENT` and `EACCES` are distinguishable. Compiles clean for arm64 and x86_64 with `-Wall -Wextra` |
| [`examples/EmulatorSignals.java`](../examples/EmulatorSignals.java) | App-uid probe. Every "an app can read X" claim in this chapter came from running this, not from `adb shell` |
| [`scripts/build-probe-app.sh`](../scripts/build-probe-app.sh) | Builds the probe into an APK with `aapt2` → `javac` → `d8` → `zipalign` → `apksigner`. No Gradle, no Android Studio, no network. Builds out of tree so no artefact reaches the repository |
| [`scripts/emu-signal-map.py`](../scripts/emu-signal-map.py) | Static mapper that **grades** what it finds against the measurements, so a DEAD check is reported as dead rather than as a hit |
| [`scripts/emu-trace.js`](../scripts/emu-trace.js) | Frida tracer, Java **and** libc. Changes nothing. Answers "which signal fired?" |
| [`scripts/emu-bypass.js`](../scripts/emu-bypass.js) | Selective neutralisation, one family at a time, so the bypass is a measurement rather than a sledgehammer |
| [`scripts/harden-avd.sh`](../scripts/harden-avd.sh) | Environment-side spoofing, with a before/after comparison that reports **what it could not fix** |

---

## Measured claims, and how to reproduce each

The point of this table is that you should not have to believe any of it.

| Claim | Reproduce with |
|---|---|
| `/dev/qemu_pipe` is absent on API 35 | `adb shell ls -la /dev/qemu_pipe`, or `emu_probe` which prints the `errno` |
| `Build.FINGERPRINT` contains no `generic` | `adb shell getprop ro.build.fingerprint` |
| `/proc/tty/drivers`, `/proc/cmdline`, `/proc/modules` are EACCES from an app | `adb shell "run-as <pkg> cat /proc/modules"` |
| Root sees ~1062 properties, the shell ~678, an app ~638 | `adb shell "getprop \| wc -l"`, the same under `run-as`, and again under `su 0` |
| `ro.boottime.*` is invisible to apps | `adb shell getprop -Z ro.boottime.qemu-props` → `boottime_prop` |
| Two `qemu`-named properties on a **real** Redmi | `adb shell "run-as <pkg> getprop \| grep -i qemu"` |
| Sensors: 41 real vs 18 emulated; 0/41 vs 18/18 AOSP | `EmulatorSignals.java`, or `dumpsys sensorservice` |
| **The emulator is 1.47× faster** (2.398 vs 3.516 ns/iter) | `emu_probe` under an app uid on both devices |
| ARM code under translation still beats a real ARM phone (3.026 ns/iter) | Push the arm64 build of `emu_probe` to an x86_64 AVD |
| Operator name is `T-Mobile`, not `Android` | `adb shell getprop gsm.operator.alpha` |
| NDK r25c binaries SIGSEGV on 16 KiB-page AVDs | `printf 'int main(void){return 42;}' > t.c`, build without `-Wl,-z,max-page-size=16384`, run — exit **139** |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [37-RootDetection](../../37-RootDetection/README.md) | The sibling control. Same trust boundary, **disjoint signal sets** — README §3.13 |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Owns repackaging (T-A) and anti-instrumentation (T-B). This chapter supplies the emulator half of its hostile-environment threat (T-C) |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | **Owns the bypass methodology.** This chapter owns the signals and bypasses only to prove one is load-bearing |
| [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | Attestation — the only signal with a root of trust off the device. Source of the `verifiedbootstate=green` vs TEE `Unverified` measurement |
| [49-KeyStore](../../49-KeyStore/README.md) | Attestation certificates and the security-level field a verifier must check |
| [22-SELinux](../../22-SELinux/README.md) | Property contexts — why an app sees ~638 properties, the shell ~678 and root ~1062 |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The app uid and domain that every reachability answer depends on |
| [62-Magisk](../../62-Magisk/README.md) | `resetprop`, and why `ro.` immutability is not a security boundary |
| [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) | The same signals with the adversary reversed |
| [55-MobSF](../../55-MobSF/README.md) | Its dynamic analysis runs in an emulator, which this chapter's subject defeats |
| [53-Frida](../../53-Frida/README.md) | The instrumentation used throughout README §7 |
| [65-Hooking](../../65-Hooking/README.md) | Hooking mechanics; the measured case of an installed hook changing nothing |
| [18-ARM](../../18-ARM/README.md) | The inlined check that survived being patched — why a "failed" hook may not be a hook problem |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | Hit the 16 KiB-page SIGSEGV independently |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | The leads-not-findings funnel applied in README §8.2 |
| [60-ADB](../../60-ADB/README.md) | Why `adb shell` is not an app |
| [16-JNI](../../16-JNI/README.md) | `JNI_OnLoad`, where a native check runs before any Java code |
| [15-Native-Code](../../15-Native-Code/README.md) | Native libraries and the dynamic linker |
| [57-Ghidra](../../57-Ghidra/README.md) | Reading a native check; the `char[92]` signature |
| [59-radare2](../../59-radare2/README.md) | The `axt` cross-reference workflow |
| [56-JADX](../../56-JADX/README.md) | DEX decompilation, and why its console under-reports failures |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What obfuscation does to these checks |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | MASVS-RESILIENCE mapping |
| [68-ReverseEngineering](../../68-ReverseEngineering/README.md) | Broader RE methodology |

---

## A note on CVEs

**This chapter cites no CVE identifiers, deliberately.**

Emulator detection is an application-level control, not a platform vulnerability class, so there is no
meaningful platform CVE to cite. Published "emulator detection bypass" advisories almost always
describe a flaw in one commercial RASP SDK, and reproducing an identifier this chapter has not
verified would violate the repository's accuracy rule.

The vulnerability classes are therefore described by **shape** rather than by identifier, in
README §5.3: the client-side integrity decision, the check that never fires, and the false positive
that blocks real customers. Each gets vulnerable code, the reason developers write it, static and
dynamic detection, an exploit, a fix as code, and an honest severity.
