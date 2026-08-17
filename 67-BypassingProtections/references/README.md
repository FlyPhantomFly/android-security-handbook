# 67 — Bypassing Protections — References

Annotated. Anything without a note was not worth including.
Nothing in this list is a CVE identifier, a bounty report URL or an AOSP line number that this
chapter could not verify — where a specific identifier would be useful but is not certain, the
**class** of issue is described and you are pointed at the authoritative index instead.

---

## AOSP source

These are file paths, which are stable across releases. Line numbers are deliberately absent.

| Path | Why it matters here |
|---|---|
| `bionic/libc/bionic/access.cpp` | `access()` is a thin wrapper over `faccessat`. Every path probe from every tier converges here — the canonical seam-2 hook point |
| `bionic/libc/bionic/system_property_*.cpp` | The three property-read paths (`_get`, `_find`, `_read_callback`). Hooking the wrong one produces a log full of successful-looking spoofs while the app reads the truth |
| `bionic/linker/linker_soinfo.cpp` | `soinfo::call_constructors` — where `.init_array` runs, **inside** `dlopen`. The symbol `early-instrument.js` tries to resolve |
| `bionic/linker/linker.cpp` | `do_dlopen`, and the ordering that puts constructors before the handle is returned |
| `art/runtime/jni/java_vm_ext.cc` | `JavaVMExt::LoadNativeLibrary` — opens the library, *then* resolves and calls `JNI_OnLoad`. The listing that proves `.init_array` precedes `JNI_OnLoad` |
| `art/runtime/native/dalvik_system_VMDebug.cc` | Behind `Debug.isDebuggerConnected()`. JDWP state, not ptrace state |
| `frameworks/base/core/java/android/os/Debug.java` | The public API; two lines, and the source of a very common confusion |
| `frameworks/base/core/java/android/app/ApplicationExitInfo.java` | The `REASON_*` constants the triage script decodes. API 30+ |
| `frameworks/base/services/core/java/com/android/server/am/AppExitInfoTracker.java` | Where the records are produced, and why `getStatus()` means an exit code for one reason and a signal for another |
| `frameworks/base/core/java/android/content/pm/ApplicationInfo.java` | `FLAG_DEBUGGABLE == 0x2` — the bit that differs between this chapter's two measured builds |
| `libcore/ojluni/src/main/java/java/io/File.java` | `exists()` — the top of the read stack |
| `libcore/luni/src/main/java/libcore/io/BlockGuardOs.java` | Where StrictMode gets involved, and why a protection doing I/O on the main thread crashes the app |
| `libcore/luni/src/main/native/libcore_io_Linux.cpp` | The JNI layer between `File.exists()` and bionic |
| `fs/proc/array.c` (Linux kernel) | Where `TracerPid` is generated — on read, per task, never stored in a file |
| `fs/open.c` (Linux kernel) | `SYSCALL_DEFINE3(faccessat, ...)` — the bottom of the read stack |

---

## Official Android documentation

- [Play Integrity API](https://developer.android.com/google/play/integrity) — the only device signal
  with a cryptographic root of trust, and **only** if a server verifies the token against a nonce it
  issued. Verified on the device it is a boolean at seam 3 like everything else.
- [`ApplicationExitInfo`](https://developer.android.com/reference/android/app/ApplicationExitInfo) —
  the reason and status constants. API 30+. The basis of this chapter's triage tool.
- [`ActivityManager.getHistoricalProcessExitReasons`](https://developer.android.com/reference/android/app/ActivityManager#getHistoricalProcessExitReasons(java.lang.String,%20int,%20int)) —
  the in-app API for the same data, if you are building the defensive side.
- [`Debug`](https://developer.android.com/reference/android/os/Debug) — `isDebuggerConnected`,
  `waitingForDebugger`. JDWP only.
- [`ApplicationInfo.FLAG_DEBUGGABLE`](https://developer.android.com/reference/android/content/pm/ApplicationInfo#FLAG_DEBUGGABLE) —
  a tamper signal, not a debugger signal.
- [StrictMode](https://developer.android.com/reference/android/os/StrictMode) — why
  `NetworkOnMainThreadException` will crash a protection that probes a socket from `onCreate`.
  Measured in this chapter's own first build.
- [JNI tips — `JNI_OnLoad`](https://developer.android.com/training/articles/perf-jni) — the contract
  and the return value (`JNI_VERSION_1_6`).
- [`android:extractNativeLibs`](https://developer.android.com/guide/topics/manifest/application-element#extractNativeLibs) —
  decides whether the `.so` is a file on disk or a stored zip entry, which changes how you patch it.

---

## OWASP MASVS / MASTG

- [OWASP MASVS](https://mas.owasp.org/MASVS/) — **MASVS-RESILIENCE** is where every bypass in this
  chapter is filed; **MASVS-AUTH** is where a flipped client-side authorisation belongs *if the
  server accepted it*. Filing a bypass under AUTH when the server re-verifies is the most common
  over-rating in mobile reports.
- [OWASP MASTG](https://mas.owasp.org/MASTG/) — the test procedures: root detection, anti-debugging,
  file integrity, reverse-engineering resilience, emulator detection.
- [MASTG — Android anti-reversing defences](https://mas.owasp.org/MASTG/Android/) — the catalogue
  this chapter's §3.10 and §3.11 tables expand with costs.

---

## Tooling

- [Frida](https://frida.re/docs/android/) — the instrumentation engine.
  [53-Frida](../../53-Frida/README.md) owns it; read its §7.4 on the four failure modes before
  blaming an app for your hook not working.
- [frida-gadget](https://frida.re/docs/gadget/) — the no-root path, and the only way to be earlier
  than `.init_array` without root. Requires repackaging, which trips signature checks.
- [Objection](https://github.com/sensepost/objection) — wraps the common seam-2 and seam-3 bypasses.
  Excellent for the first ten minutes; misleading afterwards, because when it works you do not learn
  which check it defeated.
- [Magisk](https://github.com/topjohnwu/Magisk) — DenyList and `resetprop` are the seam-1 toolkit.
  [62-Magisk](../../62-Magisk/README.md).
- [Ghidra](https://ghidra-sre.org/) — where you go when hooking stops being economic.
  [57-Ghidra](../../57-Ghidra/README.md), including its
  [`FindJNI.py`](../../57-Ghidra/scripts/FindJNI.py) for locating JNI entry points including
  dynamically registered ones.
- [jadx](https://github.com/skylot/jadx) — [56-JADX](../../56-JADX/README.md). Count the refused
  methods in the output tree, not the console summary; the two differ by roughly 30×.
- [radare2](https://rada.re/n/) — `axt sym.imp.abort` is the native equivalent of grepping for
  `System.exit`: find the responses, then walk back to the branches.
- [apktool](https://apktool.org/) — Smali round-tripping for seam-4 patches.
- [Unicorn Engine](https://www.unicorn-engine.org/) — emulate a checking routine instead of defeating
  it, when what you want is the algorithm.

---

## Research and background reading

- **OWASP MASTG's anti-reversing chapter** is the closest thing to a canonical catalogue of the
  detections in §3.10 and §3.11. It lists mechanisms; this chapter adds the cost and the seam.
- **The Frida documentation's Android section** describes `spawn` versus `attach` in terms of the
  API. The consequence — that attaching loses `.init_array` and `JNI_OnLoad` irrecoverably — is not
  stated there and is the practical content of this chapter's §3.12.
- **Vendor advisories for commercial RASP SDKs** are the right place to look for named, dated
  bypasses of a specific product version. A search of the NVD for the specific library and version
  you are testing beats repeating a CVE number from memory — a wrong identifier in a report is worse
  than none.
- **Conference tracks worth following for this subject:** Black Hat and DEF CON mobile tracks,
  OFFENSIVECON, and r2con for the static side. Named talks are deliberately not listed here rather
  than risk misattributing one.

---

## This chapter's own artefacts

| File | What it is |
|---|---|
| [`scripts/bypass-triage.py`](../scripts/bypass-triage.py) | Which control fired, at which seam, with the evidence. No root needed on API 30+ |
| [`scripts/early-instrument.js`](../scripts/early-instrument.js) | Gets hooks in before `.init_array` and `JNI_OnLoad`, and tells you loudly if you attached when you should have spawned |
| [`scripts/kill-path-tracer.js`](../scripts/kill-path-tracer.js) | Every deliberate exit path, Java and native, with the stack that led there. The stack names the branch |
| [`examples/guarded-app/`](../examples/guarded-app/) | A deliberately over-protected app: four tiers, seven signals, six distinct responses |
| [`examples/server-app/`](../examples/server-app/) | The same app with the decision moved server-side. The control group |
| [`examples/build.sh`](../examples/build.sh) | Builds all three variants with no Gradle, out of tree |
| [`labs/lab-01-triage-the-death.md`](../labs/lab-01-triage-the-death.md) | Attribute a death you did not see happen |
| [`labs/lab-02-escalation-ladder.md`](../labs/lab-02-escalation-ladder.md) | Four rounds of detect-and-bypass, built by you |
| [`labs/lab-03-when-to-stop.md`](../labs/lab-03-when-to-stop.md) | The static-versus-dynamic decision, made deliberately |
| [`labs/lab-04-ctf-the-boolean-that-lied.md`](../labs/lab-04-ctf-the-boolean-that-lied.md) | CTF: a secret that is a dependency, not a gate |

---

## Related chapters

| Chapter | Relationship to this one |
|---|---|
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | Names seam 4 — client-side verdict handling — as one of the platform's four trust seams. Its [lab-03](../../20-Security-Architecture/labs/lab-03-integrity-gate-bypass.md) introduces the **altitude** vocabulary this chapter extends from four levels to five |
| [37-RootDetection](../../37-RootDetection/README.md) | Owns root detection and its bypass. The worked instance of this chapter's method; its [`native-root-bypass.js`](../../37-RootDetection/scripts/native-root-bypass.js) is the reference libc-interposition script |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | Owns pinning. A pinning control is a verdict expressed as "does `checkServerTrusted` throw" — the same seams apply |
| `38-TamperDetection` | Owns integrity, signature and repackaging controls. This chapter owns defeating them. (No README yet at the time of writing) |
| [39-EmulatorDetection](../../39-EmulatorDetection/README.md) | Same five seams, different inputs. Owns the emulator signal set and grades each one by cost to defeat; its [`emu-bypass.js`](../../39-EmulatorDetection/scripts/emu-bypass.js) is deliberately switchable per signal family so a bypass stays a measurement |
| [40-Obfuscation](../../40-Obfuscation/README.md) | The same adversarial structure applied to code rather than to checks. Packers are the reason you sometimes cannot get in early enough to matter |
| [53-Frida](../../53-Frida/README.md) | Owns the instrumentation engine. Sends readers here for "attaches then the app dies instantly" |
| [16-JNI](../../16-JNI/README.md) | The bridge. This chapter defeats the checks that live behind it |
| [15-Native-Code](../../15-Native-Code/README.md) | What a `.so` is, how it is loaded, what `.init_array` means |
| [18-ARM](../../18-ARM/README.md) | Native patching — and its §5.4 measured the inlining trap: a patch that provably works against a function that provably no longer matters |
| [62-Magisk](../../62-Magisk/README.md) | The seam-1 toolkit: DenyList, Zygisk, `resetprop` |
| [57-Ghidra](../../57-Ghidra/README.md) · [56-JADX](../../56-JADX/README.md) | Where you go when hooking stops being economic |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Why a sweep produces leads rather than findings — 15 of 17 HIGH-band leads rejected by hand |
| [34-Cryptography](../../34-Cryptography/README.md) | "Anti-Frida / anti-debug: hooking blocked. Bypass first — or fall back to static analysis and memory dumps" |
| [49-KeyStore](../../49-KeyStore/README.md) | What a *dependency* looks like instead of a *gate* — key material the process cannot export however instrumented it is |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) · [22-SELinux](../../22-SELinux/README.md) | Why `adb shell` cannot read another app's `/proc/<pid>/maps` on Android 13, and why root is not a licence |
| [25-Binder](../../25-Binder/README.md) | The counter-example: a decision taken by something the caller cannot modify. Caller identity is stamped by the kernel and was demonstrated to be unforgeable |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Where these findings are filed, and at what severity |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The command index |
