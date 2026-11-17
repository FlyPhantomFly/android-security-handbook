# 66 — Instrumentation · references

Annotated. Every entry says what it is *for*, not merely what it is. The last section is the honest
ledger: what this chapter measured, what it derived from documentation, and what it could not check.

---

## 1. AOSP source

| Path | Read it for |
|---|---|
| `frameworks/base/core/java/android/app/Instrumentation.java` | `onCreate`, `start`, `onStart`, `finish`, `addResults`, `sendStatus`, `getContext`, `getTargetContext`, `getUiAutomation`. Also the `onCreate` javadoc that §3.6 measures to be wrong, and `finish`'s javadoc, which says in its first sentence that it kills the process |
| `frameworks/base/core/java/android/app/ActivityThread.java` | `handleBindApplication()` — the ordering in §3.6 is literally the order of three call sites in one method. `initInstrumentation()` — the class loader parent link and the op-package-name comment behind §3.7 and §3.1. `prepareInstrumentation()` — the ABI-mismatch warning. `handleInstrumentWithoutRestart()` — the framework path that attaches to a process without restarting it, which `am instrument` does not expose |
| `frameworks/base/core/java/android/content/pm/InstrumentationInfo.java` | Every field the system keeps about a test package, including `targetProcesses` and its `*` semantics |
| `frameworks/base/core/java/android/app/IActivityManager.aidl` | `startInstrumentation`, `addInstrumentationResults`, `finishInstrumentation` — the three Binder calls that are the whole protocol |
| `frameworks/base/core/java/android/app/IInstrumentationWatcher.aidl` | The callback interface `am` implements to receive status and results |
| `frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java` | `startInstrumentation()` — the identity check in §3.9 and both force-stops in §3.13. **Not in the SDK sources drop**; this chapter's claims about it come from observed behaviour and from the stack traces the device printed |
| `frameworks/base/services/core/java/com/android/server/am/ActiveInstrumentation.java` | The server-side record of a live instrumentation |
| `frameworks/base/cmds/am/src/com/android/commands/am/Instrument.java` | The wire-protocol printer, and the flag defaults behind §3.10. **Named by the device's own stack trace**, which is how this chapter confirmed the path rather than guessing it |
| `frameworks/base/cmds/am/src/com/android/commands/am/Am.java` | `onRun()` and `runInstrument()` |
| `frameworks/base/core/java/android/app/UiAutomation.java` | `executeShellCommand`, and the connection the system supplies |
| `frameworks/base/core/java/android/app/UiAutomationConnection.java` | The system-side half that actually runs the command as uid 2000 |
| `frameworks/base/core/java/android/app/LoadedApk.java` | `makeApplicationInner()` — why the `Application` constructor and `attachBaseContext` are already done when your `onCreate` runs |

**Where the quotations in §4 came from.** The Android SDK ships the framework's Java sources for the
app-side classes under `platforms/android-35`'s companion `sources/android-35/` tree — the same code
the AVD runs. `android/app/ActivityThread.java`, `android/app/Instrumentation.java`,
`android/content/pm/InstrumentationInfo.java` and `android/app/UiAutomation.java` are all present
there. The `services/` and `cmds/` files are **not**, and every claim about them in this chapter is
labelled as derived from behaviour rather than quoted.

---

## 2. Official documentation

| Source | Why |
|---|---|
| Android Developers — `Instrumentation` API reference | The canonical description of every method in §3.1.its `onCreate` javadoc is the one §3.6 contradicts with measurements |
| Android Developers — `<instrumentation>` manifest element | Attribute list and API levels for §3.2 |
| Android Developers — "Test apps on Android" | The developer-facing framing: how Gradle, `androidTest` source sets and `testInstrumentationRunner` fit together |
| AndroidX Test library documentation | `AndroidJUnitRunner`, `InstrumentationRegistry`, Espresso, UiAutomator, Orchestrator — the stack in §3.15 |
| Android Developers — "Restrictions on non-SDK interfaces" | The greylist/blocklist distinction that makes the §3.12 census meaningful and a single lookup meaningless |
| Android Developers — UI Automator guide | Why cross-app UI driving works at all: it uses `UiAutomation`, which is why it is available to an instrumentation and not to an app |
| `adb shell am help` **on the device you are testing** | Authoritative for that build. The flag list changes between releases, and §3.4's table is a transcript from API 35 |
| Android Security Bulletins | Where platform-side instrumentation identity issues appear when they appear. This chapter deliberately cites the *class* rather than inventing identifiers |

---

## 3. Standards

| Identifier | Relevance |
|---|---|
| **MASVS-RESILIENCE-1** | Platform integrity validation — does the app run the one-line `queryInstrumentation` self-check? |
| **MASVS-RESILIENCE-2** | Anti-tampering — re-sign plus instrument is the cheapest tamper path |
| **MASVS-RESILIENCE-3** | Anti-static-analysis — test residue partially undoes obfuscation, §6.4 |
| **MASVS-RESILIENCE-4** | Compromised-environment detection — instrumentation is a compromise almost no detector covers |
| **MASVS-CODE-2** | Ships as a release build — `testOnly` artefacts in distribution |
| **MASVS-CODE-4** | No debugging code in the shipped app — residue, `testOnly`, `debuggable` |
| **MASVS-STORAGE-1 / -2** | "Private" storage means private *to this UID*, and the instrumented process is that UID |
| **OWASP MASTG** | The reverse-engineering and tampering test sections. §3.9's matrix belongs there as a step |
| **RFC 2606** | Reserves `.invalid`, used by every network reference in this chapter's code |

---

## 4. Tooling used in this chapter

| Tool | Version used | Notes |
|---|---|---|
| `aapt2` | build-tools 35.0.1 | `link --debug-mode` injects `android:debuggable="true"`, which is how the two target builds differ by exactly one bit. `dump xmltree` reads the manifest of a built APK |
| `javac` | JDK 24.0.2, `--release 8` | Its `@argfile` honours double quotes; `d8`'s does not. Do not share an argfile between them |
| `d8` | build-tools 35.0.1 | Hand it class files as ordinary argv entries. An argfile with quoted paths fails with `InvalidPathException` naming a path that is plainly correct |
| `zipalign`, `apksigner` | build-tools 35.0.1 | `apksigner verify --print-certs` is how you compare two APKs' signers, which is the whole of §3.9's apparatus |
| `keytool` | JDK 24.0.2 | Two throwaway keys, generated into `$OUTDIR` outside the repository |
| `baksmali` | ships inside apktool's `Resources/` directory | **Ground truth.** Smali cannot disagree with the bytecode because it *is* the bytecode. Produced every Smali listing in §6.2 and §6.4 |
| `jadx` | 1.5.3 | Useful for navigation. Recorded limitation on this machine: it produces no output for a bare `classes.dex` and exits 0. Use `baksmali` for DEX-level work |
| `adb` | platform-tools | Every device command. Under MSYS, `MSYS_NO_PATHCONV=1` for any call carrying an absolute remote path |
| `python3` | 3.x, run as `python3 -B` | The zip step and both analysis scripts. `-B` because `PYTHONDONTWRITEBYTECODE` does not always suppress `__pycache__` |

### This chapter's own scripts

| Script | What it does | Executed? |
|---|---|---|
| [`../scripts/instrumentation-recon.sh`](../scripts/instrumentation-recon.sh) | Read-only reconnaissance: registered instrumentations, their targets, build type, `ro.debuggable`, and with `--deep` a per-package `DEBUGGABLE`/`TEST_ONLY` sweep | **Yes**, including `--deep` over 247 packages |
| [`../scripts/am-instrument-matrix.sh`](../scripts/am-instrument-matrix.sh) | Crosses target `debuggable` × test-APK signature × caller identity, eight rows, and cleans up after itself | **Yes**, all eight rows |
| [`../scripts/instrumentation-surface.py`](../scripts/instrumentation-surface.py) | Static scanner: `DECLARED` / `RESIDUE` / `CLEAN` over an APK corpus, reading through `zipfile` so compressed DEX entries are not missed | **Yes**, 38-APK sample |
| [`../scripts/parse-instrumentation-results.py`](../scripts/parse-instrumentation-results.py) | Parses `am instrument -r` into `PASS` / `FAIL` / `CRASH` / `REFUSED`, accumulating multi-line values | **Partly** — `PASS` and `REFUSED` against live device output, `CRASH` and `FAIL` against synthetic transcripts. Its header says so |
| [`../examples/build-instrumentation-fixtures.sh`](../examples/build-instrumentation-fixtures.sh) | Builds five APKs without Gradle and self-checks the one bit that differs between each pair | **Yes** |
| [`../labs/build-ctf.sh`](../labs/build-ctf.sh) | Builds and installs lab 04's two APKs, signed with one key | **Yes**, and the reference solution was run against them |

---

## 5. Measured versus documentation-derived — the honest ledger

Every substantive claim in this chapter falls into one of three buckets. This table is the index.

### 5.1 Measured on a device

| Claim | Where | Evidence |
|---|---|---|
| A non-debuggable release build can be instrumented | §3.9 row 2 | `flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]`, full data read, `INSTRUMENTATION_CODE: -1` |
| A mismatched signature is refused, debuggable or not | §3.9 rows 3–4 | `SecurityException` naming the signature check |
| Root bypasses the signature check; shell does not | §3.9 rows 5–6 | Same probe, `su 0`, succeeded in both target configurations |
| An app UID can start an instrumentation | §3.10 | `run-as … --user 0 --no-test-api-access`, plus the two intermediate denials |
| `Instrumentation.onCreate` runs after providers and before `Application.onCreate` | §3.6 | Timestamps at 0.1 ms resolution, plus a single-instant read of three markers |
| The javadoc's "before any application code has been loaded" is false | §3.6 | The same measurement, plus the call order in `handleBindApplication()` |
| The instrumented process is the target's UID, process name and SELinux domain | §3.8 | `id.*` result block |
| The MCS pair matches chapter 22's formula | §3.8 | `c210,c256` for app ID 210 |
| Test APK DEX is first on the target's class path | §3.7 | `cl.*` result block, three loaders printed |
| Private `SharedPreferences`, private files and private static fields are all readable | §3.8 | `read.*` result block, against a shell that was refused all of them |
| A private static field written by reflection changes the app's own method's answer | §3.8 | `write.setPremium=ok`, `isPremiumAfter=true` |
| `UiAutomation.executeShellCommand` runs as uid 2000 from an app-UID process | §3.11 | `ua.shell.id=uid=2000(shell)`, plus four paths that the process's own reads could not open |
| `executeShellCommand` is not a shell | §3.11 | `echo "one two"` returned the quotes; a pipeline returned nothing |
| Hidden-API enforcement moves a member count, not a single lookup | §3.12 | Census, 30 → 289 declared methods on `ActivityThread` |
| The target is force-stopped at both ends | §3.13 | Two `system_server` log lines plus a pid that changed and then vanished |
| `testOnly` is defeated by `adb install -t` | §3.14 | `INSTALL_FAILED_TEST_ONLY`, then `Success` |
| A stock Android 15 GMS image registers zero instrumentations | §7.2 | 247 packages, empty `pm list instrumentation` |
| One `DEBUGGABLE` package on that device, zero `TEST_ONLY` | §7.2 | `--deep` sweep; the one hit was this chapter's own fixture |
| A shipping, R8-minified APK carried three JUnit test classes | §6.4 | 38-APK sample; adjudicated by hand with `baksmali` |
| A pure-Java `Proxy` hook installed from `onCreate` catches the app's first event | §9.4 | `hook.call.00=event[startup, …]` |
| The lab 04 CTF is solvable exactly as designed, and the wrong timing fails instructively | lab 04 | Both transcripts recorded |

### 5.2 Documentation-derived, and labelled as such in the text

- The behaviour of `ActivityManagerService.startInstrumentation()` **step by step**. The checks are
  named from the error strings the device produced; the surrounding structure is inferred. The AOSP
  path is stable and cited, but no line is quoted from it.
- `android:handleProfiling` and `android:functionalTest` semantics, and the `-p` / `-m` / `-f`
  profiling flags. Present in the help text and in `InstrumentationInfo`; not exercised here.
- `android:targetProcesses="*"` behaviour on a multi-process app. Quoted from
  `InstrumentationInfo.java`'s javadoc; not measured, because the fixtures are single-process.
- `handleInstrumentWithoutRestart()` — visible in `ActivityThread`, not reachable through
  `am instrument`'s flag set on this build, and therefore described rather than demonstrated.
- The `androidx.test` layering in §3.15. Read from the library's documentation; the chapter
  deliberately uses none of it.

### 5.3 Not verified, and why

| Gap | Why | What it would take |
|---|---|---|
| Whether rows 5, 6 and 7 hold on a **`user`** build | The only attached device is `userdebug` with `ro.debuggable=1`, and `startInstrumentation` has a `Build.IS_DEBUGGABLE`-conditioned branch in AOSP | A production-signed retail device. The refusal rows (3 and 4) are unaffected — a permissive build cannot manufacture a refusal |
| Whether an app UID can instrument a **different** co-signed package | The `run-as` measurement in §3.10 used the target's own UID, so it demonstrates self-instrumentation only | A third fixture APK, co-signed, with its own UID |
| Whether behaviour differs on **arm64 hardware** | The Redmi `M2101K6P` (API 30) and `i9000S` (API 33) recorded in this repository's build notes were both absent throughout | Either physical device attached |
| Whether `--abi` changes anything on a multi-ABI device | The AVD advertises `x86_64` and `arm64-v8a` via `libndk_translation.so`, but the fixtures ship no native code | A fixture with a `.so` per ABI |
| A live `CRASH` or `FAIL` transcript from `am instrument` | The shipped probe catches `Throwable`, so it cannot fail on demand | A deliberately-crashing probe. The parser's header records that these two paths were exercised synthetically |
| Any real-world instrumentation on a production device | The only registered instrumentation ever observed here was this chapter's own | A device with a vendor test APK installed. §7.2's zero is the honest baseline instead |

---

## 6. Related chapters

| Chapter | Relationship |
|---|---|
| [53-Frida](../../53-Frida/README.md) | **Owns** dynamic instrumentation from outside the process. §7.6 compares the two on constraints rather than preference, and Frida wins several rows |
| [65-Hooking](../../65-Hooking/README.md) | **Owns** interception mechanism — the five hook types, trampolines, PLT/GOT. This chapter is a delivery vehicle; 65 is the payload. The sharpest one-line distinction in either chapter: hooking changes what a method **does**, instrumentation changes what the process **contains** |
| [63-LSPosed](../../63-LSPosed/README.md) | **Owns** the Zygote-injected framework. Needs root and reaches every process; this needs a signature relationship and reaches one package. Its `/data/adb/lspd` vantage finding is reproduced here in two more locations |
| [64-Xposed](../../64-Xposed/README.md) | The historical `app_process` replacement — the other extreme of "how do you get code into a process" |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | **Owns** the methodology. This chapter is one technique inside it, and its evidence discipline applies here without modification |
| [54-Objection](../../54-Objection/README.md) | Frida-based, so it inherits Frida's constraints. There is no instrumentation equivalent, and building one is a reasonable project |
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | `ActivityThread`, `LoadedApk` and the startup path this chapter measures |
| [10-APK-Internals](../../10-APK-Internals/README.md) | The APK format and the signing blocks `apksigner verify --print-certs` reads |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | Why "the target's UID" is the entire capability |
| [22-SELinux](../../22-SELinux/README.md) | The MCS formula that §3.8's measured context independently confirms |
| [24-IPC](../../24-IPC/README.md) · [25-Binder](../../25-Binder/README.md) | Every arrow in §2.2 that is not a fork |
| [27-ContentProviders](../../27-ContentProviders/README.md) | Why a provider is the earliest slot an app's own code can occupy, and why that puts it ahead of you |
| [32-Manifest](../../32-Manifest/README.md) | The `<instrumentation>` element, and manifest merger pulling debug nodes into release builds |
| [33-Storage](../../33-Storage/README.md) | The three storage shapes §3.8 reads, and why "private" is a statement about UIDs |
| [37-RootDetection](../../37-RootDetection/README.md) · [38-TamperDetection](../../38-TamperDetection/README.md) | What apps check for, and the conspicuous absence of this technique from those lists |
| [40-Obfuscation](../../40-Obfuscation/README.md) · [42-R8](../../42-R8/README.md) | Why residue survives minification, and why `-keep` rules are the usual cause |
| [49-KeyStore](../../49-KeyStore/README.md) · [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | The only defences that survive an attacker inside the process |
| [56-JADX](../../56-JADX/README.md) | §6.5's cautions, and why `baksmali` is the safer read for this material |
| [60-ADB](../../60-ADB/README.md) | The shell UID whose vantage §3.11 measures against the app's |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | **Owns** the detection arms race that §5.6's self-check starts |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | The MASVS mapping in §5.5 |
| [80-Appendix](../../80-Appendix/README.md) | Report templates and the severity rubric §5.9 applies |
