# 51 — Dynamic Analysis · References

Annotated. Every entry says why it is here and what you would read it *for*, because a reference list
without annotations is a list of things nobody will open.

---

## AOSP source

File paths only — no line numbers are quoted anywhere in this chapter, because they move.

| Path | Read it for |
|---|---|
| `frameworks/native/cmds/dumpsys/dumpsys.cpp` | Proof that `dumpsys` is a Binder `DUMP_TRANSACTION` and not a log reader — which is why every dump is a live snapshot, why each service formats its own, and why the caller needs `android.permission.DUMP` |
| `frameworks/base/core/java/android/os/Binder.java` | `dump` / `dumpAsync`, the receiving half of that transaction |
| `frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java` | `mRegisteredReceivers` — the **only** reader-visible record of the runtime broadcast surface — plus the historical broadcast log that records senders and extras |
| `frameworks/base/core/java/android/app/ContextImpl.java` | `registerReceiverInternal`: where a filter built from arbitrary runtime data becomes a `BroadcastFilter` that no file will ever describe |
| `frameworks/base/core/java/android/content/IntentFilter.java` | Why the filter is a Java object and therefore cannot be static evidence |
| `frameworks/base/services/core/java/com/android/server/am/ProcessList.java` | Where `FLAG_DEBUGGABLE` becomes `Zygote.DEBUG_ENABLE_JDWP` — the source of `adb jdwp` being exact rather than heuristic |
| `frameworks/base/core/java/android/app/ActivityThread.java` | The other end of that flag, and where a process learns it is debuggable |
| `system/core/run-as/run-as.cpp` | The two guards, **in the order** that produces two different error messages: uid < 10000 is checked before the debuggable flag |
| `system/sepolicy/private/runas.te` | Why `run-as` lands in `u:r:runas_app:...` rather than the app's own domain, and what that costs you |
| `system/logging/logd/LogBuffer.cpp` | The ring that wraps — 256 KiB on the test device — and why a long window loses its beginning |
| `system/logging/liblog/` | The `logdw` socket path from `Log.d` to the buffer, and the uid/pid stamping that `--pid` filters on |
| `art/runtime/jni/java_vm_ext.cc` | `JavaVMExt::RegisterNatives` — the binding that exists only at runtime, and the reason a stripped `.so` with no `Java_*` symbols is not missing its JNI |
| `art/runtime/class_linker.cc` | `LinkCode`, which consults the registered map **before** falling back to `dlsym` on the mangled name |
| `libcore/dalvik/src/main/java/dalvik/system/DexFile.java` | `openInMemoryDexFile` — the moment the artefact stops being the program |

---

## Official documentation

| Source | Read it for |
|---|---|
| Android Developers — *Android Debug Bridge (adb)* | `jdwp`, `forward`, `reverse`, `logcat` flags. The `reverse` subcommand is what makes a device-side listener possible with no root |
| Android Developers — *Logcat command-line tool* | `-T <timestamp>`, `-b all`, `-g`. `-T` is the reason you never need `logcat -c` on somebody's phone |
| Android Developers — *Debug your app* | The JDWP path, and what `android:debuggable` actually enables |
| Android Developers — *Inspect network traffic with the Network Inspector* | Request and response bodies for a debuggable app with **no proxy and no CA** — it instruments the client, so pinning does not apply |
| Android Developers — *Inspect your app's database* | Reading a live SQLite database including rows still in the WAL, which a file copy misses |
| Android Developers — *Profile your app performance* | The heap dump for the credential-in-a-`String` sweep |
| Android Developers — *Run apps on the Android Emulator* | Snapshots, and the Google APIs / Google Play image distinction that decides whether `adb root` works |
| `source.android.com/docs/core/permissions` | The model behind channel 02 — why `granted=` is an answer and `<uses-permission>` is a request |
| Perfetto documentation | System-wide tracing including Binder transactions, when `strace` is unavailable |

---

## OWASP

| Item | Relationship to this chapter |
|---|---|
| MASVS-STORAGE | The known-value sweep (README §5.4) is the decisive procedure for this control |
| MASVS-CRYPTO | Hook the primitive and read the transformation actually used, not the one the code appears to use |
| MASVS-AUTH | Token lifetime, refresh behaviour, and what logout genuinely clears — all runtime questions |
| MASVS-NETWORK | The intercept attempt, with the trust-store precondition established first |
| MASVS-PLATFORM | The runtime component surface, especially receivers, and the real grant state |
| MASVS-RESILIENCE | Whether the controls *work*, and at what cost they are defeated — [67](../../67-BypassingProtections/README.md) |
| MASVS-CODE | Little. Inventory with versions is a property of the artefact — [17](../../17-Libraries/README.md), statically |
| MASTG | The dynamic procedures **assume** the methodology in this chapter and do not teach it: no control run, no coverage measurement, no shell-versus-app distinction |

---

## Tools

| Tool | What it is for here | Honest limitation |
|---|---|---|
| `adb` | The transport for every channel | uid 2000, and far more privileged than any app — [60](../../60-ADB/README.md) |
| `dumpsys` | The platform's own record: channels 01, 02, 03, 06, 07 | A live snapshot. Anything that returns to its starting state is invisible |
| `logcat` | Channel 09, and the cheapest high-yield channel there is | A 256 KiB ring that wraps; the app decides what it says |
| `run-as` | Channel 04 with no root | `FLAG_DEBUGGABLE` **and** uid ≥ 10000. Two distinct refusals |
| `jdb` / JDWP | Live objects, fields and breakpoints with no injection | Debuggable only; Java only |
| Android Studio (profiler, Network Inspector, Database Inspector) | Heap dumps, live SQLite with WAL, network bodies without a proxy | Debuggable only |
| `aapt2 dump xmltree` | The coverage **denominator**, from the platform's own parser | Needs the APK, and needs every split |
| Burp Suite / mitmproxy | Channel 08 content | Only HTTP(S) it can see; defeated by pinning and by raw sockets; **void on a device with a modified trust store** |
| Frida | Altitude 3 — anything inside the process | Detectable; needs root or a rebuild; four distinct silent failure modes — [53](../../53-Frida/README.md) §7.4 |
| Objection | Frida with defaults, for the common tasks | When it fails you are debugging Frida |
| `simpleperf` | Which native functions run, with no injection and no root | Sampled and coarse; no arguments |
| `strace` | The syscall a native check really makes | **Root, and absent entirely on the test device** |
| `lldb` + `lldb-server` | Registers and memory in native code | Root for another app; SELinux blocks `/proc/<pid>/maps` reads on Android 13 |
| MobSF | Breadth, and a fast first pass on an unfamiliar app | **No stage 6 and no stage 0.** It cannot correlate, because it does not know what you did |
| `uiautomator dump` | The accessibility node tree — channel 9 of the storage sweep | A snapshot of one screen |

---

## This chapter's own tooling

| File | What it does |
|---|---|
| [`../scripts/session-recorder.sh`](../scripts/session-recorder.sh) | Brackets an exercise window with two nine-channel snapshots and reports what **changed**, with a `run-as` / `root` / `blind` mode that is auto-detected and printed. Prints `**Not captured.**` where a channel was unavailable, so that a gap can never be misread as "no change" |
| [`../scripts/coverage-reporter.py`](../scripts/coverage-reporter.py) | Says which components were actually reached, against a denominator you choose. Warns loudly when forced to use the device's resolver tables, because that denominator is always an upper bound |
| [`../examples/session-transcript-annotated.md`](../examples/session-transcript-annotated.md) | A real session, line by line, with what each observation proves — and the three subtractions applied in public |
| [`../examples/coverage-ledger.md`](../examples/coverage-ledger.md) | What was and was not exercised, with the arithmetic that produced 50% rather than 67% |
| [`../examples/README.md`](../examples/README.md) | How to read the two above, and the anonymisation statement |

---

## Tooling from other chapters that this pipeline calls

| Script | Stage | What it contributes |
|---|---|---|
| [`../../29-BroadcastReceivers/scripts/receiver-surface.py`](../../29-BroadcastReceivers/scripts/receiver-surface.py) | 5 | The whole-device runtime receiver surface, and the runtime-only residue. Channel 06 is its single-app slice |
| [`../../52-StaticAnalysis/scripts/static-sweep.py`](../../52-StaticAnalysis/scripts/static-sweep.py) | intake | The lead queue whose next-steps become the exercise script |
| [`../../52-StaticAnalysis/scripts/validate-lead.sh`](../../52-StaticAnalysis/scripts/validate-lead.sh) | 7 | The static half of a validation, including the caller closure |
| [`../../52-StaticAnalysis/scripts/blindspot-recorder.js`](../../52-StaticAnalysis/scripts/blindspot-recorder.js) | 5 | Hooks all five static blind spots and prints a delta report. Written for a static analyst; it is a **51 instrument** |
| [`../../53-Frida/scripts/native-tracer.js`](../../53-Frida/scripts/native-tracer.js) | 5 | Recovers the JNI table via `RegisterNatives` — the offsets 57 then reads |
| [`../../67-BypassingProtections/scripts/bypass-triage.py`](../../67-BypassingProtections/scripts/bypass-triage.py) | 6 | Classifies a death: reason, status, mechanism, seam. Where this chapter hands off |
| [`../../77-UsefulCommands/scripts/session.sh`](../../77-UsefulCommands/scripts/session.sh) | 1–2 | Opens a reproducible session. `session-recorder.sh` **closes a window**; the two are complementary, not competing |
| [`../../06-Android-Architecture/scripts/device-posture.sh`](../../06-Android-Architecture/scripts/device-posture.sh) | 1 | The device posture check, and the `--test-device` discipline that records your own rooting as methodology rather than reporting it as a finding |

---

## Papers, talks and reading

Rather than list specific talks by title and risk misattributing them, here are the *topics* worth
searching for. Each maps to a section of this chapter.

- **Android instrumentation and ART internals** — how a Java method is redirected at runtime, and why
  a hook is not free. Background for altitude 3.
- **Mobile app dynamic analysis at scale** — sandbox architectures, automated UI exploration
  (`monkey`, UI Automator, Droidbot), and the coverage they actually achieve. The published numbers
  are sobering and they are the argument for §3.9.
- **Code coverage for Android binaries** — Stalker-based and instrumentation-based approaches, and
  why instruction coverage costs 100–1000×.
- **Anti-analysis and evasion in mobile malware** — what a sample does when it decides it is being
  watched. The reason §6.4 exists.
- **Reproducibility in security research** — evidence directories, control runs, and stating a
  measurement's window. The general form of what this chapter calls stage 6.
- **Negative controls in experimental method** — the general-science version of §3.7.1, and worth
  reading from outside security because the discipline is a century older there.

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | **The other half of the loop.** Supplies the coverage denominator and the lead queue; receives back the names, offsets and dumped DEX. **This chapter does not triage an artefact** |
| [53-Frida](../../53-Frida/README.md) | Owns the instrumentation engine — injection, the Java bridge, `Interceptor`, `Stalker`, the four silent hook failures. **This chapter decides whether to hook; it does not teach hooking** |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | Owns everything that happens when the app fights back: the five seams, altitude, the escalation ladder, death triage. **This chapter hands off and does not compete** |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | Owns the command surface, with the "Talks to" column. **This chapter is the methodology those commands serve, and ships no command catalogue** |
| [60-ADB](../../60-ADB/README.md) | The transport, and the measurement that makes §1.4's privilege warning quantitative: 200 permissions, 16 pre-granted `SYSTEM_FIXED` |
| [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) | The 69% runtime-registration measurement, re-run here at **67% on a second device and API level** |
| [33-Storage](../../33-Storage/README.md) | The channels of §5.4, the 61,832-byte WAL, and the 132-of-132 false-positive figure. **This chapter does not rate storage findings** |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | The 12-of-14 measurement — the canonical "present but not working" control. **This chapter runs the test; 36 rates it** |
| [35-SSL](../../35-SSL/README.md) · [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | The trust-store trap, diagnosed and written up rather than published through |
| [38-TamperDetection](../../38-TamperDetection/README.md) | `TracerPid: 0` under `jdb`; the `FLAG_DEBUGGABLE` bit measurement. **38 owns the controls, 67 owns defeating them** |
| [37-RootDetection](../../37-RootDetection/README.md) | Its §7 is an instance of this chapter's method |
| [24-IPC](../../24-IPC/README.md) · [27-ContentProviders](../../27-ContentProviders/README.md) · [40-Obfuscation](../../40-Obfuscation/README.md) | Each names this chapter as the general runtime methodology their §7 specialises |
| [23-Permissions](../../23-Permissions/README.md) | The model behind channel 02. **This chapter reads the grant state; 23 explains it** |
| [28-Services](../../28-Services/README.md) | Channel 07, and the measurement that `getCallingUid()` in `onBind` returns the service's own uid |
| [57-Ghidra](../../57-Ghidra/README.md) | Consumes the offsets a `RegisterNatives` hook produces. Its §1 sends readers here to decide *which* functions to read |
| [16-JNI](../../16-JNI/README.md) | The `RegisterNatives` mechanism whose blind spot §4.6 closes |
| [18-ARM](../../18-ARM/README.md) · [19-Memory](../../19-Memory/README.md) | Registers and heap for the `lldb` path; the inlining measurement that governs §6.3 |
| [01-Computer-Science-Basics](../../01-Computer-Science-Basics/README.md) | The `gdb`-to-`lldb` transfer its lab 03 points here for |
| [04-Java](../../04-Java/README.md) | The heap-dump credential sweep its FAQ points here for — §5.4.5 |
| [49-KeyStore](../../49-KeyStore/README.md) | Names §3 as the environment build and §5 as the storage-channel sweep. Both are written to that contract |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Names this chapter a prerequisite and "the methodology behind the runtime tests" |
| [56-JADX](../../56-JADX/README.md) | Names this chapter "the runtime half, and the cross-checks" — §7.6 |
| [80-Appendix](../../80-Appendix/README.md) | The report template and the severity rubric. **This chapter produces evidence; 80 formats it** |

**Named as topics in the chapter text, and now written** — all seven have landed since this
chapter was, and are linked here so a reader is not left hunting:
[54-Objection](../../54-Objection/README.md), [55-MobSF](../../55-MobSF/README.md),
[39-EmulatorDetection](../../39-EmulatorDetection/README.md),
[50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md),
[65-Hooking](../../65-Hooking/README.md),
[66-Instrumentation](../../66-Instrumentation/README.md) and
[69-MalwareAnalysis](../../69-MalwareAnalysis/README.md).

Two of those repay a second look from this chapter specifically. `65-Hooking` owns the interception
mechanism this chapter's stage 4 depends on. `66-Instrumentation` is a stage-1 option this chapter's
environment build does not currently list: it puts a probe **inside** the target's process at the
target's UID with no root and no `frida-server`, which is precisely the vantage this chapter's
"prove it from the app, not from the shell" rule demands — with the caveat, measured there, that an
instrumentation's `UiAutomation` channel runs as uid 2000 and silently returns you to the shell's
vantage if you use it.
