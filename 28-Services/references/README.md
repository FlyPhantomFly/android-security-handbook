# 28 — Services — References

Annotated. Every entry says **why you would open it**, not just what it is called.

**No line numbers appear anywhere in this chapter.** They move every release and
a confident wrong line number is worse than none. AOSP file paths are stable and
are cited freely.

**No CVE identifiers appear anywhere in this chapter.** Service-related
vulnerabilities exist in quantity — exported services in OEM system apps are a
recurring bulletin theme — but the authoritative source is the monthly Android
Security Bulletin index, and a number recalled from memory is how errors enter
documents. Classes of issue are described instead.

---

## 1. AOSP — the system side

| Path | Why you would open it |
|---|---|
| `frameworks/base/services/core/java/com/android/server/am/ActiveServices.java` | **The one file to read.** `startServiceLocked`, `bindServiceLocked`, `publishServiceLocked`, `unbindServiceLocked`, `bringUpServiceLocked`, `setServiceForegroundLocked`, `stopServiceTokenLocked`, `serviceDoneExecutingLocked`. Every gate described in README §4.3 is here, in the order it is applied, including the resolution that makes package-visibility filtering look like a missing component |
| `frameworks/base/services/core/java/com/android/server/am/ServiceRecord.java` | The object `dumpsys activity services` prints field by field: `startRequested`, `callStart`, `lastStartId`, `isForeground`, `foregroundId`, `foregroundNoti`, `restartCount`, `crashCount`, `createTime`. Read it once and the dump stops being opaque |
| `frameworks/base/services/core/java/com/android/server/am/IntentBindRecord.java` | One per **filter-distinct Intent**. This is the `onBind` caching in README §3.3, and the reason a second client with a filter-equal Intent never causes `onBind` to run again |
| `frameworks/base/services/core/java/com/android/server/am/AppBindRecord.java` | One per (IntentBindRecord, client process) |
| `frameworks/base/services/core/java/com/android/server/am/ConnectionRecord.java` | One per `bindService` call. Holds the bind flags, so this is where `BIND_ABOVE_CLIENT` and `BIND_INCLUDE_CAPABILITIES` actually take effect |
| `frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java` | `startService`, `bindIsolatedService`, `stopService`, `setServiceForeground`, `publishService` — the Binder entry points that delegate into `ActiveServices` |
| `frameworks/base/services/core/java/com/android/server/am/ProcessList.java` | The `*_ADJ` constants, including `SERVICE_ADJ` and `SERVICE_B_ADJ`. The answer to "why did my service get killed before that one" |
| `frameworks/base/services/accessibility/java/com/android/server/accessibility/AccessibilityManagerService.java` | The system side that binds enabled accessibility services and enforces `BIND_ACCESSIBILITY_SERVICE` |

---

## 2. AOSP — the app side

| Path | Why you would open it |
|---|---|
| `frameworks/base/core/java/android/app/Service.java` | The class you subclass. `startForeground`, `stopSelf`, `stopSelfResult`, and the `START_*` constants with their values |
| `frameworks/base/core/java/android/app/ContextImpl.java` | `startServiceCommon` and `bindServiceCommon`. **The `res < 0` throw and the `res == 0` false** are the exact difference between the `SecurityException` and the silent `false` measured in README §3.6 |
| `frameworks/base/core/java/android/app/LoadedApk.java` | `ServiceDispatcher` and `InnerConnection`. `InnerConnection` holds a **weak** reference to the dispatcher, which is why a `ServiceConnection` you did not keep a strong reference to stops working, and why unbinding twice throws `IllegalArgumentException: Service not registered` |
| `frameworks/base/core/java/android/app/ActivityThread.java` | `handleCreateService`, `handleBindService`, `handleServiceArgs`, `handleUnbindService`, `handleStopService`. **This is the proof behind README §3.7**: `onBind` is called from a main-thread message with no client transaction in flight |
| `frameworks/base/core/java/android/app/IApplicationThread.aidl` | What `system_server` calls **into your app**: `scheduleCreateService`, `scheduleBindService`, `scheduleServiceArgs`, `scheduleUnbindService`. The `uid=1000 pid=0` rows in the measured Frida trace are these |
| `frameworks/base/core/java/android/app/IServiceConnection.aidl` | One method, `connected(name, binder, dead)` — how the binder reaches your `ServiceConnection` |
| `frameworks/base/core/java/android/os/Messenger.java` and `frameworks/base/core/java/android/os/IMessenger.aidl` | `Messenger` is a one-method AIDL interface around a `Handler` |
| `frameworks/base/core/java/android/os/Handler.java` | `getIMessenger()` and `MessengerImpl.send`, where `msg.sendingUid = Binder.getCallingUid()` is stamped. That one line is the whole security story of `Messenger`, and it is also the correct hook point for tracing it |
| `frameworks/base/core/java/android/os/RemoteCallbackList.java` | The right way to hold AIDL callbacks: locking and death cleanup, both of which hand-rolled versions get wrong |
| `frameworks/base/core/java/android/accessibilityservice/AccessibilityService.java` and `AccessibilityServiceInfo.java` | The base class, and the capability flags that `res/xml/*.xml` sets |
| `frameworks/base/core/java/android/app/job/JobService.java` | Where deferrable background work went after API 26 |

---

## 3. AIDL and Binder

| Resource | Why |
|---|---|
| `system/tools/aidl/` | The compiler. Read its Java generator once and you will recognise every `Stub` you meet in JADX for the rest of your career |
| Android Developers — *Android Interface Definition Language (AIDL)* | Types, `oneway`, `in`/`out`/`inout`, and the generated shape |
| AOSP — *Stable AIDL* | Versioned interfaces, and why appending is safe and reordering is not |
| [25 — Binder](../../25-Binder/README.md) | The transport this chapter sits on. §3.9 interface tokens, §3.11 identity, §3.12 `clearCallingIdentity`, §3.14 transaction limits, §3.15 the thread pool |

---

## 4. Official documentation

| Resource | Why |
|---|---|
| Android Developers — *Services overview* | The canonical description of the three shapes |
| Android Developers — *Bound services* | `onBind`, `ServiceConnection`, and the local/`Messenger`/AIDL choice |
| Android Developers — *Foreground services* | `startForeground`, the promotion deadline, and the type taxonomy |
| Android Developers — *Foreground service types are required* (Android 14) | The API 34 change, per-type permissions, `shortService` and `specialUse` |
| Android Developers — *Background execution limits* (Android 8) | The API 26 change that reshaped the whole topic |
| Android Developers — *Package visibility filtering* | The API 30 change behind the silent `false` measured in README §3.6.1 |
| Android Developers — *Create your own accessibility service* | Including the `res/xml` capability attributes |
| Android Developers — *Schedule tasks with WorkManager* | Where background services went |
| AOSP — *App Zygote* and *isolated processes* | The 90000 versus 99000 UID ranges observed live in README §3.11 |

---

## 5. OWASP MASVS / MASTG

| Identifier | Application here |
|---|---|
| **MASVS-PLATFORM-1** — IPC mechanisms are used securely | The chapter's core control: exported state, effective permission, and a per-method caller check |
| **MASVS-PLATFORM-3** — sensitive functionality is not exposed through unprotected IPC | README §5.3.1 and §5.3.4 |
| **MASVS-CODE-4** — external input is validated | Every AIDL argument and every `msg.getData()` value crossed a process boundary |
| **MASVS-AUTH-1** — authentication cannot be bypassed client-side | A package name in an extra is a claim; `Binder.getCallingUid()` is authentication |
| **MASVS-STORAGE-2** — no sensitive data leaked to other apps | An exported service returning a token is a storage leak with extra steps |
| **MASTG** — platform interaction / IPC testing | The manual methodology README §7 expands on |

---

## 6. Background reading

| Resource | Why |
|---|---|
| Norman Hardy, *The Confused Deputy* (1988) | Two pages. Reframes `clearCallingIdentity` and every "service acts on request" bug |
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | The deepest third-party treatment of `system_server`'s component management in print |
| Android Security Bulletins (monthly index) | **The** source for real service CVEs. Use the index; do not quote a number from memory |
| Chromium design documents on multi-process architecture | Why WebView renderers are `isolatedProcess` + `externalService`, which is the best real-world example of the pattern in README §3.11 |
| Vendor threat reports on mobile banking trojans | The accessibility-abuse chain in README §3.13, with real families. Read them for the *pretexts*, which is the part a defender can act on |

---

## 7. Tooling

| Tool | Use here |
|---|---|
| `adb`, `dumpsys`, `pm`, `am` | Everything in README §7.1, no root needed |
| [Frida](https://frida.re) | README §7.5 and [`../scripts/trace-service-lifecycle.js`](../scripts/trace-service-lifecycle.js). **Pass `--runtime=v8`**; the default QuickJS runtime did not run the agent's timers in this environment |
| [JADX](https://github.com/skylot/jadx) | Recovering the `Stub`, the `DESCRIPTOR` and the `TRANSACTION_*` constants |
| [apktool](https://apktool.org) | Smali when JADX fails — README §6.4 |
| `aapt2 dump xmltree` | The **binary** manifest, which is authoritative where apktool's reconstruction is not |
| Drozer | `app.service.info`, `app.service.start`. Runs as a real app, so it is subject to the same package-visibility rules your attacker is |
| Objection | `android hooking list services` |
| MobSF | Flags exported services from the manifest. It cannot bind, so it cannot tell you what one does |
| Android SDK build-tools (`aapt2`, `d8`, `aidl`, `apksigner`) | Building the fixtures without Gradle — [`../examples/attacker-app/build.sh`](../examples/attacker-app/build.sh). **Use 35.0.1 or newer**; 34.0.0's `d8` failed on an anonymous inner class |

---

## 8. This chapter's own artefacts

| File | What it is |
|---|---|
| [`../examples/IVaultService.aidl`](../examples/IVaultService.aidl) | The interface behind the vulnerable/fixed pair, with the method-order-is-the-wire-format warning |
| [`../examples/VaultService-vulnerable.java`](../examples/VaultService-vulnerable.java) | Four annotated defects, including an `onBind` check measured to be inert. Compiled, installed, and attacked on a physical device |
| [`../examples/VaultService-fixed.java`](../examples/VaultService-fixed.java) | The same interface, correct, with each fix mapped to a README section |
| [`../examples/MessengerCommandService.java`](../examples/MessengerCommandService.java) | The second pair: a `Messenger` dispatcher, the `msg.replyTo` attack that survives a correct `sendingUid` check, and the version that does not |
| [`../examples/attacker-app/ProbeActivity.java`](../examples/attacker-app/ProbeActivity.java) | The whole attacker in one class. Bind, read the descriptor, probe codes, write the token, call |
| [`../examples/attacker-app/AndroidManifest.xml`](../examples/attacker-app/AndroidManifest.xml) | Four lines, and the comment on `QUERY_ALL_PACKAGES` explains why the probe lies without it |
| [`../examples/attacker-app/build.sh`](../examples/attacker-app/build.sh) | Gradle-free, network-free build, with the three real build failures documented |
| [`../examples/measured-bind-probe.txt`](../examples/measured-bind-probe.txt) | Four targets, four different outcomes, plus the package-visibility controlled experiment |
| [`../examples/measured-frida-trace.txt`](../examples/measured-frida-trace.txt) | The `onBind uid=self` / `execTransact uid=attacker` pair, annotated, plus two ways the script killed the target before it worked |
| [`../examples/measured-service-recon.txt`](../examples/measured-service-recon.txt) | 839 services on a stock phone, ranked, and why 325 "open" is not 325 findings |
| [`../scripts/service-recon.py`](../scripts/service-recon.py) | Joins the Service Resolver Table, `pm query-services` and `pm list permissions -f -g` into one ranked verdict per service |
| [`../scripts/trace-service-lifecycle.js`](../scripts/trace-service-lifecycle.js) | Frida: every lifecycle callback and every Binder transaction, with the caller UID at each |
| [`../labs/lab-01-map-the-service-surface.md`](../labs/lab-01-map-the-service-surface.md) | Enumerate and triage, `adb` only |
| [`../labs/lab-02-bind-from-an-unprivileged-app.md`](../labs/lab-02-bind-from-an-unprivileged-app.md) | Build the prober and bind four real services |
| [`../labs/lab-03-the-check-that-does-nothing.md`](../labs/lab-03-the-check-that-does-nothing.md) | The `onBind` identity trap, from both sides, then fixed |
| [`../labs/lab-04-lifecycle-and-foreground.md`](../labs/lab-04-lifecycle-and-foreground.md) | `START_STICKY` under a real kill, the 5-second deadline, and the OEM refusal |
| [`../labs/lab-05-ctf-the-silent-door.md`](../labs/lab-05-ctf-the-silent-door.md) | Four flags, one of which is awarded for **not** reporting something |

---

## Related chapters

| Chapter | Relationship to this one |
|---|---|
| [25 — Binder](../../25-Binder/README.md) | Owns the **transport**: parcels, transaction codes, interface tokens, the thread pool, `clearCallingIdentity`, and the measured proof that a caller UID cannot be forged. This chapter uses all of it and re-explains none of it |
| [24 — IPC](../../24-IPC/README.md) | Owns **surface enumeration** across every mechanism, and the confused-deputy methodology. It tells you what is reachable; this chapter tells you what a service does once you reach it |
| [21 — App Sandbox](../../21-App-Sandbox/README.md) | Owns UIDs and **`isolatedProcess`'s sandbox mechanics** — the throwaway uid, the empty group set, the `isolated_app` domain. This chapter owns `isolatedProcess`'s *service* semantics: bind-only, file descriptors in, `externalService` |
| [23 — Permissions](../../23-Permissions/README.md) | Owns **protection levels**, which is what decides whether an `android:permission` on a service is a gate or a decoration |
| [32 — Manifest](../../32-Manifest/README.md) | Owns the **declaration audit**: the `exported` default, manifest merging, custom-permission squatting, and why apktool's reconstruction is not authoritative |
| [26 — Intent](../../26-Intent/README.md) | Owns **Intent resolution and redirection**, and `PendingIntent` creator identity — the only authenticated way a started service can learn who started it |
| [27 — ContentProviders](../../27-ContentProviders/README.md) | Owns **`call()`-as-RPC abuse**. It sends developers here for the replacement, which is README §3.9, including the honest cost of the migration |
| [22 — SELinux](../../22-SELinux/README.md) | Owns the **`binder:call` MAC decision**, which happens in the kernel before any check in this chapter runs |
| [09 — Android App Internals](../../09-Android-App-Internals/README.md) | Owns `ActivityThread` and app startup, which is the machinery `handleCreateService` and `handleBindService` sit inside |
| [19 — Memory](../../19-Memory/README.md) | Owns `oom_adj` and the low-memory killer — the mechanism behind "why did my service get killed" |
| [53 — Frida](../../53-Frida/README.md) | Owns the instrumentation used in README §7.5 |
| [57 — Ghidra](../../57-Ghidra/README.md) | Reversing a native `onTransact`, for services whose binder comes from JNI |
| [40 — Obfuscation](../../40-Obfuscation/README.md) | Why the descriptor string and the transaction codes always survive R8 |
| [71 — OWASP Mobile](../../71-OWASP-Mobile/README.md) | The MASVS controls mapped in §5 |
| [77 — Useful Commands](../../77-UsefulCommands/README.md) | `adb`, `dumpsys`, `pm` and `am` invocations collected in one place |
