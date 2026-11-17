# 29 — Broadcast Receivers — References

Annotated. Every entry says *why* you would open it, not just what it is.

Nothing here is a fabricated identifier. Where this chapter would normally cite a CVE
number it describes the class of issue instead — see
[Why no CVE identifiers appear](#why-no-cve-identifiers-appear) at the end.

---

## 1. AOSP source — the authoritative answers

Paths are stable across releases. **Line numbers are not, and none appear anywhere in this
chapter** — search for the method name instead.

| Path | Open it when you need to know |
|---|---|
| `frameworks/base/services/core/java/com/android/server/am/BroadcastQueue.java` | **The single most important file for this chapter.** The parallel and ordered lists, `processNextBroadcastLocked()`, and `deliverToRegisteredReceiverLocked()` — which is where *both* permission checks live, one against the sender and one against the receiver. Also `broadcastTimeoutLocked()`, the ANR path. Substantially rewritten in Android 14 for the per-process "modern broadcast queue"; the pre-14 shape is what most devices in the field run. |
| `frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java` | `broadcastIntent()` and `broadcastIntentLocked()`. The protected-broadcast check, the sticky-broadcast handling, the flag stripping, and the two-source receiver collection. The `SecurityException` message text this chapter measured is constructed here. |
| `frameworks/base/services/core/java/com/android/server/am/BroadcastRecord.java` | One in-flight broadcast: the Intent, the ordered receiver list, `resultCode`/`resultData`/`resultExtras`, `resultAbort`, and the timing fields that `dumpsys` prints. |
| `frameworks/base/services/core/java/com/android/server/am/BroadcastFilter.java` | One runtime-registered filter. Holds `requiredPermission` — the exact field `dumpsys activity broadcasts` prints, and the one `deliverToRegisteredReceiverLocked` reads. |
| `frameworks/base/services/core/java/com/android/server/am/ReceiverList.java` | All filters registered by one `IIntentReceiver` in one process. Its `dump()` produces the `* ReceiverList{...}` lines this chapter's script parses. |
| `frameworks/base/services/core/java/com/android/server/am/BroadcastConstants.java` | `bcast_timeout`, `bcast_slow_time`, `bcast_deferral`, `bcast_deferral_decay_factor`. The values are device-tunable, which is why this chapter measured them rather than quoting them. |
| `frameworks/base/core/java/android/app/ContextImpl.java` | `registerReceiverInternal()` — where a `BroadcastReceiver` becomes an `IIntentReceiver` Binder object. Read it to understand why AMS never learns your receiver's class name, and why `registerReceiver` returns an `Intent` (the sticky value). Also `sendBroadcast()` and friends. |
| `frameworks/base/core/java/android/app/LoadedApk.java` | `ReceiverDispatcher`, `InnerReceiver`, `Args`. The per-process delivery machinery. `Args` is what carries `ordered` and `sticky` across the Handler hop, and hooking it is how `scripts/hook-broadcast.js` achieves complete coverage without enumerating loaded classes. |
| `frameworks/base/core/java/android/app/ActivityThread.java` | `handleReceiver()` — the completely separate path for **manifest-declared** receivers. A fresh instance per broadcast, created by reflection. |
| `frameworks/base/core/java/android/content/BroadcastReceiver.java` | `goAsync()`, `PendingResult`, `abortBroadcast()`, `setResultCode/Data/Extras`. The Javadoc here is unusually good on the lifetime rules. |
| `frameworks/base/core/java/android/content/Context.java` | The contracts for `sendBroadcast*` and `registerReceiver*`, and the `RECEIVER_EXPORTED` / `RECEIVER_NOT_EXPORTED` constant definitions with their API-level annotations. |
| `frameworks/base/core/java/android/content/IIntentReceiver.aidl` | The one-method interface. Seven parameters, and reading them tells you exactly what information a receiver is given — and what it is not. |
| `frameworks/base/core/java/android/content/IntentFilter.java` | `match()`, priority, and the data model. Chapter [26-Intent](../../26-Intent/README.md) walks the matching algorithm properly; come here for the priority field. |
| `frameworks/base/core/res/AndroidManifest.xml` | **Every platform `<protected-broadcast>` declaration.** This is the file `scripts/protected-broadcast-map.sh` reads out of `framework-res.apk`. Measured: 537 elements, 532 distinct actions, on Android 11 / API 30. |
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java` | `isProtectedBroadcast()` and `queryIntentReceivers()` — the static half of the two-source receiver lookup, and the resolver behind `cmd package query-receivers`. |

---

## 2. Official Android documentation

| Document | Why |
|---|---|
| **Broadcasts overview** (`developer.android.com/guide/components/broadcasts`) | The canonical description of the two registration paths, ordered broadcasts, and the security recommendations. Read the "Security considerations and best practices" section — it is short and it is correct. |
| **Broadcast exceptions** (`developer.android.com/guide/components/broadcast-exceptions`) | **The API 26 exemption list**, in full. This is the authoritative source for "which implicit broadcasts still reach manifest receivers", and it changes between releases — check it against the release you are testing rather than reciting it. |
| **Behaviour changes: Android 8.0** | The implicit-broadcast limits and the background execution limits, described as two separate changes, which is how you should think about them. |
| **Behaviour changes: Android 13 (API 33)** | `RECEIVER_EXPORTED` / `RECEIVER_NOT_EXPORTED`. Note carefully that the requirement is `targetSdk`-gated, not device-gated. |
| **Behaviour changes: Android 12 (API 31)** | `android:exported` becomes mandatory for components with an intent filter, and the notification-trampoline restriction. |
| **`Context` reference** | Every `registerReceiver` and `sendBroadcast` overload with its API level. The fastest way to work out which overload an app called from a smali descriptor. |
| **`BroadcastReceiver` reference** | The `goAsync()` / `PendingResult` contract, including the requirement to call `finish()`. |
| **`ContextCompat.registerReceiver` (AndroidX)** | The backport. Explains the `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` mechanism this chapter measured in the wild. |
| **`LocalBroadcastManager` (AndroidX, deprecated)** | Deprecated for architectural reasons. Its deprecation notice recommends `LiveData` / observables — all equally invisible to other apps. |
| **App Manifest: `<receiver>` and `<protected-broadcast>`** | The attribute reference.`<protected-broadcast>` is documented as usable only by system apps. |
| **Android Security Bulletins** | Where you go to find a real, verifiable CVE for a broadcast issue when a report needs one. Search there and cite what you actually read. |

---

## 3. OWASP MASVS / MASTG

| Identifier | Relevance |
|---|---|
| **MASVS-PLATFORM-1** — "The app uses IPC mechanisms securely" | The primary control. Exported receivers, unguarded runtime registrations, implicit broadcasts carrying data, and ordered-broadcast result leaks all map here. |
| **MSTG-PLATFORM-4** (MASVS v1) — "The app does not export sensitive functionality through IPC facilities" | The v1 wording. Most report templates still use it. |
| **MASVS-STORAGE-2** — sensitive data is not exposed unintentionally | Broadcast extras are recorded in cleartext in `dumpsys activity broadcasts` (measured), and sticky broadcasts are readable by any app. Both are storage exposure as much as IPC exposure. |
| **MASVS-CODE-4** — untrusted input is validated | An `Intent` arriving at `onReceive` is untrusted input. The missing `getAction()` check is the canonical failure of this control. |
| **MASTG — Android platform testing** | The procedural chapters on testing IPC endpoints. Useful as a report skeleton; thin on the runtime-registration surface, which is the gap this chapter fills. |

---

## 4. Tools

| Tool | Use |
|---|---|
| **`adb shell dumpsys activity broadcasts`** | The only reader of AMS's runtime registration table, the only record of broadcast senders, and a cleartext dump of extras. Everything in this chapter is downstream of it. |
| **`adb shell cmd package query-receivers`** | The **static** half — PackageManager's manifest resolver, API 29+. Its value here is as a subtrahend: what the AMS table has and this does not is the invisible surface. |
| **`adb shell am broadcast`** | Firing. Remember it is uid 2000 and it sends **ordered** broadcasts (both measured). |
| **`aapt2 dump xmltree`** | Reading `framework-res.apk`'s protected-broadcast declarations. Ships in every SDK build-tools directory and inside apktool. |
| **Frida** (`frida.re`) | The only way to recover receiver class names and export state. See [53-Frida](../../53-Frida/README.md). |
| **drozer** | `app.broadcast.info`, `app.broadcast.send`. Its agent is an ordinary app, which makes it a far better reachability oracle than `adb shell`. Blind to runtime registrations. |
| **Objection** | Quick `android hooking watch class_method` on an `onReceive`. Good for a first look, no substitute for the dispatcher hook. |
| **jadx / apktool** | Static reading. Remember that action strings survive obfuscation and class names do not. |

---

## 5. This chapter's own scripts

| Script | What it does that nothing else does |
|---|---|
| [`../scripts/receiver-surface.py`](../scripts/receiver-surface.py) | Parses AMS's runtime registration table, cross-references it against PackageManager to isolate the **runtime-only** actions, and parses the broadcast history for sender uids and extras. |
| [`../scripts/hook-broadcast.js`](../scripts/hook-broadcast.js) | Recovers the receiver **class name** and **export state**, which `dumpsys` cannot give you; hooks the send side including the invisible `receiverPermission` argument; and measures the caller-uid fact rather than asserting it. |
| [`../scripts/protected-broadcast-map.sh`](../scripts/protected-broadcast-map.sh) | Builds the device's protected-broadcast list two independent ways — statically from `framework-res.apk`, and dynamically by asking the enforcement path — and classifies a list of actions against it. |

---

## Why no CVE identifiers appear

This repository's accuracy rule is that a CVE number, a bug-bounty URL or an AOSP line
number is either verified or omitted, and that describing the *class* of issue is preferred
to guessing an identifier. Broadcast-related issues are numerous and the identifiers are
easy to misremember, so this chapter names the classes and leaves the lookup to you:

| Class | What to search the Security Bulletins for |
|---|---|
| Privileged system receiver reachable by an ordinary app | "BroadcastReceiver" plus "elevation of privilege" in the framework or a vendor component |
| Attribution-referrer forgery | The SDK's own advisories; `com.android.vending.INSTALL_REFERRER` is **measured forgeable** and this is an application-layer issue, rarely a platform CVE |
| Push-payload forgery | `com.google.android.c2dm.intent.RECEIVE` handling in older push integrations |
| Ordered-broadcast credential leak | Almost always an application finding rather than a platform one |
| SMS / OTP interception | Pre-Android-4.4 platform behaviour and the malware families that used it |

When a report needs a citation, open the bulletin, read the entry, and cite that. Do not
cite this table.

---

## Related chapters

| Chapter | Relationship to this one |
|---|---|
| [24-IPC](../../24-IPC/README.md) | Owns **surface enumeration across all IPC mechanisms**. Start there for a whole-app map; come here for the broadcast-specific runtime surface. |
| [25-Binder](../../25-Binder/README.md) | Owns the **transport**. Broadcasts ride on Binder. 25 also demonstrates, by experiment, that Binder caller identity cannot be forged — which is the contrast that makes this chapter's "you cannot know the sender" fact interesting: the identity exists, it is just consumed by AMS. |
| [26-Intent](../../26-Intent/README.md) | Owns **the Intent message itself**: the twelve fields, explicit versus implicit, `IntentFilter.match()`, the resolution algorithm, intent redirection and `PendingIntent`. Broadcast *resolution* is documented there. This chapter owns broadcast *dispatch*. `26/scripts/intent-surface-map.py` explicitly excludes runtime receivers and points here. |
| [27-ContentProviders](../../27-ContentProviders/README.md) | The other unauthenticated component entry point, with a very different failure mode — providers leak data on read, receivers accept commands on write. |
| 28-Services | Broadcast receivers frequently start services. The background execution limits that constrain that are 28's subject. |
| 30-Activities | The third component type. |
| [32-Manifest](../../32-Manifest/README.md) | Owns the **declaration audit** — export defaults by `targetSdk`, `protectionLevel` resolution, the three-way decoder comparison, severity of a declaration. Run `32-Manifest/scripts/manifest-audit.py` first. This chapter is what that audit cannot see. |
| [23-Permissions](../../23-Permissions/README.md) | `protectionLevel` semantics. Essential: a receiver guarded by a `normal` permission is not guarded. |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | Why uid separation matters, and what uid 2000 (`adb shell`) actually is. |
| [53-Frida](../../53-Frida/README.md) | The instrumentation this chapter's hook script relies on. |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | MASVS mapping and report framing. |
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | `ActivityThread`, the main `Looper`, and the process lifecycle that determines when a runtime receiver exists at all. |
