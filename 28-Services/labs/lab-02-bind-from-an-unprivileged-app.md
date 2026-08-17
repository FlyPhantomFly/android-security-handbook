# Lab 02 — Bind to a real service from an unprivileged app

> **Objective:** build a real Android app with no permissions worth the name,
> bind it to four real services on your device, and get four different outcomes.
> Finish able to tell, from the evidence, which of `true`, `false`, `false +
> SecurityException` and `true-but-never-connected` you are looking at — and why
> three of those four are routinely misreported.

| | |
|---|---|
| **Difficulty** | Intermediate |
| **Time** | 90–150 minutes |
| **Needs** | `adb`; Android SDK build-tools **35.0.1 or newer**; a JDK; the ability to install an APK |
| **Measured against** | Redmi `M2101K6P`, Android 11 / API 30, arm64 |
| **Reads** | [README §3.6](../README.md), [§5.2](../README.md), [§7.3](../README.md) |
| **Uses** | [`../examples/attacker-app/`](../examples/attacker-app/ProbeActivity.java), [`../scripts/service-recon.py`](../scripts/service-recon.py) |
| **Expected output** | [`../examples/measured-bind-probe.txt`](../examples/measured-bind-probe.txt) |

---

## 0. Why an app, and not `adb shell`

There is no `am bind-service`. There never has been.

Binding requires a `ServiceConnection` object, which requires a `Context`, which
requires an app. `adb shell` can *start* services and can *enumerate* them, but
it cannot hold a Binder connection, which means it cannot do the one thing that
turns a lead into a finding.

Three further reasons the shell is not a substitute, and each has produced a
wrong report:

| `adb shell` | A real app |
|---|---|
| uid 2000 (`shell`), SELinux domain `shell` | uid 10000+, domain `untrusted_app` |
| **Exempt from package-visibility filtering** | Subject to it, and it is silent |
| Holds shell-only permissions an app never has | Holds only what it declared |
| `am start-service` is subject to background-start policy in a way an app in the foreground is not | Behaves like the attacker you are modelling |

> **🧠 Mental Model**
> The shell is a *privileged observer*. The app is the *actual attacker*. Any
> claim about reachability that was measured from the shell is a claim about the
> wrong principal.

---

## 1. Setup

```bash
# host
cd Android-Pentesting-Notes/28-Services/examples/attacker-app
ls
```

```text
AndroidManifest.xml  ProbeActivity.java  build.sh
```

Check your tooling:

```bash
# host
ls "$ANDROID_HOME/build-tools" | sort -V | tail -3
javac -version
adb devices
```

> **⚠️ Warning**
> **Use build-tools 35.0.1 or newer.** 34.0.0's `d8` fails on the anonymous inner
> class in `ProbeActivity.java` with
> `NullPointerException: Cannot invoke "String.length()" because "<parameter1>" is null`,
> against class files produced by a modern JDK with `-source 8 -target 8`. The
> identical input compiles cleanly under 35.0.1. This is a tooling bug, not a
> problem with the code, and it wasted forty minutes when this lab was written.

---

## 2. Step 1 — build it

```bash
# host
sh build.sh
```

```text
SDK          .../Android/Sdk
build-tools  .../build-tools/35.0.1
android.jar  .../platforms/android-35/android.jar
[1/5] javac
3 warnings
[2/5] d8
[3/5] aapt2 link
[4/5] adding classes.dex
[5/5] apksigner

-rw-r--r-- 1 ... 12677 ... out/probe.apk
built out/probe.apk
```

Twelve kilobytes. That is the entire attacker.

**Q1.** The build has five steps and no Gradle. What is Gradle actually adding
here, and why is it worth knowing this pipeline by hand?

<details>
<summary>Answer</summary>

Gradle adds dependency resolution, resource compilation, incremental builds,
variant management and R8. None of those are needed for one class and no
resources.

Knowing the pipeline matters for a tester because you will regularly need to
build a tiny probe app on a machine that has no network, no Gradle cache, and no
patience — and because when a build fails, "Gradle said no" is not a diagnosis
while "`d8` rejected my class file" is.
</details>

### 2.1 Read the manifest before you install it

```bash
# host
cat AndroidManifest.xml
```

The only interesting line:

```xml
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>
```

Keep that in mind. In §5 you will remove it and watch the results change.

---

## 3. Step 2 — install it

```bash
# host
sh build.sh install
```

If that works, skip to §4. If you see this:

```text
adb: failed to install out/probe.apk:
     Failure [INSTALL_FAILED_USER_RESTRICTED: Install canceled by user]
```

then you are on a device with an OEM install restriction. This is **not** a
problem with the APK and **not** an Android behaviour. On the reference device
(MIUI) it was established, rather than assumed, that:

- it gates **new** packages only — installing an *update* over an already-present
  package went through without complaint;
- it is bypassed with root.

Three ways forward, best first:

```bash
# 1. Turn the restriction off. MIUI: Settings -> Additional settings ->
#    Developer options -> "Install via USB". Requires a Mi account sign-in.

# 2. Rooted device -- install as root. This is what the chapter's measurements used.
sh build.sh install root

# 3. Use a different device or an emulator.
adb -e install out/probe.apk
```

> **⚠️ Warning — read this before quoting any result from this lab**
> If you use option 2, **root was used only to install.** The app then runs as an
> ordinary unprivileged app with no root, no ADB in the attack path, and one
> permission. That distinction is the difference between "an attacker app can do
> this" and "a rooted device can do this", and conflating them in a report is a
> serious error. Say which you did.

Confirm what you installed:

```bash
# host
adb shell "dumpsys package com.pentest.ch28probe | grep -E 'userId=|targetSdk'"
```

```text
    userId=10313
    versionCode=0 minSdk=21 targetSdk=30
```

**Write your uid down.** Every later measurement is quoted against it.

---

## 4. Step 3 — bind four services and get four different answers

Pick targets from Lab 01. The reference run used one of each interesting kind:

| Target | Expected |
|---|---|
| `com.example.notesvault/.VaultService` | your own vulnerable service, if you built Lab 03's fixture. Skip it for now if not |
| `com.android.keychain/com.android.keychain.KeyChainService` | `OPEN` in the table, system credential store |
| `com.android.settings/com.android.settings.wifi.MiuiWifiService` | guarded by a `signature` permission |
| `com.miui.analytics/com.miui.analytics.AnalyticsService` | `OPEN`, a real vendor service |

Substitute equivalents from your own device if these are absent. Anything
`service-recon.py` rated `OPEN` will do for two of them, and anything it rated
`SIGNATURE` for the third.

```bash
# host
adb logcat -c
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.android.keychain/com.android.keychain.KeyChainService,com.android.settings/com.android.settings.wifi.MiuiWifiService,com.miui.analytics/com.miui.analytics.AnalyticsService'
sleep 9
adb logcat -d -s CH28
```

Reference output, trimmed:

```text
CH28: probe uid=10313 pid=21583

CH28: BIND-RETURN com.android.keychain/...KeyChainService  => true
CH28: BIND-RETURN com.android.settings/.wifi.MiuiWifiService => false
      SecurityException: Not allowed to bind to service
      Intent { cmp=com.android.settings/.wifi.MiuiWifiService }
CH28: BIND-RETURN com.miui.analytics/...AnalyticsService   => true

CH28: CONNECTED com.miui.analytics/...AnalyticsService
      descriptor='com.miui.analytics.ICore' alive=true ping=true local=false
CH28:   TX code=1 ok=true replyBytes=100
        exception=java.lang.SecurityException: Binder invocation to an incorrect interface
CH28:   TX code=2 ok=true replyBytes=100  exception=...incorrect interface
CH28:   TX code=3 ok=true replyBytes=100  exception=...incorrect interface

CH28: SUMMARY [KeyChainService=true, MiuiWifiService=false, AnalyticsService=true]
CH28: PROBE-DONE
```

### 4.1 Read it carefully

**Q2.** `KeyChainService` returned `true`. Did you connect to it?

<details>
<summary>Answer</summary>

**No.** There is no `CONNECTED` line for it, anywhere, and the probe waited six
seconds.

`bindService` returning `true` means the request was *accepted*: the component
resolved, you passed the permission check, and the system will try. It does not
mean a binder came back. `KeyChainService.onBind` returns a binder only for the
action it expects, and the probe deliberately sends a bare component Intent with
no action, so it returned `null`.

From API 28 you can observe this directly by implementing
`ServiceConnection.onNullBinding`.

**This is the outcome that produces false positives.** A tester who records
`bindService → true` against the system credential store and writes it up has
filed a critical finding about a connection that never existed.
</details>

**Q3.** `MiuiWifiService` returned `false` **and threw**. What does the throw tell
you that a bare `false` would not?

<details>
<summary>Answer</summary>

That the component **exists** and that something **refused** you. `ContextImpl`
throws when `system_server` returned a negative result — `exported="false"` with
a different UID, or `android:permission` not held. A bare `false` (result zero)
means the Intent did not resolve at all.

Cross-check which it was:

```bash
adb shell pm query-services -n com.android.settings/.wifi.MiuiWifiService
#   enabled=true exported=true
#   permission=com.xiaomi.permission.ACCESS_WIFI
adb shell "pm list permissions -f -g | grep -A4 ACCESS_WIFI"
#   protectionLevel:signature
```

Exported, guarded by a signature-level permission. **This is a control observed,
not a finding**, and it belongs in the report as one.
</details>

**Q4.** `AnalyticsService` connected and reported
`descriptor='com.miui.analytics.ICore'`. Where did that string come from, and
what did it cost you?

<details>
<summary>Answer</summary>

From the service itself. `IBinder.getInterfaceDescriptor()` is transaction code
`1598968902` — the ASCII bytes `'_NTF'`, `INTERFACE_TRANSACTION` — and **every**
Binder object in the system answers it, for free, to anyone holding a handle.

It cost you nothing and no APK. You now know the AIDL interface name, which is
the fastest possible starting point for finding the `Stub` in a decompiled APK.

Any report sentence of the form "the interface is not publicly documented, which
provides some protection" is wrong, and this line is the evidence.
</details>

**Q5.** The empty-parcel probes at codes 1–3 all returned
`SecurityException: Binder invocation to an incorrect interface`. What does that
tell you about the object, and what would `ok=false` with an empty reply have
meant instead?

<details>
<summary>Answer</summary>

`SecurityException: ...incorrect interface` comes from
`Parcel.enforceInterface`, which is generated into every AIDL `Stub.onTransact`.
So: **this is an AIDL `Stub`**, the code is live, and the only thing in your way
is a public string you have already been given.

`ok=false` with an empty reply would mean a raw `Binder` whose `onTransact`
returned `false` — the code is not handled. Keep sweeping.

A third possibility, `ok=true` with a non-empty reply and no exception, means the
method **ran** with no arguments and no token check. If you see that, you have
already changed something.
</details>

---

## 5. Step 4 — the controlled experiment that changes how you test

This is the most important part of the lab.

```bash
# host -- pick a THIRD-PARTY app on your device, not a system one
adb shell pm list packages -3 | head
python3 ../../scripts/service-recon.py --open --package com.vendor.fileexplorer
```

Bind it:

```bash
# host
adb logcat -c
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.vendor.fileexplorer/com.google.firebase.iid.FirebaseInstanceIdService'
sleep 8
adb logcat -d -s CH28
```

Reference result **with** `QUERY_ALL_PACKAGES` in the manifest:

```text
CH28: BIND-RETURN com.vendor.fileexplorer/...FirebaseInstanceIdService => true
CH28: CONNECTED ... descriptor='' alive=true ping=true local=false
CH28:   TX code=1 ok=false replyBytes=0 exception=(none)
```

Now remove the permission and rebuild:

```bash
# host
cp AndroidManifest.xml /tmp/manifest.bak
grep -v QUERY_ALL_PACKAGES /tmp/manifest.bak > AndroidManifest.xml
sh build.sh
adb uninstall com.pentest.ch28probe
sh build.sh install          # or: sh build.sh install root

adb logcat -c
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.vendor.fileexplorer/com.google.firebase.iid.FirebaseInstanceIdService'
sleep 8
adb logcat -d -s CH28
```

Reference result **without** it:

```text
CH28: BIND-RETURN com.vendor.fileexplorer/...FirebaseInstanceIdService => false
```

No exception. Nothing else in logcat. No denial anywhere on the device.

Restore it:

```bash
# host
cp /tmp/manifest.bak AndroidManifest.xml
sh build.sh && adb uninstall com.pentest.ch28probe && sh build.sh install
```

**Q6.** What just happened, and what would you have concluded if you had only run
the second version?

<details>
<summary>Answer</summary>

**Package visibility filtering.** From API 30, an app whose `targetSdk` is 30 or
higher cannot see most other packages. A filtered package behaves *exactly* like
a component that does not exist: `bindService` returns `false`, throws nothing,
and logs nothing.

Without the first run you would have written "not reachable" about a service that
is wide open. On API 30+ this is the leading cause of false negatives in service
testing, and it is invisible — there is no denial to find.
</details>

**Q7.** Is package visibility a mitigation? Would you list it as one?

<details>
<summary>Answer</summary>

**No, and no.**

`QUERY_ALL_PACKAGES` is available to any app that requests it. A `<queries>`
element naming one specific target package needs **no permission at all**:

```xml
<queries>
    <package android:name="com.example.target"/>
</queries>
```

Package visibility is an **anti-enumeration** measure: it stops apps
*inventorying* the device, which is a privacy control and a real one. It does not
stop an attacker who already knows what they are attacking, which is every
attacker in this threat model.

Listing it as a mitigation in a report is a factual error, and a developer who
believes it will stop looking for the real fix.
</details>

**Q8.** The descriptor came back as `''`. What kind of object is that, and why is
it *more* interesting than an AIDL one?

<details>
<summary>Answer</summary>

An empty descriptor means a **raw `Binder`**, not a generated AIDL `Stub`. There
is no `enforceInterface` call, so **nothing enforces an interface token at all**
and every transaction code is reachable with an empty parcel.

That is more interesting because with AIDL you at least know the code layout from
the `.aidl` ordering and can find the `Stub` in the APK. A hand-written
`onTransact` has no schema anywhere, which means undocumented codes doing
undocumented things. [25 §3.9](../../25-Binder/README.md).
</details>

---

## 6. Step 5 — the four outcomes, as a decision table

Fill this in from your own device before moving on.

| Your target | `bindService` | Exception | `CONNECTED`? | Descriptor | Diagnosis |
|---|---|---|---|---|---|
| | | | | | |
| | | | | | |
| | | | | | |
| | | | | | |

The diagnoses, for reference:

| Return | Exception | Connected | Diagnosis |
|---|---|---|---|
| `true` | — | yes | **Reachable.** Now find out what the methods do |
| `true` | — | **no** | `onBind` returned `null`. Try again with an action from the manifest |
| `false` | `SecurityException` | no | **A real gate.** `exported=false`, or a permission you do not hold |
| `false` | **none** | no | **Package visibility.** Not a control. Add `<queries>` and re-run |

---

## 7. Step 6 — turning a connection into evidence

A connection is still not a finding. Take one service you connected to and answer
three questions **with evidence**:

**1. What interface does it expose?** You already have the descriptor. Now get the
methods:

```bash
# host
adb shell pm path com.miui.analytics
adb pull /system/.../MiuiAnalytics.apk .
jadx -d out/ MiuiAnalytics.apk
grep -rn "ICore\$Stub\|extends ICore.Stub" out/sources/ | head
grep -rn "TRANSACTION_" out/sources/ | head -20
```

**2. Does any method do something you could not do yourself?** Read the `case`
bodies. A method that returns the app's version string is not a finding, however
reachable.

**3. Does the method check its caller?**

```bash
# host
grep -rn -A20 "ICore\$Stub" out/sources/ | grep -E "getCallingUid|checkSignatures|checkCallingPermission|enforce"
```

If that grep is empty for a method that does something interesting, you have a
finding. If it is not empty, you have a control observed.

> **🔍 Pentester's Note**
> Stop when you have an answer, and be willing for the answer to be "nothing".
> The chapter's own audit of the reference device stopped exactly here for the
> three real system services it probed: reaching `com.miui.analytics.ICore` is
> not a finding, and the chapter says so rather than padding the result.

---

## 8. Success criteria

- [ ] `out/probe.apk` built from source on your machine, under 20 KB.
- [ ] It is installed, and you can state its uid.
- [ ] You have produced **at least three** of the four outcomes in the decision
      table from real services on your device, with the logcat lines to prove it.
- [ ] You have run the `QUERY_ALL_PACKAGES` experiment in both directions and
      can state what a bare `false` means.
- [ ] You can name one service you *connected* to and one you *could not*, and
      say precisely why for each.
- [ ] You have written one sentence explaining why "reachable" and "vulnerable"
      are different, using a service from your own device as the example.

---

## 9. Common mistakes in this lab

| Mistake | Consequence |
|---|---|
| Recording `bindService → true` as reachability | False positive. Measured: `KeyChainService` |
| Recording `bindService → false` as protection | False negative. Measured: package visibility |
| Building without `QUERY_ALL_PACKAGES` and not noticing | Every third-party target silently unreachable |
| Testing from `adb shell` and generalising | The shell is exempt from visibility filtering and is not `untrusted_app` |
| Sweeping transaction codes on system services | These are **not** read-only probes. There is no schema telling you which codes mutate state. Do it on a device you can reflash |
| Reporting a connection with no method-level evidence | See §7 |
| Quoting a root-installed result as "an unprivileged app can" without saying root was used to install | Materially misleading |
| Using build-tools 34.0.0 and blaming the source | `d8` bug; use 35.0.1+ |

---

## 10. Cleanup

```bash
# host
adb uninstall com.pentest.ch28probe
rm -rf out
```

**Do not leave the prober installed on a device you care about.** Its own
`ProbeActivity` is `exported="true"` so that `am start` can drive it, which means
any app on the device can start it and hand it a target list.

---

## Next

[Lab 03 — The check that does nothing](lab-03-the-check-that-does-nothing.md)
builds a victim service with a caller check in the wrong place, and watches both
sides of the same connection disagree about who is calling.
