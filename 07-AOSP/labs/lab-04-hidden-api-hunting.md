# Lab 04 — Hidden APIs and the blocklist

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Chapter:** [07 — AOSP](../README.md) §3.7, §3.8
**Setup required:** any device or emulator with adb (API 28+), and Android Studio or Gradle

---

## Objective

Reach a hidden framework API by reflection, watch the blocklist deny it, change the policy and watch it
succeed, change your `targetSdk` and watch the `max-target-X` rule fire — then map a real `@SystemApi`
surface to the permissions that gate it, which is the skill you use when auditing preinstalled apps.

---

## Why this matters to a tester

Three concrete reasons, and all three come up in real engagements.

1. **Your tooling depends on it.** Frida's Java bridge, most instrumentation frameworks, and every app
   that reaches `ServiceManager` all go through reflection into `@hide` classes. When they misbehave on
   a particular device, hidden-API policy is one of the first things to check.
2. **It changes app behaviour, silently.** A denial throws an ordinary `NoSuchMethodException`, so an
   app that catches broadly behaves differently with no visible cause. "The app stopped working
   after we bumped `targetSdk`" is very often this.
3. **`@SystemApi` is the map of privileged capability.** When you decompile an OEM or carrier app and
   find calls you do not recognise, the system API surface tells you whether you have found something
   privileged — and therefore whether reaching that app's exported components is worth pursuing.

---

## Setup

```bash
# host
adb devices
adb shell getprop ro.build.version.sdk          # must be 28+
adb shell settings get global hidden_api_policy  # record the STARTING value
```

**Record the starting value.** You will reset it at the end.

Build the probe app from [`../examples/02-HiddenApiProbe.kt`](../examples/02-HiddenApiProbe.kt).

```kotlin
// app/build.gradle.kts
android {
    namespace = "com.example.hiddenapiprobe"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.example.hiddenapiprobe"
        minSdk = 26
        targetSdk = 35              // you will change this in Part C
    }
}
```

```bash
# host
./gradlew installDebug
```

---

## Part A — Observe enforcement at the default policy

### A1. Confirm the default

```bash
# host
adb shell settings delete global hidden_api_policy
adb shell settings get global hidden_api_policy       # expect: null
```

`null` means the platform default, which is full enforcement.

### A2. Run the probe

```bash
# host
adb logcat -c
adb shell am force-stop com.example.hiddenapiprobe
adb shell am start -n com.example.hiddenapiprobe/.MainActivity
sleep 2
adb logcat -d -s HiddenApiProbe
```

**Record**, as a table, for each of the five probe groups: which accesses returned `[OK ]` and which
returned `[DENY]`, and the exception type for each denial.

### A3. Watch the platform's own log

```bash
# host
adb logcat -c
adb shell am force-stop com.example.hiddenapiprobe
adb shell am start -n com.example.hiddenapiprobe/.MainActivity
sleep 2
adb logcat -d | grep -i "Accessing hidden"
```

**Record:** three lines verbatim. Note the *list name* each line reports — `unsupported`,
`max-target-X`, or `blocked`. That is the platform telling you exactly which list a member is on.

### A4. Explain the pattern

Some of the probes succeed even at full enforcement. `SystemProperties`, `ActivityThread` and
`ServiceManager` are all `@hide`, and all are widely reachable.

**Record:** why. (Hint: what would happen to the app ecosystem if Google blocked them outright? The
answer is the entire design rationale for the `unsupported` list.)

---

## Part B — Change the policy

### B1. JUST_WARN

```bash
# host
adb shell settings put global hidden_api_policy 1
adb shell am force-stop com.example.hiddenapiprobe
adb logcat -c
adb shell am start -n com.example.hiddenapiprobe/.MainActivity
sleep 2
adb logcat -d -s HiddenApiProbe
```

**Record:** which previously-denied accesses now succeed.

### B2. DISABLED

```bash
# host
adb shell settings put global hidden_api_policy 0
adb shell am force-stop com.example.hiddenapiprobe
adb logcat -c
adb shell am start -n com.example.hiddenapiprobe/.MainActivity
sleep 2
adb logcat -d | grep -i "Accessing hidden" | wc -l
```

**Record:** the count of "Accessing hidden" lines at policy 0 versus policy 1. What is the difference
between the two settings?

### B3. The observations that matter

**Record answers to all four:**

1. Did you need root? Did you need a userdebug build?
2. Which UID holds the permission that made `settings put global` work, and what is that permission
   called?
   ```bash
   adb shell dumpsys package com.android.shell | grep -i WRITE_SECURE_SETTINGS
   ```
3. Does the setting survive a reboot? Test it.
   ```bash
   adb reboot && adb wait-for-device && sleep 30
   adb shell settings get global hidden_api_policy
   ```
4. Why does that mean you must record the value in your evidence, and reset it before handing a device
   back?

### B4. Reset

```bash
# host
adb shell settings delete global hidden_api_policy
adb shell settings get global hidden_api_policy
```

---

## Part C — The `max-target-X` rule

This is the part that explains a very common real-world bug report.

### C1. Lower `targetSdk`

```kotlin
// app/build.gradle.kts
defaultConfig {
    targetSdk = 28          // was 35
}
```

```bash
# host
adb shell settings delete global hidden_api_policy     # back to full enforcement
./gradlew installDebug
adb shell am force-stop com.example.hiddenapiprobe
adb logcat -c
adb shell am start -n com.example.hiddenapiprobe/.MainActivity
sleep 2
adb logcat -d -s HiddenApiProbe
```

### C2. Diff

**Record:** which accesses succeed at `targetSdk = 28` that were denied at `targetSdk = 35`, with the
policy identical in both runs.

### C3. Explain the mechanism

**Record**, in complete sentences:

- What the `max-target-X` lists do, and what X refers to.
- Why the platform is designed this way — what compatibility problem does it solve?
- **The real-world consequence:** a client says "our app broke when we bumped `targetSdk` from 28 to 33
  and we cannot work out why". What would you check first, and what command would you run?

### C4. Verify against the published list

Find one of the members that changed behaviour in the official non-SDK interface list:

<https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces>

**Record:** the member, the list it is on, and whether the list matches what you observed.

---

## Part D — Mapping the `@SystemApi` surface

Now the auditing skill.

### D1. Read the surface

On [cs.android.com](https://cs.android.com/), with the branch set to your device's release:

```
file:core/api/system-current.txt
```

(If empty, try `frameworks/base/api/system-current.txt` — the path moved during the Mainline refactor.)

**Record:** roughly how many lines it is, and three system APIs whose names suggest genuinely privileged
capability.

### D2. Find what gates one

Pick one of your three. Find its implementation and identify the permission that guards it.

```
# cs.android.com
function:<theMethodName> path:frameworks/base
```

Then find the permission's declaration:

```
file:core/res/AndroidManifest.xml content:"<THE_PERMISSION_NAME>"
```

**Record:** the method, the permission, and its exact `protectionLevel`. Then answer: **can a
third-party app hold it?** Justify from the protection level, not from intuition.

**Verify on a device:**

```bash
adb shell pm list permissions -f | grep -A4 <THE_PERMISSION_NAME>
```

### D3. Find who holds it

```bash
# adb shell — which packages have been granted this permission?
dumpsys package | grep -B30 "<THE_PERMISSION_NAME>" | grep "Package \[" | head -20

# adb shell — the privileged permission allow-list
cat /system/etc/permissions/privapp-permissions-platform.xml | grep -B2 -A2 "<THE_PERMISSION_NAME>"
```

**Record:** which preinstalled packages hold it.

### D4. The auditing question

For one package that holds a privileged permission, answer:

- Does it export any components?
  ```bash
  adb shell dumpsys package <pkg> | sed -n '/Activity Resolver Table/,/Permissions:/p'
  ```
- Are any of them reachable by a third-party app?
- If a third-party app could reach one, could it induce that package to exercise its privileged
  capability on the attacker's behalf?

**Record:** your reasoning. This is the confused-deputy question ([§5.3.2](../README.md#532-the-confused-deputy-across-clearcallingidentity))
asked from the outside, and it is exactly how privileged preinstalled apps are audited.

---

## Part E — Hidden APIs in a real app

### E1. Find non-SDK usage in something you did not write

```bash
# host — pick any APK
jadx -d decompiled some-app.apk

rg -n "com\.android\.internal|android\.os\.ServiceManager|SystemProperties|VMRuntime" \
   decompiled/sources/ | head -30

# reflection into hidden classes is the give-away
rg -n 'Class\.forName\("android\.|Class\.forName\("dalvik\.|Class\.forName\("com\.android\.internal' \
   decompiled/sources/ | head -20
```

**Record:** every hidden class the app reaches, and for each, one sentence on what it is probably for.
Common findings and their usual purpose:

| Reference | Usually means |
|---|---|
| `android.os.SystemProperties` | Root or emulator detection, or device fingerprinting |
| `android.os.ServiceManager` | Talking directly to a system service with no public SDK |
| `dalvik.system.VMRuntime` | A hidden-API bypass, or heap manipulation |
| `com.android.internal.*` | Using internal framework classes; check *which* |
| `android.app.ActivityThread` | Getting the `Application` from a static context — very common in libraries |

### E2. Test the consequence

```bash
# host
adb shell settings put global hidden_api_policy 2       # full enforcement
adb logcat -c
# exercise the app
adb logcat -d | grep -i "Accessing hidden" | grep <the-app-package>
```

**Record:** which of the app's hidden-API accesses the platform logged, and whether the app behaved
differently.

---

## Success criteria

- [ ] You recorded the device's starting `hidden_api_policy` and reset it at the end.
- [ ] You have a table of probe results at policy 2, 1 and 0.
- [ ] You captured "Accessing hidden" log lines and identified the list name in them.
- [ ] You demonstrated the `max-target-X` rule by changing only `targetSdk`.
- [ ] You can state, from your own testing, whether `settings put global hidden_api_policy` needs root
      and whether it survives a reboot.
- [ ] You traced one `@SystemApi` method to the permission that gates it, and read that permission's
      `protectionLevel` from `frameworks/base/core/res/AndroidManifest.xml`.
- [ ] You identified which preinstalled packages hold that permission and whether any export a component.
- [ ] You found hidden-API usage in an app you did not write and explained what each reference is for.

---

## Common mistakes in this lab

| Mistake | Why it costs you |
|---|---|
| Forgetting to `am force-stop` between runs | The old process keeps running with the old policy; your results are stale |
| Not resetting `hidden_api_policy` afterwards | You changed the platform's behaviour for every app on someone's device |
| Not recording the policy value in evidence | A colleague cannot reproduce your result, and neither can you |
| Assuming a denial means "the app is doing something bad" | Ordinary apps and libraries reach hidden APIs constantly. The question is *which* one and *what for*. |
| Concluding a `@SystemApi` is unreachable because it needs a permission | Check whether a *preinstalled app that holds it* exposes a route to it. That is the finding. |
| Testing on one Android version and generalising | The lists change between releases. Record the version. |

---

## Discussion questions

1. The blocklist is enforced by ART, in-process, on data ART itself holds. What does that imply about
   whether it is a *security* boundary or a *compatibility* mechanism? Support your answer from
   [§3.8](../README.md#38-the-hidden-api-blocklist), and say what that means for how you should
   describe it in a report.
2. `settings put global hidden_api_policy 1` works over plain adb on retail devices. Is that a
   vulnerability? Argue both sides, then commit to one — and consider who can run `adb shell` and what
   else that person can already do.
3. Bypass libraries typically reach `VMRuntime.setHiddenApiExemptions`, itself a hidden method. Explain
   the bootstrapping problem that creates, and why the bypass nonetheless works.
4. You are auditing an OEM's preinstalled app. It calls twelve `@SystemApi` methods. Describe the
   process you would follow to decide which of the twelve, if any, are worth spending a day on.
