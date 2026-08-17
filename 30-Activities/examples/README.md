# 30 — Activities: examples

Two complete, buildable Android applications and two standalone teaching files. Everything here is
**source**; the repository never ships built APKs, and `build.sh` writes its output out of tree.

> **⚠️ Authorised testing only**
> `victim-app` is deliberately vulnerable and `hijacker-app` deliberately squats a task affinity and
> draws an overlay over other applications. Install them on a device you own, and uninstall them when
> you are done. Never point a `taskAffinity` at an application you do not own.

---

## Build and install

```bash
# host — build both APKs out of tree (nothing is written into the repository)
./build.sh

# host — build and install on the attached device
./build.sh --install

# host — choose where the artefacts go
OUTDIR=/tmp/ch30 ./build.sh --install

# host — remove both apps
./build.sh --uninstall
```

Requirements: an Android SDK with build-tools (`aapt2`, `d8`, `zipalign`, `apksigner`) and one
platform `android.jar`; a JDK with `javac` and `keytool`; `adb` for `--install`. No Gradle, no Android
Studio, no network.

If `adb install` fails with `INSTALL_FAILED_USER_RESTRICTED`, that is an OEM "Install via USB" gate
and **not** a fault in the APK — the message "Install canceled by user" is untrue. `build.sh` detects
that exact failure and falls back to `su -c 'pm install -r ...'` automatically. See
[README §7.8](../README.md) for the full diagnosis and the non-root alternatives.

---

## Layout

Source files are kept **flat** in each app directory. `build.sh` lays them out into the package
directories `javac` expects, at build time, under `$OUTDIR`. This is the same convention
[24-IPC](../../24-IPC/examples/) and [08-Build-System](../../08-Build-System/) use, and it keeps the
repository readable — nobody wants to click through
`src/main/java/com/pentest/ch30/victim/` to find one file.

```
examples/
  build.sh                     builds both apps out of tree
  DeputyActivity.java          the vulnerable deputy   (annotated teaching copy)
  DeputyActivityFixed.java     the fixed counterpart   (annotated teaching copy)
  victim-app/
    AndroidManifest.xml
    Base.java                  shared superclass: logs taskId + instance identity
    MainActivity.java          LAUNCHER, standard, default affinity
    AlphaActivity.java         launchMode=standard
    BetaActivity.java          launchMode=singleTop
    GammaActivity.java         launchMode=singleTask
    DeltaActivity.java         launchMode=singleInstance
    EpsilonActivity.java       non-default taskAffinity, same package
    InternalActivity.java      exported=false; opens the vault for its own app
    VaultActivity.java         the CTF target (lab-05)
    ConsentActivity.java       tapjacking target: no obscured-touch filtering
    ConsentSafeActivity.java   the hardened counterpart
    SecretProvider.java        exported=false, grantUriPermissions=true
  hijacker-app/
    AndroidManifest.xml
    HijackActivity.java        taskAffinity squat + singleTask
    ReparentActivity.java      allowTaskReparenting variant
    CrossStartActivity.java    cross-package start, with and without NEW_TASK
    DeputyExploitActivity.java builds the nested-Intent payload
    GrantSinkActivity.java     where a laundered grant is cashed in
    TapjackActivity.java       raises/drops the overlay
    OverlayService.java        the overlay window itself
```

> **Note on `DeputyActivity.java` and `DeputyActivityFixed.java`.** These live one level up rather
> than inside `victim-app/`, because they are the chapter's two headline teaching files and §9.2 of
> the README walks them line by line. `build.sh` copies them into the victim's source tree at build
> time, so there is exactly one copy of each and no possibility of the README and the app drifting
> apart.

---

## What each file is for

### `victim-app`

| File | Purpose | Used by |
|---|---|---|
| `AndroidManifest.xml` | Two deliberate vulnerabilities and nothing else. In particular it does **not** set `android:taskAffinity=""` — that absence is what lab-02 measures against. | all labs |
| `Base.java` | Logs `getTaskId()`, `System.identityHashCode(this)` and `getCallingActivity()` on every lifecycle event. `identityHashCode` is what distinguishes "the system reused the instance" from "the system built a new one" — the `ActivityRecord` hash in `dumpsys` cannot tell you that. | lab-01 |
| `Alpha` / `Beta` / `Gamma` / `Delta` | One launch mode each, and no logic of their own, so anything you observe is attributable to the manifest. | lab-01 |
| `EpsilonActivity` | A non-default affinity **inside the app's own package** — the control proving the task boundary follows the affinity string, not the package. | lab-01 |
| `InternalActivity` | `exported="false"`. The control for confused-deputy reachability, and the app's own legitimate route into the vault. | lab-03, lab-05 |
| `VaultActivity` | Exported, `singleTop`, authorises with `getCallingActivity()` **once** in `onCreate` and caches the answer. The CTF target. | lab-05 |
| `ConsentActivity` | A consequential button with **no** `filterTouchesWhenObscured`. Logs the `MotionEvent` flags so you can see that the platform warned and the app ignored it. | lab-04 |
| `ConsentSafeActivity` | Identical, one line different. With filtering on, an obscured event never reaches the listener — so **absence** of a log line is the successful result. | lab-04 |
| `SecretProvider` | `exported="false"`, `grantUriPermissions="true"`. Logs `Binder.getCallingUid()` on every query, which is the strongest available evidence in the grant-laundering finding. | lab-03, lab-05 |

### `hijacker-app`

| File | Purpose | Used by |
|---|---|---|
| `AndroidManifest.xml` | **The attack lives here, not in the code.** Two attributes on one `<activity>` are the entire StrandHogg payload. | lab-02 |
| `HijackActivity` | `taskAffinity` naming the victim + `launchMode="singleTask"`. Bright red, so the lab's outcome is legible at a glance. | lab-02 |
| `ReparentActivity` | The `allowTaskReparenting` variant, tested separately because the two variants are handled by different code. | lab-02 |
| `CrossStartActivity` | Not an attack — a measuring instrument. `adb shell am` always implies `FLAG_ACTIVITY_NEW_TASK`, so the "joins the caller's task" case is unreachable from the shell. This is how you reach it. | lab-01 |
| `DeputyExploitActivity` | Builds an `Intent` nested inside another `Intent`'s extras. `am` has no `--eparcelable`, so this payload cannot be sent from the shell at all. Prints all three possible control outcomes by name. | lab-03, lab-05 |
| `GrantSinkActivity` | Where the laundered grant is cashed in. Prints the stolen value, or the denial verbatim. | lab-03 |
| `TapjackActivity` | Exists only because a background app may not start a Service from API 26. Its header documents both traps that produce the identical misleading error. | lab-04 |
| `OverlayService` | `TYPE_APPLICATION_OVERLAY` + `FLAG_NOT_TOUCHABLE` + `FLAG_NOT_FOCUSABLE`. A Service, because an Activity's window is removed the moment the victim comes forward. | lab-04 |

---

## Deliberate lab affordances

Two things in these apps are **not** what real malware looks like. They are called out here so that
nobody learns a wrong recognition pattern from a lab:

| Affordance | Why it is here | What real malware does |
|---|---|---|
| `OverlayService` is `android:exported="true"` | So `am startservice` can raise and drop the overlay without a UI | Starts its overlay service from inside its own process and exports nothing. **When auditing an APK, do not expect the overlay service to be exported.** |
| `DeputyExploitActivity`, `CrossStartActivity` and `TapjackActivity` are exported | So the labs can be driven entirely from `adb` | An attacker app has one launcher Activity and does its work internally |

The `<queries>` element in the hijacker's manifest is **not** an affordance — a real attacker
targeting API 30+ declares it too, and leaving it out makes the grant-laundering control measure
package visibility instead of the provider's export state. See [README §7.5](../README.md).

---

## Package and uid notes

| | |
|---|---|
| Victim package | `com.pentest.ch30.victim` |
| Attacker package | `com.pentest.ch30.attacker` |
| Provider authority | `com.pentest.ch30.victim.secrets` |
| Deputy actions | `com.pentest.ch30.victim.FORWARD`, `...FORWARD_SAFE` |
| Log tag | `CH30` — `adb shell "logcat -d -s CH30:I"` |

Both apps target `targetSdkVersion 30` and `minSdkVersion 21`. `targetSdk 30` matters: it puts the
attacker under package-visibility filtering, which is realistic and which produces the trap in
[README §7.5](../README.md). Record the uids at the start of every lab —
several results are only legible if you know which uid is which:

```bash
# host
adb shell "dumpsys package com.pentest.ch30.victim   | grep userId=" | head -1
adb shell "dumpsys package com.pentest.ch30.attacker | grep userId=" | head -1
```

---

## Related

- [`../scripts/task-affinity-map.py`](../scripts/task-affinity-map.py) — the runtime task view.
- [`../scripts/activity-trace.js`](../scripts/activity-trace.js) — Frida, from inside the app.
- [`../labs/`](../labs/lab-01-read-the-task-graph.md) — the five labs that drive these apps.
- [26-Intent examples](../../26-Intent/examples/README.md) — the same two-app pattern applied to the
  Intent message rather than to the Activity.
