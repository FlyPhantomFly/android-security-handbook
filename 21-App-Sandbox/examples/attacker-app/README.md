# attacker-app — proving sandbox reachability from an ordinary application

> A minimal, dependency-free Android APK that probes what an ordinary,
> unprivileged app can actually reach of **another app's sandbox**, and prints
> one of five verdicts for every boundary it tests.

**Belongs to:** [21 — The Android Application Sandbox](../../README.md) — see §3.14, §5.8 and §9.3
**Lab:** [`../../labs/lab-03-attacker-app.md`](../../labs/lab-03-attacker-app.md)
**Companion:** [24-IPC's attacker-app](../../../24-IPC/examples/attacker-app/README.md) — same idea,
aimed at the IPC surface. Use both.

---

## 1. Why this exists

Almost every rejected Android finding is rejected for the same reason. The tester demonstrated
something from `adb shell`, wrote it up as "reachable by a malicious app", and a developer replied —
correctly — that it is not.

> **📖 Definition**
> **`adb shell`.** The interactive shell `adbd` gives you on the device. It runs as the Linux user
> `shell`, **UID 2000**, in the SELinux domain `shell`, with **no seccomp filter**, a **non-empty
> capability bounding set**, and supplementary groups no application holds. It can read
> `/data/local/tmp`, traverse directories an app cannot, and invoke `pm`, `am`, `dumpsys` and
> `run-as`. It is not an app.

> **⚠️ Warning**
> A file you read or a provider you queried from `adb shell` is **not** thereby proven reachable by an
> attacker. Reproducing the same operation from an ordinary installed app is a **different
> experiment** with a **different answer**, and only that second answer supports the sentence "any app
> the user installs can do this".

This APK is that second experiment. It is installed like any other app, receives an ordinary UID in
the 10000+ range, runs in the `untrusted_app` SELinux domain with its own MCS categories, gets
`Seccomp: 2` and an empty capability set — and declares exactly one permission, `INTERNET`, which is
`protectionLevel="normal"`, granted silently at install on every Android version, and never shown to
the user.

> **🧠 Mental Model**
> The shell is a maintenance engineer with a master key. This APK is a member of the public. Both can
> walk up to the same door. Only one of them tells you whether the door is locked.

---

## 2. What is in this directory

| File | What it is |
|---|---|
| `AndroidManifest.xml` | The manifest. Contains the **`<queries>`** block, which is the single most important element in this project — see §4. |
| `ProbeActivity.java` | The probe. Eight sections: own identity, package visibility, the target's private data, the target's shipped code, exported providers (including `openFile` traversal), shared storage, the clipboard, and `/proc`. |
| `build.gradle` | Single-module build, flat source layout, no dependencies. |
| `settings.gradle` | Makes this directory a standalone Gradle build. |

There are no third-party dependencies — not even AndroidX. That is deliberate. This APK is *evidence*:
a client engineer will install it and read its output, and the fewer non-platform classes it contains,
the less room there is to argue the result came from something other than the APIs any app can call.

---

## 3. Build and install

```bash
# host — from this directory
gradle assembleDebug

# or from the repository root
gradle -p 21-App-Sandbox/examples/attacker-app assembleDebug
```

No Gradle wrapper JAR is committed to this repository. If you want `./gradlew`, generate one once:

```bash
# host — in this directory
gradle wrapper --gradle-version 8.5
```

Then install:

```bash
# host
adb install -r build/outputs/apk/debug/attacker-app-debug.apk
adb logcat -c
```

Requirements: JDK 11 or 17, Gradle 7.5+ (or Android Studio), and an Android SDK with `compileSdk 33`.
If Gradle cannot find the SDK, create `local.properties` here containing
`sdk.dir=/absolute/path/to/Android/sdk`.

> **⚠️ Warning**
> `build.gradle` pins Android Gradle Plugin **7.4.2** on purpose. AGP 8.0 removed the `package="…"`
> attribute in `AndroidManifest.xml` in favour of `namespace` in `build.gradle`. To use AGP 8: bump
> the classpath version, add `namespace 'com.attacker.sandboxprobe'` to the `android { }` block, and
> delete the `package` attribute from the manifest. Nothing else changes.

---

## 4. Point it at a target — and fix `<queries>` first

Two things must be set per engagement.

**First, the target package.** Either edit `DEFAULT_TARGET` in `ProbeActivity.java`, or override it at
launch without rebuilding:

```bash
# adb shell
am start -n com.attacker.sandboxprobe/.ProbeActivity --es target com.example.target
```

**Second — and this is the one that catches everyone — the `<queries>` block.**

> **📖 Definition**
> **Package visibility filtering.** From `targetSdk` 30 (Android 11), an app can no longer see the
> full list of installed packages. It sees itself, a small set of always-visible system packages,
> packages it interacts with through certain APIs, and whatever it declares in `<queries>`.

This is a privacy control, not a security boundary. A real attacker simply declares the target, or
holds `QUERY_ALL_PACKAGES`. It never makes an exported component unreachable. But if *you* forget it,
the platform hides the target from your probe and every symptom looks like absence:

| Symptom with no `<queries>` entry | What it looks like | What it actually is |
|---|---|---|
| `getPackageInfo()` throws `NameNotFoundException` | "the app is not installed" | filtered |
| `getInstalledApplications()` returns a short list | "few apps on this device" | filtered |
| `ContentResolver.query()` throws `IllegalArgumentException: Unknown URL` | "no such provider" | filtered |
| Every data-directory probe returns `ABSENT` | "nothing there" | you never resolved the target |

> **🔍 Pentester's Note**
> Reporting "the target's data is not reachable from a third-party app" because your own manifest hid
> the target is a self-inflicted false negative, and it is common. The probe checks this in **section
> 1** of its output and tells you plainly which explanation applies. Read that section before reading
> anything else.

Providers need a second entry, by **authority**, not just by package:

```xml
<queries>
    <package  android:name="com.example.target" />
    <provider android:authorities="com.example.target.provider" />
</queries>
```

Harvest the real authorities from the target's manifest:

```bash
# host
apktool d -f target.apk -o work/ >/dev/null
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml
```

And check for a shared UID, because if one exists your whole analysis must be done at the granularity
of the group, not the app:

```bash
# adb shell
dumpsys package com.example.target | grep -i sharedUser
pm list packages -U | grep ':10412$'      # every package on that UID
```

---

## 5. Run it

```bash
# host
adb logcat -c
adb shell am start -n com.attacker.sandboxprobe/.ProbeActivity --es target com.example.target
adb logcat -s SANDBOXPROBE:W
```

The report also renders on screen, selectable, so you can screenshot it for a report appendix.

Run a subset while iterating:

```bash
# adb shell
am start -n com.attacker.sandboxprobe/.ProbeActivity \
   --es target com.example.target \
   --es only identity,provider,storage
```

Valid phase names: `identity`, `visibility`, `data`, `apk`, `provider`, `storage`, `clipboard`,
`procfs`.

Capture evidence:

```bash
# host
adb logcat -d -s SANDBOXPROBE:W > evidence/sandbox-probe-$(date +%Y%m%d-%H%M).txt
adb exec-out screencap -p       > evidence/sandbox-probe.png
```

> **⚠️ Warning**
> The clipboard section requires the probe to be in the **foreground**. Since Android 10 an app may
> read the clipboard only while it holds input focus or is the default IME. A `null` result from a
> background read is the platform working, not the target being safe.

---

## 6. How to read the results

Every line carries one of five verdicts. They are not interchangeable, and the difference between them
is the difference between a finding and an anecdote.

| Verdict | Meaning | What you may write in a report |
|---|---|---|
| `REACHABLE` | The operation succeeded from an ordinary app UID. | "An unprivileged third-party application can …" — the strongest claim available without root. |
| `DENIED` | The platform refused us: `SecurityException`, `EACCES`, `canRead()` false. | "Not reachable by a third-party application." Record it — ruling things out is part of the work, and a report that also says what is *safe* is more credible. |
| `ABSENT` | Does not exist **or** package visibility filtering is hiding it. | Nothing, until you have re-checked `<queries>` and read section 1. |
| `ERROR` | The target accepted the request and then threw. | **Still reachable.** The door opened; the room behind it was untidy. Often the most interesting result, because an unhandled exception means the input reached real code. |
| `INCONCLUSIVE` | The API cannot tell us. | Nothing. Go and get the missing evidence. |

Three traps the output warns about inline:

**A `null` cursor is not a denial.** A provider may return `null` because the URI did not match its
`UriMatcher`, not because it refused you. Harvest real paths from the decompiled provider's
`UriMatcher.addURI()` calls — see [27-ContentProviders](../../../27-ContentProviders/README.md).

**A `permission` attribute is not necessarily protection.** A custom permission with
`protectionLevel="normal"` is granted silently to any app that asks for it. Check the level before
recording a component as guarded; the probe marks these `INCONCLUSIVE` for exactly that reason.

**`ABSENT` on a data directory is a *good* result and needs a second look.** `File.exists()` returns
false when the path cannot be traversed, which is what mode `0700` on the parent produces. That is the
sandbox working. If it ever returns `REACHABLE`, check for `sharedUserId` first.

> **🔬 Under the Hood**
> Why does the target's data directory deny you but its APK does not? Two different files with two
> different owners and modes. `/data/data/<pkg>` is `0700` owned by the app's UID, and the missing
> execute bit blocks traversal one level up — so a careless `0666` file inside is still unreachable by
> another app. `/data/app/…/base.apk` is `0644` owned by `system`, and `PackageManager` hands out its
> path. The first is the sandbox's core claim; the second is the platform's deliberate design. See
> [§3.2 and §3.3](../../README.md#3-deep-internal-working).

---

## 7. What each probe actually proves

| Probe | Permission needed | What a `REACHABLE` proves |
|---|---|---|
| Target's data directory | none | **The sandbox has failed, or the two apps share a UID.** Investigate immediately — this should never happen. |
| Target's APK / native libs | none | Nothing on its own; it is the design. But it means every secret compiled into that APK is public. |
| Exported provider `query()` | none | Any installed app reads that data — no prompt, no interaction. Usually the highest-severity class, because a provider normally sits on a database. |
| Exported provider `openFile()` traversal | none | The target's **entire read authority**, because the target opened the file itself and the kernel never rechecks a descriptor. |
| Shared storage | varies by API level | Data that left the sandbox permanently — it survives the target's uninstall. |
| Clipboard | none, but foreground only | The target put something on a system-wide buffer. State the version and app state. |
| `/proc` | none | On API 29+ almost nothing. A closed side channel; note the closure rather than reporting it. |
| Package visibility | none | How much of the device an app can enumerate — a privacy property, not a security one. |

---

## 8. The discipline this app is meant to enforce

Run **both** experiments and record **both** results. The table is the artefact:

| Thing | From `adb shell` | From this APK | Verdict |
|---|---|---|---|
| `/data/data/com.example.target` | listed (with root) | `DENIED` | **Not** a finding — the sandbox held |
| `/data/local/tmp` | writable | `DENIED` | **Not** a finding — shell privilege only |
| `content://…/users` | rows returned | `REACHABLE` | Finding — any app can read it |
| `openFile ../shared_prefs/x.xml` | rows returned | `REACHABLE` | Finding — traversal, target's read authority |
| `/storage/emulated/0/app-debug.log` | readable | `REACHABLE` | Finding — data left the sandbox |

Then, for every `REACHABLE` row, do the part no tool does for you: **walk the reach-through.** What can
you make that thing do that you could not do directly? A door is only as serious as the room behind it.

> **⚠️ Warning**
> Severity comes from what the door reaches, not from the fact that it opened. An exported provider
> that returns a version string is **Low**. Reading the credential store is **High**. And an
> `openFile` traversal grants the *target's* read authority — not root, not arbitrary system access —
> so bound the claim by testing what it **cannot** reach, and say so.

Finally, record the ground truth the probe prints in its header: the target's `targetSdk`, your
device's build fingerprint, the Android release and the security patch level. Half the platform's
mitigations are `targetSdk`-gated, so a finding that is real against an app targeting API 28 may be
impossible against the same source targeting API 34.

> **🔍 Pentester's Note**
> Build the target at two `targetSdk` levels and run the probe against both. The rows that change are
> exactly the version-conditional findings, and knowing which those are is the difference between a
> report that survives review and one that does not.

---

## 9. Extending it

In rough order of value:

1. **Real provider paths** harvested from the decompiled `UriMatcher`, replacing the built-in guesses.
2. **The rest of the IPC surface** — activities, services with a transaction sweep, receivers,
   abstract UNIX sockets, localhost ports, and the confused-deputy path. That is a solved problem: use
   [24-IPC's attacker-app](../../../24-IPC/examples/attacker-app/README.md) rather than duplicating it.
3. **`MediaStore` enumeration** for shared-storage artefacts that are no longer directly listable on
   API 30+.
4. **A `sharedUserId` sweep**: for every package on the same UID as the target, repeat sections 2–4.
   The weakest member of the group defines the security of all of them.
5. **A backup probe**: check `FLAG_ALLOW_BACKUP` on the target and, on devices where it still works,
   attempt a transport-based backup — see [§5.5](../../README.md#5-security-perspective).
6. **`FLAG_SECURE` checking** across the target's screens, which pairs with the clipboard and screen
   capture material in §3.14.

> **🔍 Pentester's Note**
> Keep a generic build of this in your toolkit with the target package in an Intent extra, as here.
> Its real value is not the probing — it is that a client engineer can install the same APK and see
> the same output, which ends arguments about whether a finding is real.

---

## 10. Legal and safety

This app exists to prove reachability against applications you own or have written authorisation to
test. Everything it does is available to any app the user installs, which is exactly why the findings
matter — and exactly why running it against third-party software without permission is not acceptable.

The probe only reads. It does not write to, modify, or delete anything belonging to another
application. It is nonetheless an app that enumerates other applications' data, which in many
jurisdictions is a criminal offence on a device you do not own, regardless of intent. Use a dedicated
test device. Keep it off the Play Store; it would be flagged, correctly, as a Potentially Harmful
Application.
