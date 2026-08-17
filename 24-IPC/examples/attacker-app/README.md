# attacker-app — proving IPC reachability from an ordinary application

> A minimal, dependency-free Android APK that probes another app's IPC surface
> from an unprivileged application UID, and prints `REACHABLE` or `DENIED` for
> every door it tries.

**Belongs to:** [24-IPC](../../README.md) — see §3.22 step 4, §7.6 and §9.3
**Related:** [77-UsefulCommands lab 03](../../../77-UsefulCommands/labs/lab-03-exported-sweep.md)

---

## 1. Why this exists

Almost every rejected Android IPC finding is rejected for the same reason. The
tester demonstrated something from `adb shell`, wrote it up as "reachable by a
malicious app", and a developer replied — correctly — that it is not.

> **📖 Definition**
> **`adb shell`.** The interactive shell `adbd` gives you on the device. It runs
> as the Linux user `shell`, **UID 2000**, in the SELinux domain `shell`. That
> user is not an application. It holds capabilities and SELinux permissions that
> no installed app has, including the ability to start some components,
> read some providers, and traverse directories an app cannot.

> **⚠️ Warning**
> A component you launched with `am start` is **not** thereby proven reachable
> by an attacker. `am` runs in your shell's context, with your shell's identity.
> Reproducing the same operation from an ordinary app is a **different
> experiment** with a **different answer**, and only that second answer supports
> the sentence "any app the user installs can do this".

This APK is that second experiment. It is installed like any other app, is
assigned an ordinary UID in the 10000+ range, runs in the `untrusted_app`
SELinux domain, and declares exactly one permission — `INTERNET`, which is
granted silently at install to every app on every Android version and is never
shown to the user.

> **🧠 Mental Model**
> Think of the shell as a maintenance engineer with a master key, and this APK
> as a member of the public. Both can walk up to the same door. Only one of them
> tells you whether the door is locked.

---

## 2. What is in this directory

| File | What it is |
|---|---|
| `AndroidManifest.xml` | The manifest. Contains the **`<queries>`** block, which is the single most important line in this project — see §4. |
| `ProbeActivity.java` | The probe. Enumerates and exercises activities, services, receivers, providers, abstract sockets, localhost ports, and the confused-deputy path. |
| `GrantSink.java` | Where a **stolen content-URI grant** lands, and where it is used. Turns "the deputy forwarded our Intent" into rows of the victim's data in a log line. |
| `Eavesdropper.java` | Passive broadcast listener at maximum priority. Catches the **sending-direction** leak that manifest analysis of the target can never show. |
| `build.gradle` | Single-module build, flat source layout, no dependencies. |
| `settings.gradle` | Makes this directory a standalone Gradle build. |

There are no third-party dependencies — not even AndroidX. That is deliberate.
This APK is *evidence*: a client engineer will install it and read its output,
and the fewer non-platform classes it contains, the less room there is to argue
that the result came from something other than the APIs any app can call.

---

## 3. Build and install

```bash
# host — from this directory
gradle assembleDebug

# or from the repository root
gradle -p 24-IPC/examples/attacker-app assembleDebug
```

No Gradle wrapper JAR is committed to this repository. If you want `./gradlew`
to work, generate one once:

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

Requirements: JDK 11 or 17, Gradle 7.5+ (or Android Studio), and an Android SDK
with `compileSdk 33` installed. If Gradle cannot find the SDK, create
`local.properties` here containing `sdk.dir=/absolute/path/to/Android/sdk`.

> **⚠️ Warning**
> `build.gradle` pins Android Gradle Plugin **7.4.2** on purpose. AGP 8.0 removed
> the `package="…"` attribute in `AndroidManifest.xml` in favour of `namespace`
> in `build.gradle`. If you prefer AGP 8: bump the classpath version, add
> `namespace 'com.attacker.poc'` to the `android { }` block, and delete the
> `package` attribute from the manifest. Nothing else changes.

---

## 4. Point it at a target — and fix `<queries>` first

Two things must be set for each engagement.

**First, the target package name.** Either edit `DEFAULT_TARGET` in
`ProbeActivity.java`, or override it at launch without rebuilding:

```bash
# adb shell
am start -n com.attacker.poc/.ProbeActivity --es target com.example.target
```

**Second — and this is the one that catches everyone — the `<queries>` block in
`AndroidManifest.xml`.**

> **📖 Definition**
> **Package visibility filtering.** From `targetSdk` 30 (Android 11), an app can
> no longer see the full list of installed packages. It sees only: itself, a
> small set of always-visible system packages, packages it interacts with
> through certain APIs, and whatever it declares in a `<queries>` element.

This is a privacy control, not a security boundary. A real attacker simply
declares the target, or holds `QUERY_ALL_PACKAGES`. It never makes an exported
component unreachable. But if *you* forget it, the platform hides the target
from your probe and every symptom looks like absence:

| Symptom with no `<queries>` entry | What it looks like | What it actually is |
|---|---|---|
| `getPackageInfo()` throws `NameNotFoundException` | "the app is not installed" | filtered |
| `resolveActivity()` returns `null` | "no such component" | filtered |
| `startActivity()` throws `ActivityNotFoundException` | "not reachable" | filtered |
| `ContentResolver.query()` throws `IllegalArgumentException: Unknown URL` | "no such provider" | filtered |

> **🔍 Pentester's Note**
> Reporting "no exported components are reachable from a third-party app"
> because your own manifest hid the target is a self-inflicted false negative,
> and it is common. The probe checks this **first**, in section 0 of its output,
> and tells you plainly which of the two explanations applies. Read that section
> before reading anything else.

Providers need a second entry, by **authority**, not just by package:

```xml
<queries>
    <package  android:name="com.example.target" />
    <provider android:authorities="com.example.target.provider" />
</queries>
```

Find the authorities from the target's manifest:

```bash
# host
apktool d -f target.apk -o work/ >/dev/null
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml
```

---

## 5. Run it

```bash
# host
adb logcat -c
adb shell am start -n com.attacker.poc/.ProbeActivity --es target com.example.target
adb logcat -s poc:I
```

The report also renders on screen, selectable, so you can screenshot it for a
report appendix.

Run a subset while you iterate — a full sweep launches every exported activity
of the target, which is disruptive:

```bash
# adb shell
am start -n com.attacker.poc/.ProbeActivity \
   --es target com.example.target \
   --es only providers,sockets,localhost
```

Valid phase names: `visibility`, `activities`, `services`, `receivers`,
`providers`, `sockets`, `localhost`, `deputy`.

Point the confused-deputy probe at the component you believe forwards Intents:

```bash
# adb shell
am start -n com.attacker.poc/.ProbeActivity \
   --es target com.example.target \
   --es deputy .ui.ShareHandlerActivity \
   --es key   next_intent \
   --es only  deputy
```

Capture evidence:

```bash
# host
adb logcat -d -s poc:I > evidence/ipc-probe-$(date +%Y%m%d-%H%M).txt
adb exec-out screencap -p > evidence/ipc-probe.png
```

---

## 6. How to read the results

Every line carries one of five verdicts. They are not interchangeable, and the
difference between them is the difference between a finding and an anecdote.

| Verdict | Meaning | What you may write in a report |
|---|---|---|
| `REACHABLE` | The operation succeeded from an ordinary app UID. | "An unprivileged third-party application can …" — the strongest claim available without root. |
| `DENIED` | The platform refused us: `SecurityException`, or `bindService` returned `false`. | "Not reachable by a third-party application." Record it — ruling things out is part of the work. |
| `ABSENT` | The component or endpoint does not exist **or** package visibility filtering is hiding it. | Nothing, until you have re-checked `<queries>`. |
| `ERROR` | The target accepted the request and then threw. | **Still reachable.** The door opened; the room behind it was untidy. Often the most interesting result, because an unhandled exception means the input reached real code. |
| `INCONCLUSIVE` | The API cannot tell us. | Nothing. Go and get the missing evidence — usually from the target's own logcat. |

Three specific traps the output warns about inline:

**`sendBroadcast()` never throws.** It is fire-and-forget and returns normally
even when nothing was permitted to run. The probe uses
`sendOrderedBroadcast()` with a result receiver to get *some* signal, but the
only conclusive proof that a receiver ran is a log line from the **target's**
process:

```bash
# host — watch the TARGET, not the probe
adb logcat --pid=$(adb shell pidof -s com.example.target | tr -d '\r') -v threadtime
```

**`startService()` can fail because of a restriction on *us*.** From API 26 a
background app cannot start a service. That is a limit on the caller, not a
protection on the target, and the probe labels it `INCONCLUSIVE` rather than
`DENIED`. Keep the probe in the foreground and re-run.

**A `null` cursor is not a denial.** A provider may return `null` because the
path did not match its `UriMatcher`, not because it refused you. Try more paths,
and harvest the real ones from the decompiled provider's `UriMatcher.addURI()`
calls — see [27-ContentProviders](../../../27-ContentProviders/README.md).

> **🔬 Under the Hood**
> Why does a denial arrive as a `SecurityException` in *your* process for an
> Activity, but as a `false` return value for `bindService`? Because the check
> happens in `system_server`. `ActivityManagerService.checkComponentPermission`
> decides reachability and, for an activity start, `Instrumentation.checkStartActivityResult`
> converts the negative result code into an exception on the calling thread. The
> bind path reports failure through the return value instead. Same decision,
> same place, two different ways of telling you. See
> [25-Binder](../../../25-Binder/README.md).

---

## 7. What each probe actually proves

| Probe | Permission needed | What a `REACHABLE` proves |
|---|---|---|
| Exported activity | none | Any installed app can start that screen and control every extra it reads. |
| Bound service + transaction sweep | none | Any app can bind and invoke transaction codes. A handled code with no caller check is a privileged method callable by anyone. |
| Broadcast receiver | none | Any app can trigger whatever action the receiver performs. |
| ContentProvider | none | Any app can read the data. This is normally the highest-severity class, because a provider usually sits directly on a database. |
| **Abstract UNIX socket** | **none** | Any app can speak the app's private protocol. There is no filesystem entry, therefore no mode bits, therefore nothing to misconfigure — see below. |
| Localhost TCP | `INTERNET` | Any app holding a silently-granted `normal` permission can drive the local server. |
| Confused deputy | none | The target will exercise its own authority on an attacker's instructions. |

> **🔍 Pentester's Note**
> The abstract-socket probe is the one people skip and the one that most often
> pays. An abstract-namespace `AF_UNIX` socket — the `@name` form, created by
> `LocalServerSocket("name")`, which is the SDK's *default* — has **no inode, no
> owner, no group and no mode bits**. There is not even a permission to get
> wrong. Every app in the same network namespace, which on Android is every app
> on the device, can connect if it knows the name. Nothing in the target's
> manifest hints that the socket exists.

Guessing names is weak. Get the real list from the device and feed it back in:

```bash
# adb shell
cat /proc/net/unix | grep '@'
```

Then use [`../../scripts/abstract-socket-probe.py`](../../scripts/abstract-socket-probe.py)
and [`../../scripts/enumerate-ipc-surface.sh`](../../scripts/enumerate-ipc-surface.sh).

---

## 8. The discipline this app is meant to enforce

Run **both** experiments and record **both** results. The table is the artefact:

| Component | From `adb shell` | From this APK | Verdict |
|---|---|---|---|
| `.ui.WebActivity` | launched | `REACHABLE` | Finding — any app can drive it |
| `.internal.AdminActivity` | launched | `DENIED` | **Not** a finding — shell privilege only |
| `content://…/users` | rows returned | `DENIED` | **Not** a finding |
| `@com.example.target.ipc` | connected | `REACHABLE` | Finding — no permission required |

Then, for every `REACHABLE` row, do the part no tool does for you: **walk the
reach-through.** What can you make that component do that you could not do
directly? A door is only as serious as the room behind it.

> **⚠️ Warning**
> Severity comes from what the door reaches, not from the fact that it opened.
> An abstract socket that returns a version string is **Low**. An intent
> redirection that reaches only components that were *already exported* is **not
> a finding at all**, and saying so in a report is what makes your other
> findings believable.

Finally, record the ground truth this probe prints in its header: the target's
`targetSdk`, your device's build fingerprint, the Android release and the
security patch level. Half the platform's IPC mitigations are `targetSdk`-gated,
so a finding that is real against an app targeting API 22 may be impossible
against the same source targeting API 33.

---

## 9. Extending it

Things worth adding for a specific engagement, in rough order of value:

1. **Real provider paths** harvested from the decompiled `UriMatcher`, instead
   of the built-in guesses.
2. **The four provider injection points** — `projection`, `selection`,
   `sortOrder`, and the URI path itself — plus an `openFile` traversal attempt
   with `../../databases/app.db`. See
   [27-ContentProviders](../../../27-ContentProviders/README.md).
3. **A real AIDL client.** Copy the target's `.aidl` (reconstruct it from the
   `DESCRIPTOR` string and the `TRANSACTION_*` constants in JADX output — §6.1)
   and call methods by name instead of sweeping raw codes.
4. **Deep-link squatting**, by uncommenting the `SchemeSquatter` block in the
   manifest and setting the target's scheme. See
   [26-Intent](../../../26-Intent/README.md).
5. **A `PendingIntent` harvester**, if the target hands `PendingIntent`s out in
   notifications or broadcasts. A mutable one lets you act with the target's
   identity.
6. **A localhost HTTP route scanner**, once a listener is found — and check the
   `Host` and `Origin` header handling, because a browser-reachable localhost
   service is exploitable by DNS rebinding with no malicious app at all.

> **🔍 Pentester's Note**
> Keep a generic build of this in your toolkit with the target package in a
> `BuildConfig` field or, as here, in an Intent extra. Re-targeting should take
> thirty seconds. Its real value is not the probing — it is that a client
> engineer can install the same APK and see the same output, which ends
> arguments about whether a finding is real.

---

## 10. Legal and safety

This app exists to prove reachability against applications you own or have
written authorisation to test. Everything it does is available to any app the
user installs, which is exactly why the findings matter — and exactly why
running it against third-party software without permission is not acceptable.

The probe launches every exported activity of the target and sends broadcasts to
every exported receiver. On a device with real user data, that can change state.
Use a dedicated test device, snapshot before you start, and never run the
confused-deputy or `HIJACK_ORDERED` paths against production data.
