# 21 — App Sandbox · Examples

Code for [chapter 21](../README.md) §9 and the labs, in two groups that are read differently.

**The evidence files** — §9.1 to §9.3 — compile against the platform SDK alone, with no AndroidX and
no third-party dependency. That is deliberate: they exist to *prove* things, and the fewer
non-platform classes they contain, the less room there is to argue that a result came from something
other than the APIs any app can call.

**The pattern files** — §9.4 and §9.5 — are the opposite kind of artefact. They are not experiments;
they are the shape you recommend in remediation text, and they are written the way a real app would
write them. `SecureSharing.kt` therefore uses AndroidX `FileProvider`, and the render trio depends on
a project-local `IDocumentRenderer` AIDL interface and a bundled native parser that are described in
the chapter rather than shipped here. Read them; do not expect them to compile in isolation.

---

## What is here

### Evidence — things you run

| File | Chapter | What it demonstrates |
|---|---|---|
| [`SandboxIdentity.kt`](SandboxIdentity.kt) | §9.1 | Prints this process's complete identity — the framework's view *and* the kernel's, side by side. The starting point for everything else. |
| [`IRiskyParser.aidl`](IRiskyParser.aidl) | §9.2 | The **entire** interface of an isolated process: two methods plus passed file descriptors. Small enough to audit by reading one file. |
| [`RiskyParserService.kt`](RiskyParserService.kt) | §9.2 | A service running with `android:isolatedProcess="true"`. Reports what it can reach — which is almost nothing — and still does useful work on a descriptor it was handed. |
| [`IsolatedProbeActivity.kt`](IsolatedProbeActivity.kt) | §9.2 | The host side. Binds three services running **identical** code in three configurations and prints all three reports for comparison. |
| [`AttackerProbe.kt`](AttackerProbe.kt) | §9.3, Lab 3 | The probe logic on its own — a nosy object you can drop into any app that declares no dangerous permissions. Every `DENIED` line is the sandbox working; every `OK` line is where the findings are. |
| [`attacker-app/`](attacker-app/) | §9.3, Lab 3 | A buildable, dependency-free probe APK around that logic. The only experiment that answers "can an app the user installs reach X". |

### Patterns — things you recommend

| File | Chapter | What it demonstrates |
|---|---|---|
| [`SecureSharing.kt`](SecureSharing.kt) | §9.4 | Sharing a file with another app without weakening the sandbox: written inside `cacheDir`, served by a **non-exported** `FileProvider` over an allowlisted path, handed out as a read-only per-URI grant, and purged on logout. Four properties, each of which is a finding when it is missing. |
| [`RenderZygotePreload.kt`](RenderZygotePreload.kt) | §9.5 | `android.app.ZygotePreload` for `android:useAppZygote="true"` — the risky native library is loaded **once**, in the app's own isolated Zygote, so N renderers cost roughly the memory of one. |
| [`DocumentRenderService.kt`](DocumentRenderService.kt) | §9.5 | The confined side: an `isolatedProcess` service that never opens a path itself, writes only into a `SharedMemory` region the host owns, and returns primitives so a parser bug has nothing to reach for. |
| [`DocumentRenderClient.kt`](DocumentRenderClient.kt) | §9.5 | The host side: read-only `ParcelFileDescriptor` in, bounded `SharedMemory` out, sealed `PROT_READ` after the render, service unbound in `finally`. The interface *is* the attack surface, and this is what a tight one looks like. |

These four are extracted verbatim from the chapter README, which walks through them line by line. If
you change one, change both.

---

## The three experiments, in order

### 1. What am I? — `SandboxIdentity.kt`

Drop `SandboxIdentity.dump(this)` into any `onCreate()`.

```bash
# host
adb logcat -c
adb shell am start -n com.example.sandboxlab/.MainActivity
adb logcat -s SANDBOXPROBE:I
```

Three lines in that output carry most of the chapter:

| Line | Means |
|---|---|
| `Groups: … 3003 …` | GID 3003 is `AID_INET`. **This line is the `INTERNET` permission** — a Linux group membership, not a framework check, and therefore not hookable from inside the process. |
| `CapBnd: 0000000000000000` | The capability *bounding* set is empty, so no capability can ever be acquired by any route. |
| `Seccomp: 2` | `SECCOMP_MODE_FILTER`. Your `adb shell` shows `0`. That single difference is why a shell experiment answers a different question from an app experiment. |

Cross-check from outside with [`../scripts/sandbox-inspect.sh`](../scripts/sandbox-inspect.sh), which
prints the same fields and annotates them.

### 2. Is it a boundary? — the isolated-process trio

`IsolatedProbeActivity.kt` binds three services whose implementations are identical. Only the manifest
differs:

```xml
<service android:name=".MainProcessService"     android:exported="false" />
<service android:name=".SeparateProcessService" android:process=":worker" android:exported="false" />
<service android:name=".RiskyParserService"     android:isolatedProcess="true" android:exported="false" />
```

Keeping the code identical is what makes the comparison valid: every difference in the output is
attributable to the declaration and nothing else.

| | main process | `android:process` | `android:isolatedProcess` |
|---|---|---|---|
| Separate process | no | yes | yes |
| Separate **UID** | no | **no** | **yes** (99000–99999) |
| Permissions | app's | app's | **none** |
| Data directory | app's | app's | none exists |
| Network | yes | yes | **no** |
| SELinux domain | `untrusted_app` | `untrusted_app` | `isolated_app` |
| **Security boundary?** | no | **no** | **yes** |

`android:process` is the trap. It is a *memory and lifecycle* tool — a crash boundary, and the ability
to free memory by killing a process. It provides no isolation whatsoever, because the new process
holds the app's UID and can open every file the main process can.

Confirm from outside, which is what makes it evidence rather than a self-report:

```bash
# adb shell
ps -A -o USER,PID,NAME | grep sandboxlab
ps -A -Z              | grep sandboxlab
```

> **Under the Hood**
> Watch `countLines()`. The isolated process cannot open *any* file, yet it reads one successfully.
> The host called `ParcelFileDescriptor.open()` under the host's own UID, the kernel checked
> permissions **once, at `open()`, in the opening process**, and the resulting descriptor travelled
> across Binder. Reads through it are never rechecked. Used deliberately this is what makes isolated
> workers usable at all; used carelessly in a `ContentProvider.openFile()` it is escape class 5.

Full walkthrough: [`../labs/lab-02-isolated-process.md`](../labs/lab-02-isolated-process.md).

### 3. What can *another app* reach? — `attacker-app/`

The only experiment that supports a claim about apps.

```bash
# host
gradle -p 21-App-Sandbox/examples/attacker-app assembleDebug
adb install -r 21-App-Sandbox/examples/attacker-app/build/outputs/apk/debug/attacker-app-debug.apk
adb logcat -c
adb shell am start -n com.attacker.sandboxprobe/.ProbeActivity --es target com.example.target
adb logcat -s SANDBOXPROBE:W
```

Read [`attacker-app/README.md`](attacker-app/README.md) before running it — in particular §4, on the
`<queries>` block, which silently invalidates the whole run if you skip it.

---

## Reachability discipline

> **Warning**
> `adb shell` is UID 2000 in the SELinux domain `shell`, with no seccomp filter, a non-empty
> capability bounding set, and supplementary groups no app holds. A thing you reached from a shell is
> **not** proven reachable by an attacker.

| Experiment | Answers |
|---|---|
| `adb shell` | "Can UID 2000 in the `shell` domain do this?" — almost never the question you care about |
| `run-as <pkg>` | "Can this app's UID read this file?" — debuggable builds only, and in a *different* SELinux domain with no seccomp filter, so not a faithful reproduction |
| Frida in the target | "Can code already executing inside the process do this?" — a different, weaker adversary |
| **A probe APK** | **"Can any app the user installs do this?"** — the finding |

Run both. Record both. The difference between the two columns is the finding.

---

## Building

These are source files, not a project. To run them, create an empty Android project (Kotlin,
`minSdk 29`, `applicationId com.example.sandboxlab`), enable AIDL, and drop the files in:

```groovy
// host — app/build.gradle
android {
    namespace 'com.example.sandboxlab'
    compileSdk 34
    defaultConfig { applicationId "com.example.sandboxlab"; minSdk 29; targetSdk 34 }
    buildFeatures { aidl true }
}
```

```
src/main/aidl/com/example/sandboxlab/IRiskyParser.aidl
src/main/java/com/example/sandboxlab/SandboxIdentity.kt
src/main/java/com/example/sandboxlab/RiskyParserService.kt
src/main/java/com/example/sandboxlab/IsolatedProbeActivity.kt
```

Declare `INTERNET` in the host app's manifest, so the isolated process's lack of network is
attributable to isolation rather than to a missing permission. That is the control in the experiment
and it is easy to forget.

`attacker-app/` is a complete standalone Gradle build and needs none of this.

---

## Legal

Everything here is designed to run against applications you own or have written authorisation to test.
The probe app in particular enumerates other applications' data, which in many jurisdictions is a
criminal offence on a device you do not own, regardless of intent. Use a dedicated test device.

## See also

- [`../scripts/`](../scripts/) — `sandbox-inspect.sh`, `seccomp-probe.js`, `in-process-reach.js`, and
  [`manifest-exposure.py`](../scripts/manifest-exposure.py), which reads a decoded manifest as a
  statement about the UID boundary and tells you which of these experiments to run next
- [`../labs/`](../labs/) — the five labs these examples support
- [24-IPC's attacker-app](../../24-IPC/examples/attacker-app/README.md) — the same methodology aimed
  at the IPC surface: activities, services, receivers, providers, abstract sockets, localhost, and the
  confused-deputy path
