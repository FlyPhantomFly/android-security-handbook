# StartupProviderPersistence — proving a ContentProvider runs before `Application.onCreate()`

> A minimal app that puts three timestamps in logcat and settles the question for good:
> a `ContentProvider.onCreate()` declared anywhere in the **merged** manifest executes
> **before** the app's own `Application.onCreate()`, with the app's UID and the app's
> permissions, and before a single line of the app author's own code has run.

**Belongs to:** [09 — Android App Internals](../../README.md) — see §3.14 (the bootstrap order),
§3.19 (the `Application` class and provider-based initialisation) and §9.2
**FAQ:** [`../../faq.md`](../../faq.md) — question 8 asks exactly this
**Live version:** [`../../scripts/trace-app-startup.js`](../../scripts/trace-app-startup.js) shows the
same ordering on any app, including one whose source you do not have

---

## 1. Why this exists

The ordering is documented, but "documented" is not the same as "believed". Almost everyone meeting
Android for the first time assumes `Application.onCreate()` is the app's entry point — the place
where nothing has happened yet and everything can still be controlled. It is not. By the time it
runs, every `ContentProvider` in the merged manifest has already been constructed and had its
`onCreate()` called.

That single fact has three consequences that matter more than the ordering itself.

**For a developer:** initialisation you put in `Application.onCreate()` is not "first". Any SDK that
ships a provider beat you to it, so your logging setup, your crash handler, your strict-mode policy
and your certificate pinning are all installed *after* third-party code has already run.

**For a pentester:** a Frida script attached to a running process has missed all of it. So has a
hook installed from `Application.onCreate()`. If your root-detection bypass does not fire, the check
very likely ran in a provider. This is why §7.2 of the chapter insists on `frida -U -f` (spawn)
rather than `frida -U -n` (attach).

**For anyone reviewing a dependency:** adding a line to `build.gradle` is functionally equivalent to
granting that dependency arbitrary code execution at process start, inside your UID, holding your
permissions, before your code can defend itself. The provider is merged into your manifest by the
Gradle manifest merger. You never wrote it and you will not find it in your source tree.

> **🧠 Mental Model**
> `Application.onCreate()` feels like the front door of the house. It is actually the moment you walk
> into the living room. The manifest merger let the contractors in through the back door an hour ago,
> and they have been working the whole time.

---

## 2. What is in this directory

| File | What it is |
|---|---|
| `AndroidManifest.xml` | Declares `DemoApplication`, `EarlyInitProvider` and `DemoActivity`. The `<provider>` element is the stand-in for one merged in from an AAR. |
| `EarlyInitProvider.kt` | A `ContentProvider` that exists only for its `onCreate()` timing. It logs its identity and writes a `SharedPreferences` value, to show it can already touch the app's private storage. |
| `DemoApplication.kt` | Logs `attachBaseContext` and `onCreate`. These are the bracket either side of the provider. |
| `DemoActivity.kt` | Logs its own `onCreate`, giving you the fourth and last timestamp. Source in §3 below. |

There are no dependencies — not even AndroidX. That is deliberate. AndroidX would pull in
`androidx.startup.InitializationProvider`, and the point of this demo is that the *only* provider in
the manifest is the one you can see.

---

## 3. The one file the chapter README does not print

The manifest declares `.DemoActivity` but the chapter prints only three of the four sources. Save
this as `DemoActivity.kt` next to the others:

```kotlin
// examples/StartupProviderPersistence/DemoActivity.kt
package com.example.startup

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.TextView

class DemoActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        Log.i(TAG, "ACTIVITY onCreate  <-- last of the four")
        super.onCreate(savedInstanceState)

        // Read back what the provider wrote before any of this app's own code ran.
        val written = getSharedPreferences("early", 0).getLong("last_provider_init", -1L)
        setContentView(TextView(this).apply {
            setPadding(48, 48, 48, 48)
            typeface = android.graphics.Typeface.MONOSPACE
            text = "EarlyInitProvider wrote last_provider_init = $written\n" +
                   "It did that before DemoApplication.onCreate() ran.\n\n" +
                   "adb logcat -d -s StartupOrder -v time"
        })
    }

    companion object { private const val TAG = "StartupOrder" }
}
```

---

## 4. Build

Any single-module Android project will do; the four sources are plain platform APIs. Minimal
`build.gradle` for a flat source layout:

```groovy
// examples/StartupProviderPersistence/build.gradle
plugins {
    id 'com.android.application'
    id 'org.jetbrains.kotlin.android'
}

android {
    namespace 'com.example.startup'
    compileSdk 34
    defaultConfig {
        applicationId 'com.example.startup'
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName '1.0'
    }
    sourceSets {
        main {
            manifest.srcFile 'AndroidManifest.xml'
            java.srcDirs = ['.']
        }
    }
}
```

```bash
# host — from this directory
gradle assembleDebug
```

No Gradle wrapper JAR is committed to this repository. Generate one once if you want `./gradlew`:

```bash
# host — in this directory
gradle wrapper --gradle-version 8.5
```

If you would rather not set up Gradle at all, paste the four files into a new "No Activity" project
in Android Studio, point the manifest at them, and run. The demo depends on nothing but the
ordering.

---

## 5. Run and observe

The three commands that matter are `logcat -c`, `force-stop` and `am start`, in that order. Clearing
the buffer first means the output you read is from this launch. `force-stop` is not optional: if the
process is already alive, Android reuses it, no bootstrap happens, and you will see the activity log
line with nothing before it — which looks exactly like the demo failing.

```bash
# host — observe the order
adb install -r app-debug.apk
adb logcat -c
adb shell am force-stop com.example.startup
adb shell am start -n com.example.startup/.DemoActivity
adb logcat -d -s StartupOrder -v time
```

### Expected output

```text
09-04 11:20:31.101 I/StartupOrder: APPLICATION attachBaseContext
09-04 11:20:31.118 I/StartupOrder: PROVIDER onCreate  uid=10234 pid=4821
09-04 11:20:31.118 I/StartupOrder:   package  = com.example.startup
09-04 11:20:31.119 I/StartupOrder:   dataDir  = /data/user/0/com.example.startup
09-04 11:20:31.141 I/StartupOrder: APPLICATION onCreate  <-- providers already ran
09-04 11:20:31.167 I/StartupOrder: ACTIVITY onCreate  <-- last of the four
```

Your UID, PID and absolute timestamps will differ. The **order** will not, and neither will the
sign of the differences. Read the four lines as a proof:

| Line | Timestamp | What it establishes |
|---|---|---|
| `APPLICATION attachBaseContext` | `.101` | The `Application` object exists and has a `Context`. This is the earliest Java code of yours that can run. |
| `PROVIDER onCreate` | `.118` | 17 ms later, provider code runs — with `uid=10234`, the host app's UID, and full access to the host's `dataDir`. |
| `APPLICATION onCreate` | `.141` | 23 ms after the provider. Everything the provider did is already done. |
| `ACTIVITY onCreate` | `.167` | The first moment any UI exists. |

The `dataDir` line is the part worth staring at. The provider printed
`/data/user/0/com.example.startup` — not a directory of its own, because it does not have one. It is
inside the host app's sandbox, as the host app.

---

## 6. Verify the provider really did write to private storage

The provider wrote `last_provider_init` into `SharedPreferences` before the `Application` existed.
`DemoActivity` reads it back and shows it on screen; you can also confirm it from the shell, which
is the more convincing version because it inspects the file on disk:

```bash
# adb shell — the app is debuggable, so run-as works (see faq.md question 10)
run-as com.example.startup cat /data/user/0/com.example.startup/shared_prefs/early.xml
```

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <long name="last_provider_init" value="1725441631118" />
</map>
```

That value is a `System.currentTimeMillis()` captured at `.118` — before `APPLICATION onCreate` at
`.141`. A file on disk, written by code the app author did not write, timestamped before the app
author's initialisation began.

---

## 7. Now do it to an app whose source you do not have

The demo proves the mechanism. The skill is recognising it in the wild, where the provider is not in
your source tree and is not named anything as obvious as `EarlyInitProvider`.

```bash
# host — every provider in the MERGED manifest, which is the only one that matters
aapt2 dump xmltree base.apk --file AndroidManifest.xml | grep -A 6 'E: provider'
```

```bash
# adb shell — the same list, from the installed package
dumpsys package com.example.app | sed -n '/Provider Resolver Table/,/Service Resolver Table/p'
```

```bash
# host — watch it happen live, in order, with timings
frida -U -f com.example.app --no-pause -l ../../scripts/trace-app-startup.js
```

Anything that appears in those lists and is not declared in `src/main/AndroidManifest.xml` arrived
from a dependency and runs before the app's own code. `androidx.startup.InitializationProvider` is
the common one, and it is a multiplexer: every library registering an `Initializer` through its
`<meta-data>` entries runs inside that single provider's `onCreate()`. The Frida script hooks
`androidx.startup.AppInitializer.doInitialize` for exactly that reason — otherwise you see one
provider and miss the ten initialisers behind it.

---

## 8. What this demo does NOT show

- **It is not a persistence technique on its own.** The provider runs when the process starts; it
  does not start the process. Genuinely persistent startup requires a component the system launches
  — a boot-completed receiver, a job, an alarm, an accessibility service. The directory name refers
  to persistence *of initialisation across every process start*, not survival across reboot.
- **It says nothing about the sandbox.** The provider runs inside the app's existing sandbox and
  gains nothing the app did not already have. What that sandbox permits is
  [21 — App Sandbox](../../../21-App-Sandbox/README.md).
- **It is single-process.** With `android:process` in play, `Application.onCreate()` and the
  providers run again in each process. See [`../MultiProcessDemo/README.md`](../MultiProcessDemo/README.md).
- **It does not cover provider ordering among themselves.** `android:initOrder` (set to `100` here)
  influences the order providers within a manifest are initialised, but relying on it across merged
  manifests is fragile and outside what this demo demonstrates.
- **It proves nothing about native code.** `System.loadLibrary()` from a provider runs `JNI_OnLoad`
  even earlier in relative terms; the Frida script logs those calls, this demo does not make any.

---

## See also

- [`../../README.md`](../../README.md) — §3.14 the bootstrap order, §3.19 provider-based initialisation
- [`../../faq.md`](../../faq.md) — question 8
- [`../../scripts/trace-app-startup.js`](../../scripts/trace-app-startup.js) — the same ordering, live, on any app
- [`../AppIdentityProbe.kt`](../AppIdentityProbe.kt) — what the provider's `uid=` line means in full
- [`../../../27-ContentProviders/README.md`](../../../27-ContentProviders/README.md) — the component itself, as an IPC surface
- [`../../../32-Manifest/README.md`](../../../32-Manifest/README.md) — manifest merging, which is how the provider got there
