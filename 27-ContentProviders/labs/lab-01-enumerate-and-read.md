# Lab 01 — Enumerate and Read an Exported Provider

**Difficulty:** Beginner in concept, Intermediate in setup — see the note below
**Time:** 60–90 minutes for the analysis, **plus 1–2 hours to build the two apps** the first time
**Prerequisites:** [Chapter 27 §1–3](../README.md#1-introduction),
[§7.1–7.3](../README.md#71-enumerating-providers-on-a-device), a device or emulator, `adb`, Android
Studio (or `gradle`) to build a tiny app. Root is **not** required.

> **Warning — read this before you start**
> The *ideas* in this lab are beginner-level: query a provider, then prove an ordinary app can do the
> same. The **Setup is not**. It asks you to create **two Android Studio projects from scratch**, add
> a class to each, edit two manifests, and build and install both. If you have never built an Android
> app, budget one to two extra hours and expect to fight Gradle, the SDK download and the emulator
> before you run a single `content query`.
>
> If that is where you are, do the following first and come back:
> - [03 — Programming Fundamentals](../../03-Programming-Fundamentals/README.md) and
>   [04 — Java](../../04-Java/README.md) for the language.
> - [08 — Build System](../../08-Build-System/README.md) for what Gradle and Android Studio are
>   actually doing.
> - Chapter 27 [§7.1–7.3](../README.md#71-enumerating-providers-on-a-device) can be read and the
>   `adb shell content` commands practised against **providers already on your device**, with no
>   building at all. That gets you the enumeration half of this lab today.

---

## Objective

Build a deliberately exported content provider, enumerate it the way an attacker would, read its data
from `adb shell`, and then — the step that turns an observation into a finding — reproduce that read
from an ordinary, unprivileged application. By the end you will never again confuse "readable from
`adb shell`" with "reachable by an attacker".

## Why this matters

This is the single most common false positive in Android reports, and it gets junior testers' findings
rejected. `adb shell` runs as UID 2000 (`shell`), which the platform grants privileges no ordinary app
holds. A `content query` that succeeds from the shell proves nothing about what a malicious app can do.
The discipline this lab drills — *reproduce from an unprivileged UID before you report* — is what
separates a finding from a screenshot. Chapter [77-UsefulCommands](../../77-UsefulCommands/README.md)
teaches the same discipline across all four component types; here you apply it to a provider, where a
second twist appears: `query()` and `openFile()` take different permission paths and must both be
tested.

> **Definition**
> A **provider is "reachable"** by a principal if that principal's process can obtain the provider and
> perform an operation on it. Reachability depends on the caller's UID and permissions, *not* on
> whether some other, more-privileged principal (like the shell) can reach it.

---

## Setup

You will build two tiny apps: the **target** (holds the provider) and the **probe** (an unprivileged
attacker). Use the ready-made provider in this chapter.

```bash
# host — create the target app around the example provider
# 1. New empty Android project, package com.example.vuln, minSdk 21+
# 2. Copy ../examples/VulnerableNotesProvider.java into it (fix the package line if needed)
# 3. Register it EXPORTED in AndroidManifest.xml (this is deliberate for the lab):
```

```xml
<!-- target app — AndroidManifest.xml, inside <application> -->
<provider
    android:name=".VulnerableNotesProvider"
    android:authorities="com.example.vuln.notes.provider"
    android:exported="true" />
```

```bash
# host — build, install, and force the provider to initialise (which seeds the DB)
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
# Touching the authority starts the app and runs onCreate -> DbHelper.onCreate (seed data)
adb shell content query --uri content://com.example.vuln.notes.provider/notes
```

> **Under the Hood**
> That last command did more than read. Resolving the authority forced Android to fork the target's
> process, run its `Application` constructor, call `installContentProviders()` (which ran
> `ContentProvider.onCreate()` and seeded the database), and only then serve the query. An app with no
> exported activity can still be started by anyone who knows one of its provider authorities. See
> [§3.11](../README.md#311-provider-lifecycle-and-process-behaviour).

---

## Steps

### Step 1 — Enumerate every provider on the device

```bash
# adb shell — the whole-device view
dumpsys package providers
```

```bash
# adb shell — just your target, as PackageManagerService parsed it (the ground truth)
dumpsys package com.example.vuln | grep -A12 "Provider{"
```

Or let the chapter script do the triage, including resolving each permission's protection level:

```bash
# host
../scripts/provider-enum.sh package com.example.vuln
```

**Q1.** What `exported` value does `dumpsys` report for your provider? Does it agree with the manifest?

**Q2.** The provider declares no permission. Using the decision table in
[§5.3](../README.md#detection--static), what is the verdict — and what is still *unproven* at this
point?

### Step 2 — Discover the paths without reading the source

Pretend you do not have the source. Mine `content://` strings from the installed APK, and use the
error-message oracle.

```bash
# adb shell — the Unknown-URI oracle: a wrong path that reaches the code proves you are past the check
content query --uri content://com.example.vuln.notes.provider/does-not-exist
content query --uri content://com.example.vuln.notes.provider/notes
```

**Q3.** The first command throws `IllegalArgumentException: Unknown URI`; the second returns rows.
Explain precisely what the *difference* between those two responses tells you, referencing the response
table in [§7.3](../README.md#73-distinguishing-the-error-responses).

### Step 3 — Read the data from the shell

```bash
# adb shell
content query --uri content://com.example.vuln.notes.provider/notes
content query --uri content://com.example.vuln.notes.provider/notes --projection "_id,title"
```

**Q4.** Record the rows returned. This is your "shell-readable" baseline.

### Step 4 — Test getType and openFile separately

```bash
# adb shell — getType is unprotected by the framework; a free reachability probe
content gettype --uri content://com.example.vuln.notes.provider/notes
```

```bash
# adb shell — openFile takes a DIFFERENT code path from query; test it too
content read --uri content://com.example.vuln.notes.provider/docs/readme.txt
```

**Q5.** Did `openFile` (`content read`) behave the same as `query`? Why is testing both mandatory, even
when one succeeds? (Hint: [§3.9](../README.md#39-openfile-openassetfile-and-the-pipe-helpers) and the
FileProvider note in [32-Manifest lab 04](../../32-Manifest/labs/lab-04-provider-surgery.md).)

### Step 5 — Build the unprivileged probe app

This is the step that makes it a finding. The probe needs **no permissions**, only a `<queries>` entry
so it can see the target on Android 11+.

```xml
<!-- probe app — AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.probe">
    <queries>
        <package android:name="com.example.vuln" />
    </queries>
    <application android:label="Probe">
        <activity android:name=".ProbeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

```java
// probe app — ProbeActivity.java
package com.example.probe;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import java.io.InputStream;

public class ProbeActivity extends Activity {
    private static final String TAG = "PROBE";
    private static final String URI = "content://com.example.vuln.notes.provider/notes";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        // 1. query() — the read path
        try (Cursor c = getContentResolver().query(Uri.parse(URI), null, null, null, null)) {
            if (c == null) {
                Log.i(TAG, "QUERY -> null cursor");
            } else {
                Log.i(TAG, "QUERY -> READABLE, " + c.getCount() + " rows, cols="
                        + java.util.Arrays.toString(c.getColumnNames()));
                if (c.moveToFirst()) Log.i(TAG, "  row0: " + c.getString(1));
            }
        } catch (SecurityException e) {
            Log.i(TAG, "QUERY -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, "QUERY -> " + e);
        }

        // 2. openInputStream() — a SEPARATE permission path from query()
        try (InputStream in = getContentResolver().openInputStream(
                Uri.parse("content://com.example.vuln.notes.provider/docs/readme.txt"))) {
            Log.i(TAG, "OPEN  -> READABLE");
        } catch (SecurityException e) {
            Log.i(TAG, "OPEN  -> DENIED: " + e.getMessage());
        } catch (Exception e) {
            Log.i(TAG, "OPEN  -> " + e.getClass().getSimpleName());
        }
    }
}
```

```bash
# host
./gradlew :probe:assembleDebug
adb install -r probe/build/outputs/apk/debug/app-debug.apk
adb logcat -c
adb shell am start -n com.example.probe/.ProbeActivity
adb logcat -s PROBE
```

**Q6.** Did the probe app's `query` succeed? Compare its output to your shell baseline from Step 3.

**Q7.** Build the reachability table:

| URI / op | Shell (UID 2000) | Probe app (UID 10xxx) | Verdict |
|---|---|---|---|
| `notes` query | | | |
| `docs/readme.txt` openFile | | | |

### Step 6 — Make it a false positive, then fix it

Change the manifest to `android:exported="false"`, rebuild, reinstall, and re-run both the shell
commands and the probe app.

```xml
<provider
    android:name=".VulnerableNotesProvider"
    android:authorities="com.example.vuln.notes.provider"
    android:exported="false" />
```

**Q8.** After the change, what does the shell report, and what does the probe app report? Which of the
two would have misled you if it were your only evidence?

**Q9.** With `exported="false"`, is the provider now completely unreachable? Name at least two ways it
could still be reached (hint: [FAQ 13](../faq.md) and
[§4.2](../README.md#42-acquiring-a-provider-the-system_server-side)).

---

## Hints

<details>
<summary>Hint 1 — the probe app sees nothing / ActivityNotFoundException</summary>

On Android 11+ your probe cannot see the target package without a `<queries>` entry. Without it,
`ContentResolver` cannot resolve the authority and you will misread the result as "unreachable". Add:

```xml
<queries><package android:name="com.example.vuln" /></queries>
```
</details>

<details>
<summary>Hint 2 — content query returns nothing even from the shell</summary>

The authority may differ from the package name. Read it from the manifest or from `dumpsys`:

```bash
adb shell dumpsys package com.example.vuln | grep -oE 'authority=[^ ]+'
```
</details>

<details>
<summary>Hint 3 — openFile / content read fails but query works</summary>

That is expected and important, not a bug in your setup. `openFile` and `query` are different methods
with different permission handling. The vulnerable provider's `openFile` only serves `docs/*`; a
`notes` URI will throw. Point the `content read` at a `docs/...` path.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1.** `dumpsys` reports `exported=true`, matching the manifest. Trust `dumpsys` over the decompiler in
general, because it shows what `PackageManagerService` actually parsed.

**Q2.** Verdict: exported with no permission → a finding *candidate*. What is unproven is
**reachability by an ordinary app** — everything so far was UID 2000. The finding is not established
until Step 5.

**Q3.** `Unknown URI` is thrown by the *provider's own code*, which means you passed the framework
permission check and reached `query()`; only the path was wrong. `SecurityException: Permission Denial`
would mean you never reached the code. The difference is a path-enumeration oracle: diff error messages
across a wordlist to map valid paths without reading any data.

**Q4.** The single seeded note row (`shopping / milk and eggs`). Plus, via injection you would reach the
`users` and `session` tables — that is Lab 02.

**Q5.** Testing both is mandatory because a provider can deny `query` and permit `openInputStream`, or
vice versa — they are separate methods with separate checks. `FileProvider` is the canonical case: it
serves through `openFile` and has no meaningful `query`, so testing only the cursor tells you nothing
about a file-serving provider.

**Q6/Q7.** With `exported="true"` and no permission, the probe app's `query` succeeds and matches the
shell baseline — *now* it is a real finding, reproduced from an unprivileged UID.

**Q8.** After `exported="false"`: the shell **still** reads it (UID 2000 / `shell` retains privileges),
but the probe app gets `SecurityException: ... not exported from uid ...`. If the shell result had been
your only evidence you would have reported a non-issue. This is the whole lesson.

**Q9.** Even non-exported, the provider is reachable: (a) from any app sharing its UID via
`android:sharedUserId` (the same-UID short circuit in `checkComponentPermission`); (b) from within the
app's own process, e.g. through a WebView with `setAllowContentAccess(true)` loading attacker content,
or any code-execution primitive in the app; and (c) from `system`/`root`.

</details>

---

## Success criteria

- [ ] You built and installed an exported provider and enumerated it with `dumpsys` and the chapter script
- [ ] You used the `Unknown URI` vs `Permission Denial` oracle to distinguish a wrong path from a denied provider
- [ ] You read the provider's data from `adb shell`
- [ ] You tested `query` **and** `openFile`/`openInputStream` separately and can say why both are required
- [ ] You built an unprivileged probe app with no permissions and a `<queries>` entry
- [ ] You produced the side-by-side shell-vs-app reachability table
- [ ] You flipped `exported` to `false` and observed the shell succeed while the app was denied
- [ ] You can state, in one sentence, why a `content query` from `adb shell` is not by itself a finding
- [ ] You can name two ways a non-exported provider is still reachable
