# Lab 02 — Tracing the Install Flow End to End

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Chapter:** [09 — Android App Internals](../README.md)
**Depends on:** [Lab 01 — App Identity and UID](lab-01-app-identity-and-uid.md)

---

## Objective

`adb install app.apk` is one command. Behind it, six subsystems cooperate: `adb`, `PackageInstaller`,
`PackageManagerService`, the signature verifier, `installd`, and `dex2oat`. By the end of this lab you
will have watched each of them do its job, and you will have performed the whole sequence by hand.

Specifically you will:

1. Capture a complete, timestamped log of one installation.
2. Perform a **session-based install** manually with `pm install-create`, `install-write` and
   `install-commit`, including streaming the APK from the host with no staging file on the device.
3. Install a **split APK set** and confirm every split lands under one identity.
4. Observe the `ACTION_PACKAGE_ADDED` broadcast being delivered.
5. Diff the filesystem, the SELinux labels, `packages.list` and `packages.xml` **before and after**,
   so you can point at the exact moment each artefact came into existence.
6. Abandon a session and prove that nothing was created.

> **Mental Model**
> An install is not a copy. It is a **transaction**: the system opens a staging area, accepts bytes,
> verifies them cryptographically, allocates an identity, creates labelled storage, compiles code,
> writes durable records, and only then tells the world. Any step can fail and roll the whole thing
> back. Think of `install-create` / `install-write` / `install-commit` as `BEGIN` / `INSERT` /
> `COMMIT`.

---

## Prerequisites

| Requirement | Check |
|---|---|
| Completed Lab 01 | you must already be comfortable with `dumpsys package` |
| Rooted emulator, API 33+ | `adb root && adb shell whoami` prints `root` |
| An APK you can install and uninstall freely | any debug build |
| A split APK set (optional but recommended for Part 3) | see Part 3 setup |
| `python3` on the host for timestamp conversion | `python3 --version` |

```bash
# host
PKG=com.example.probe
APK=./app-debug.apk
adb root
adb shell getprop ro.build.version.sdk
```

---

## Part 0 — Take a "before" snapshot

You cannot see what an install created unless you know what existed first. Capture the baseline.

```bash
# host
mkdir -p lab02 && cd lab02
adb shell "pm list packages -U"                          > before-packages.txt
adb shell "su -c 'cat /data/system/packages.list'"       > before-packages-list.txt
adb shell "su -c 'ls -laZ /data/app'"                    > before-data-app.txt
adb shell "su -c 'ls -laZ /data/user/0'"                 > before-user0.txt
adb shell "su -c 'ls -laZ /data/user_de/0'"              > before-userde0.txt
adb shell "su -c 'ls -la /data/misc/profiles/ref'"       > before-profiles.txt
```

Make sure the subject package is genuinely absent:

```bash
# host
adb uninstall $PKG || true
adb shell pm list packages -u | grep -w $PKG || echo "clean: not present, not even with kept data"
```

If it appears in `pm list packages -u`, a previous `pm uninstall -k` left a record behind. Remove it:

```bash
# adb shell
pm uninstall --user 0 com.example.probe
cmd package uninstall com.example.probe
```

---

## Part 1 — Watch a normal install happen

### Step 1.1 — Start the log capture

Open a second terminal and leave this running for the whole of Part 1.

```bash
# host — terminal 2
adb logcat -c
adb logcat -v threadtime \
  PackageManager:V PackageInstaller:V PackageInstallerSession:V \
  installd:V Installer:V dex2oat:V dexopt:V \
  ActivityManager:I ActivityTaskManager:I \
  ApkSignatureVerifier:V PackageParser:V ParsingPackageUtils:V \
  '*:S' | tee install-trace.txt
```

The trailing `'*:S'` silences every tag you did not list. Without it you will drown.

> **Warning**
> Tag names differ slightly between releases and vendors. If a tag produces nothing, drop the filter
> entirely (`adb logcat -v threadtime | tee install-trace.txt`) and grep afterwards. Absence of a tag
> is not absence of the subsystem.

### Step 1.2 — Install

```bash
# host — terminal 1
adb install -r $APK
```

**Expected output:**

```text
Performing Streamed Install
Success
```

The words **"Performing Streamed Install"** are the point. `adb` did not push a file to
`/data/local/tmp`. It opened a `PackageInstaller` session and streamed the APK into it over the
existing `adb` connection.

### Step 1.3 — Read the trace

Stop terminal 2 and read `install-trace.txt`. You are looking for one line from each phase. The exact
wording varies by release; the *phases* do not.

| Phase | Look for something like | Which component |
|---|---|---|
| Session opened | `Created install session [1234567]` | `PackageInstallerService` |
| Bytes written | `Copying/Staging ... base.apk`, `openWrite` | `PackageInstallerSession` |
| Commit requested | `Committing session`, `sealed` | `PackageInstallerSession` |
| Manifest parsed | package name, versionCode, targetSdk echoed | `ParsingPackageUtils` / `PackageParser` |
| Signature verified | v2/v3 scheme mention, or a failure | `ApkSignatureVerifier` |
| Identity assigned | `New package installed` / `uid=10234` | `PackageManagerService` |
| Data dirs created | `createAppData`, `restorecon` | `installd` |
| Compilation | `dex2oat` command line, compiler filter | `dex2oat` |
| App told the world | `PACKAGE_ADDED`, `Start proc` | `ActivityManager` |

Useful greps:

```bash
# host
grep -nE 'install session|Committing|sealed' install-trace.txt
grep -nE 'createAppData|restorecon|destroyAppData' install-trace.txt
grep -nE 'dex2oat|compiler-filter|CompilerFilter' install-trace.txt
grep -nE 'PACKAGE_ADDED|package_added|New package installed' install-trace.txt
grep -nE 'Signature|apkSigning|verif' install-trace.txt
```

**Expected output (shape, not exact text):**

```text
042:  1234  1250 I PackageInstaller: Created install session [98123456] for com.example.probe
118:  1234  1250 D installd: createAppData(com.example.probe, user 0, flags 3)
119:  1234  1250 D installd: restorecon_app_data /data/user/0/com.example.probe
201:  4402  4402 I dex2oat64: dex2oat64 --compiler-filter=verify --dex-file=...base.apk
260:  1234  1310 I PackageManager: New package installed: com.example.probe uid=10234
288:  1234  1400 I ActivityManager: Start proc 4821:com.example.probe/u0a234
```

### Step 1.4 — Diff the filesystem

```bash
# host
adb shell "su -c 'ls -laZ /data/app'"              > after-data-app.txt
adb shell "su -c 'ls -laZ /data/user/0'"           > after-user0.txt
adb shell "su -c 'ls -laZ /data/user_de/0'"        > after-userde0.txt
adb shell "su -c 'cat /data/system/packages.list'" > after-packages-list.txt

diff before-data-app.txt      after-data-app.txt
diff before-user0.txt         after-user0.txt
diff before-userde0.txt       after-userde0.txt
diff before-packages-list.txt after-packages-list.txt
```

**Expected output:**

```text
> drwxr-xr-x 3 system system u:object_r:apk_data_file:s0  ... ~~kQ3n8LmA==~~
> drwx------ 5 u0_a234 u0_a234 u:object_r:app_data_file:s0:c234,c256,c512,c768 ... com.example.probe
> drwx------ 4 u0_a234 u0_a234 u:object_r:app_data_file:s0:c234,c256,c512,c768 ... com.example.probe
> com.example.probe 10234 1 /data/user/0/com.example.probe default:targetSdkVersion=34 3003 0 1 null null
```

Four artefacts, four different owners and labels. Write down which component created each:

| Artefact | Created by | Owner | SELinux label |
|---|---|---|---|
| `/data/app/~~x~~/com.example.probe-y/` | `PackageManagerService` via staging rename | `system:system` | `apk_data_file` |
| `/data/user/0/com.example.probe` | `installd` (`createAppData`) | `u0_a234` | `app_data_file:s0:c…` |
| `/data/user_de/0/com.example.probe` | `installd` (`createAppData`) | `u0_a234` | `app_data_file:s0:c…` |
| `packages.list` line | `PackageManagerService` (`Settings`) | `system:package_info` | `system_data_file` |

### Step 1.5 — Look inside the fresh data directory

```bash
# adb shell (root)
ls -laZ /data/user/0/com.example.probe
ls -laZ /data/user_de/0/com.example.probe
ls -laZ /data/app/~~*~~/com.example.probe*/
```

**Expected output:**

```text
drwxrws--x 2 u0_a234 u0_a234_cache u:object_r:app_data_file:s0:c234,c256,c512,c768  cache
drwxrws--x 2 u0_a234 u0_a234_cache u:object_r:app_data_file:s0:c234,c256,c512,c768  code_cache
lrwxrwxrwx 1 root    root          u:object_r:app_data_file:s0:c234,c256,c512,c768  lib -> /data/app/~~kQ3n8LmA==~~/com.example.probe-9dK2vP1w==/lib/arm64
```

Two details worth noticing immediately:

- **`files/`, `databases/` and `shared_prefs/` do not exist yet.** `installd` creates only `cache` and
  `code_cache`. The rest are created lazily by the framework the first time the app calls
  `getFilesDir()`, `openOrCreateDatabase()` or `getSharedPreferences()`. If you are triaging an app
  and `shared_prefs/` is missing, the app has never written a preference.
- **`cache` is group-owned by a *different* GID** (`u0_a234_cache`, numerically 20000 + appId) with
  the setgid bit. That is how the platform accounts and enforces per-app cache quotas separately from
  the rest of the data directory.

### Step 1.6 — Confirm the compilation artefacts

```bash
# adb shell (root)
find /data/app -path '*com.example.probe*' -name '*.odex' -o -path '*com.example.probe*' -name '*.vdex' -o -path '*com.example.probe*' -name '*.art' 2>/dev/null
ls -la /data/misc/profiles/ref/com.example.probe 2>/dev/null
ls -la /data/misc/profiles/cur/0/com.example.probe 2>/dev/null
dumpsys package dexopt | grep -A 3 com.example.probe
```

**Expected output:**

```text
[com.example.probe]
  path: /data/app/~~kQ3n8LmA==~~/com.example.probe-9dK2vP1w==/base.apk
    arm64: [status=verify] [reason=install]
```

On a modern release, the install-time compiler filter for a normal app is usually `verify` (not full
AOT). Real optimisation happens later, in the background `dexopt` job, guided by the profile the app
generates while running. Force it now if you want to see `dex2oat` do real work:

```bash
# adb shell
cmd package compile -m speed -f com.example.probe
```

and watch `dex2oat` in logcat while it runs.

---

## Part 2 — Do the install by hand with a session

Now perform, manually, what `adb install` did for you.

### Step 2.1 — Uninstall and re-snapshot

```bash
# host
adb uninstall $PKG
adb shell "su -c 'ls /data/user/0 | grep probe'" || echo "gone"
```

### Step 2.2 — Stage the APK on the device (the explicit variant)

```bash
# host
adb push $APK /data/local/tmp/app.apk
```

```bash
# adb shell
SZ=$(stat -c %s /data/local/tmp/app.apk)
echo "size=$SZ"
pm install-create -r -S $SZ
```

**Expected output:**

```text
size=4823119
Success: created install session [98123457]
```

> **Definition — install session**
> A session is a server-side staging area owned by `PackageInstallerService`, identified by an integer.
> It holds the APK bytes and the `SessionParams` (install reason, target user, installer attribution,
> whether it is staged, whether it is multi-package) until you either commit it or abandon it. Nothing
> is visible to the rest of the system until commit succeeds.

The `-S <size>` is mandatory when you stream, because the service pre-allocates space and refuses a
write whose length does not match. Get it wrong and `install-write` fails.

### Step 2.3 — Write and commit

```bash
# adb shell
SID=98123457                                   # the number from the previous step
pm install-write -S $SZ $SID base /data/local/tmp/app.apk
pm install-commit $SID
```

**Expected output:**

```text
Success: streamed 4823119 bytes
Success
```

```bash
# adb shell
pm list packages -U | grep -w "package:com.example.probe"
```

Note the `base` argument to `install-write`. That is the **split name**, not a filename. `base` is
the reserved name for the base APK; configuration splits use names like `config.arm64_v8a`.

### Step 2.4 — Inspect a live session before committing

Repeat the create and write, but pause before commit:

```bash
# host
adb uninstall $PKG
SZ=$(stat -c %s $APK)
SID=$(adb shell pm install-create -r -S $SZ | tr -dc '0-9')
echo "session=$SID"
adb shell pm install-write -S $SZ $SID base - < $APK
```

Now look at the session from the outside:

```bash
# adb shell
dumpsys package installs
```

```bash
# adb shell (root)
ls -laZ /data/app/vmdl$SID.tmp 2>/dev/null || ls -laZ /data/app | grep vmdl
```

**Expected output:**

```text
Active install sessions:
  Session 98123458:
    mode=FULL_INSTALL installerPackageName=com.android.shell
    userId=0 mInstallerUid=2000 createdMillis=... sealed=false
    resolvedBaseCodePath=...
```

```text
drwxrwx--x 2 system install u:object_r:apk_tmp_file:s0 ... vmdl98123458.tmp
```

The staging directory is labelled `apk_tmp_file`, a different SELinux type from the final
`apk_data_file`. That distinction is deliberate: policy can allow the installer to write to staging
while forbidding it to write to installed code.

Now throw it away and prove nothing survived:

```bash
# adb shell
pm install-abandon $SID
dumpsys package installs
pm list packages | grep probe || echo "nothing installed"
```

```bash
# adb shell (root)
ls /data/app | grep vmdl || echo "staging dir gone"
```

### Step 2.5 — Stream from the host with no file on the device

This is exactly what `adb install` does internally, and it is the technique to use when
`/data/local/tmp` is unwritable or monitored.

```bash
# host
SZ=$(stat -c %s $APK)
SID=$(adb shell pm install-create -r -i com.android.vending -S $SZ | tr -dc '0-9')
adb shell pm install-write -S $SZ $SID base - < $APK
adb shell pm install-commit $SID
adb shell dumpsys package $PKG | grep -E 'installerPackageName|installInitiator|packageSource'
```

**Expected output:**

```text
Success: streamed 4823119 bytes
Success
    installerPackageName=com.android.vending
```

> **Pentester's Note**
> `-i com.android.vending` set the attributed installer to the Play Store even though the APK
> arrived over USB. Any app that decides "am I a legitimate install?" by calling
> `getInstallerPackageName()` has just been defeated by one command-line flag. Since API 30, the
> stronger `InstallSourceInfo` triple — installing package, initiating package, originating package —
> is available, and the *initiating* package is much harder to forge because the system records the
> UID that actually opened the session. Check which API the app uses before you call the control
> adequate. Report the naive check as a finding.

Compare:

```bash
# adb shell
dumpsys package com.example.probe | grep -E 'installer|Initiator|originating|packageSource'
```

---

## Part 3 — Install a split APK set

### Step 3.1 — Get a split set

If you have an `.aab`, generate the splits with `bundletool`:

```bash
# host
bundletool build-apks --bundle=app.aab --output=app.apks --local-testing
unzip -o app.apks -d apks/
ls apks/splits/
```

**Expected output:**

```text
base-master.apk  base-arm64_v8a.apk  base-xxhdpi.apk  base-en.apk
```

If you do not have a bundle, you can still do the mechanics with a single APK plus a
`--split`-less session; the important part is the naming, which is described below.

### Step 3.2 — Install the set with one command

```bash
# host
adb install-multiple apks/splits/base-master.apk apks/splits/base-arm64_v8a.apk apks/splits/base-xxhdpi.apk
```

### Step 3.3 — Install the set by hand

```bash
# host
adb uninstall $PKG
SID=$(adb shell pm install-create -r | tr -dc '0-9')

for f in apks/splits/*.apk; do
  n=$(basename "$f" .apk)
  case "$n" in
    *master*) SPLIT=base ;;
    *arm64_v8a*) SPLIT=config.arm64_v8a ;;
    *xxhdpi*) SPLIT=config.xxhdpi ;;
    *en*) SPLIT=config.en ;;
    *) SPLIT="$n" ;;
  esac
  SZ=$(stat -c %s "$f")
  echo "writing $SPLIT ($SZ bytes)"
  adb shell pm install-write -S $SZ $SID "$SPLIT" - < "$f"
done

adb shell pm install-commit $SID
```

**Expected output:**

```text
writing base (3211904 bytes)
Success: streamed 3211904 bytes
writing config.arm64_v8a (1440264 bytes)
Success: streamed 1440264 bytes
writing config.xxhdpi (812031 bytes)
Success: streamed 812031 bytes
Success
```

### Step 3.4 — Confirm they all landed under one identity

```bash
# adb shell
pm path com.example.probe
dumpsys package com.example.probe | grep -E 'splits=|codePath=|userId='
```

**Expected output:**

```text
package:/data/app/~~kQ3n8LmA==~~/com.example.probe-9dK2vP1w==/base.apk
package:/data/app/~~kQ3n8LmA==~~/com.example.probe-9dK2vP1w==/split_config.arm64_v8a.apk
package:/data/app/~~kQ3n8LmA==~~/com.example.probe-9dK2vP1w==/split_config.xxhdpi.apk
    splits=[base, config.arm64_v8a, config.xxhdpi]
    userId=10234
```

One `codePath`, one `userId`, several APKs. Splits are **not** a privilege boundary. They share a
signature, a UID, a data directory and a process.

> **Pentester's Note**
> Any analysis pipeline that pulls only `base.apk` is blind to every native library and every dynamic
> feature module. When you receive an APK from a client, ask whether it is the base of a bundle. When
> you pull from a device, always iterate `pm path` output.

### Step 3.5 — Try to commit a mismatched split

```bash
# host — deliberately break it
adb uninstall $PKG
SID=$(adb shell pm install-create -r | tr -dc '0-9')
adb shell pm install-write -S $(stat -c %s apks/splits/base-arm64_v8a.apk) $SID config.arm64_v8a - < apks/splits/base-arm64_v8a.apk
adb shell pm install-commit $SID
```

**Expected output:**

```text
Failure [INSTALL_FAILED_INVALID_APK: Full install must include a base package]
```

A session containing only splits is rejected. The base APK carries the manifest that defines the
identity; without it there is nothing to install.

---

## Part 4 — Watch the `PACKAGE_ADDED` broadcast

### Step 4.1 — Observe it in logcat

```bash
# host — terminal 2
adb logcat -c
adb logcat -v time | grep -iE 'PACKAGE_ADDED|PACKAGE_REPLACED|PACKAGE_REMOVED|BroadcastQueue.*android.intent.action.PACKAGE'
```

```bash
# host — terminal 1
adb install -r $APK
```

**Expected output:**

```text
09-04 11:20:31.442 I/ActivityManager: Delivering broadcast android.intent.action.PACKAGE_ADDED to ...
```

### Step 4.2 — Observe it with a receiver

`PACKAGE_ADDED` is one of the broadcasts still deliverable to manifest-declared receivers (it is on
the exemption list for the implicit-broadcast restrictions introduced in Android 8). Add a receiver to
any test app:

```xml
<!-- AndroidManifest.xml -->
<receiver
    android:name=".PackageWatcher"
    android:exported="false">
    <intent-filter>
        <action android:name="android.intent.action.PACKAGE_ADDED" />
        <action android:name="android.intent.action.PACKAGE_REMOVED" />
        <action android:name="android.intent.action.PACKAGE_REPLACED" />
        <data android:scheme="package" />
    </intent-filter>
</receiver>
```

```kotlin
// PackageWatcher.kt
package com.example.probe

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class PackageWatcher : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // intent.data is "package:com.whatever" — the scheme-specific part is the package name.
        val pkg = intent.data?.schemeSpecificPart
        // EXTRA_UID is the appId/UID of the package the event is about.
        val uid = intent.getIntExtra(Intent.EXTRA_UID, -1)
        // EXTRA_REPLACING distinguishes an upgrade from a fresh install/removal.
        val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
        Log.i("PackageWatcher", "action=${intent.action} pkg=$pkg uid=$uid replacing=$replacing")
    }
}
```

```bash
# host
adb logcat -c
adb install -r some-other.apk
adb logcat -s PackageWatcher
```

**Expected output:**

```text
I/PackageWatcher: action=android.intent.action.PACKAGE_ADDED pkg=com.other.app uid=10240 replacing=false
```

The `<data android:scheme="package" />` element is mandatory. Without it your filter never matches and
you will spend an hour wondering why.

> **Warning**
> A receiver cannot **prevent** or **modify** an install. `PACKAGE_ADDED` is a notification after the
> fact. Any product that claims to "block malicious installs" from an ordinary app is either a device
> owner using `DevicePolicyManager`, a privileged verifier holding
> `PACKAGE_VERIFICATION_AGENT`-class privileges, or exaggerating.

### Step 4.3 — Note what your own app does *not* receive

Install your own app again and check the log. You will not see your own `PACKAGE_ADDED`, because a
package is stopped when it is replaced and does not receive its own add event. What it does receive,
if it registers for it, is `ACTION_MY_PACKAGE_REPLACED`. That asymmetry is exactly the mechanism
malware uses to re-establish itself after an update, so it is worth seeing once.

---

## Part 5 — Uninstall and watch it all unwind

```bash
# host — terminal 2
adb logcat -c
adb logcat -v time installd:V PackageManager:V ActivityManager:I '*:S'
```

```bash
# host — terminal 1
adb uninstall $PKG
```

```bash
# host
adb shell "su -c 'ls /data/user/0 | grep probe'"    || echo "CE data gone"
adb shell "su -c 'ls /data/user_de/0 | grep probe'" || echo "DE data gone"
adb shell "su -c 'ls /data/app | grep -c probe'"
adb shell "su -c 'grep -c probe /data/system/packages.list'"
```

Then repeat with `-k` and compare:

```bash
# host
adb install -r $APK
adb shell pm uninstall -k $PKG
adb shell "su -c 'ls -d /data/user/0/com.example.probe'"     # still there!
adb shell pm list packages | grep probe || echo "not listed normally"
adb shell pm list packages -u | grep probe                    # but listed with -u
```

**Expected output:**

```text
/data/user/0/com.example.probe
not listed normally
package:com.example.probe
```

That is `DELETE_KEEP_DATA`. The record and the directories survive; only the code and the launcher
entry are gone. Clean up properly:

```bash
# host
adb shell pm uninstall $PKG
```

---

## Hints

<details>
<summary>Hint 1 — <code>pm install-write</code> fails with "Failed to parse size"</summary>

You passed the wrong byte count, or `stat -c %s` behaved differently than expected. On the device use
`stat -c %s`, on macOS hosts use `stat -f %z`. Verify before using it:

```bash
# host (Linux/Git Bash)
stat -c %s app.apk
# host (macOS)
stat -f %z app.apk
# adb shell
stat -c %s /data/local/tmp/app.apk
```

The size must be the exact byte count of what you are about to stream.
</details>

<details>
<summary>Hint 2 — I cannot capture the session id reliably</summary>

`pm install-create` prints `Success: created install session [98123457]` with a trailing carriage
return over `adb shell`. Strip everything that is not a digit:

```bash
# host
SID=$(adb shell pm install-create -r | tr -dc '0-9')
echo "[$SID]"
```

If `$SID` is empty, the create failed — run the command without capturing to see the error.
</details>

<details>
<summary>Hint 3 — logcat shows nothing from installd or dex2oat</summary>

Those tags log at debug/verbose level and some builds filter them. Try, in order: drop the tag filter
entirely and grep afterwards; raise the log level with
`adb shell setprop log.tag.installd VERBOSE`; check the other buffers with
`adb logcat -b all`; and confirm your ring buffer is big enough with
`adb logcat -G 16M`.
</details>

<details>
<summary>Hint 4 — the install fails with INSTALL_FAILED_UPDATE_INCOMPATIBLE</summary>

A package with the same name is installed (possibly with `-k`, so invisible in the normal listing)
and its signature does not match yours. Remove the leftover record:

```bash
# adb shell
pm list packages -u | grep example
pm uninstall com.example.probe
cmd package uninstall com.example.probe
```

If the package is a system app you cannot remove it; pick a different package name.
</details>

<details>
<summary>Hint 5 — INSTALL_FAILED_DEPRECATED_SDK_VERSION on Android 14+</summary>

API 34 and later block installing APKs whose `targetSdkVersion` is very old. Either rebuild with a
modern target, or bypass it for testing:

```bash
# host
adb install --bypass-low-target-sdk-block app.apk
```
</details>

<details>
<summary>Hint 6 — <code>ls /data/app/~~*~~/</code> matches nothing in my shell</summary>

The `~~` is literal text in the directory name, and your host shell may be expanding `~`. Quote it,
or do the globbing on the device:

```bash
# adb shell
ls -d /data/app/*/com.example.probe*
find /data/app -maxdepth 2 -name 'com.example.probe*'
```
</details>

---

## Success criteria

You have completed this lab when you can do all of the following without notes:

1. Install an APK using only `pm install-create`, `pm install-write` and `pm install-commit`,
   streaming from the host, with no file written to `/data/local/tmp`.
2. Point at the log lines proving that the signature was verified **before** the data directory was
   created, and explain why that order is mandatory.
3. Name the four filesystem artefacts an install creates, their owners, and their SELinux labels.
4. Explain why `cache/` has a different group from its parent directory.
5. Explain why `files/` and `shared_prefs/` do not exist immediately after install.
6. Install a three-APK split set by hand and show that all three share one `codePath` and one
   `userId`.
7. Set a false `installerPackageName` and explain to a developer which API they should have used
   instead.
8. Show the difference on disk between `pm uninstall` and `pm uninstall -k`.
9. Abandon a session and demonstrate that the staging directory disappeared.

---

## What you learned

- **`adb install` is a client of the same public API the Play Store uses.** There is no privileged
  back door for the store; there is `PackageInstaller`, and everything goes through it. That is why
  you can reproduce every step by hand.
- **Installation is transactional.** Sessions can be created, written, inspected, committed or
  abandoned. Nothing about the package is visible to any other process until commit succeeds, which
  is what makes an interrupted install safe.
- **Order matters and is security-relevant.** Parse, then verify the signature, then allocate the
  identity, then create labelled storage, then compile, then announce. A build that created the data
  directory before verifying the signature would leak an identity to unverified code.
- **`installd` exists because `system_server` must not be able to write arbitrary files as arbitrary
  UIDs.** Separating the privileged filesystem operations into a tiny native daemon with a narrow
  Binder interface is a deliberate privilege-separation decision, and the AIDL file
  (`frameworks/native/cmds/installd/binder/android/os/IInstalld.aidl`) is the complete list of what
  the framework is allowed to ask for.
- **Installer attribution is metadata, not proof.** `installerPackageName` is settable from the
  command line. `InstallSourceInfo.getInitiatingPackageName()` is much stronger because the system
  records the UID that actually opened the session.
- **Splits are one app.** One signature, one UID, one data directory, one process — no boundary.
- **Broadcasts are notifications, not hooks.** `PACKAGE_ADDED` arrives after the fact and cannot veto
  anything.

---

## Next

- [Lab 03 — CTF: The shared UID heist](lab-03-ctf-the-shared-uid-heist.md)
- [`../scripts/trace-app-startup.js`](../scripts/trace-app-startup.js) — now that the app is
  installed, watch what happens the first time it runs.
- [`../examples/StartupProviderPersistence/README.md`](../examples/StartupProviderPersistence/README.md)
  — the code that runs before `Application.onCreate()`.
- [`../../10-APK-Internals/README.md`](../../10-APK-Internals/README.md) — what was inside the file
  you just watched being parsed.
