# Lab 01 — App Identity and UID

**Difficulty:** Beginner
**Time:** 45–60 minutes
**Chapter:** [09 — Android App Internals](../README.md)

---

## Objective

By the end of this lab you will be able to take any package name on any Android device and, without
guessing, state:

1. The **appId** the system assigned to it and the **UID** its processes actually run as.
2. Which **Android user** (owner profile, work profile, secondary user) that UID belongs to.
3. Where its **code** and its **data** live on disk.
4. Which **supplementary GIDs** it holds and which permission each one came from.
5. Its **SELinux domain** and the MLS categories encoding its identity.
6. How to confirm every one of the above from at least two independent sources, so that when a tool
   lies to you, you notice.

That last point is the real objective. Anyone can run `pm list packages -U`. A researcher can
corroborate it against `/proc`, against `packages.list`, and against the kernel's own view.

> **Mental Model**
> You are performing an identity investigation on a suspect. The package name is the name on the
> door. The UID is the fingerprint. The SELinux label is the security clearance badge. The data
> directory is the office. You will visit all four and check that they agree.

---

## Prerequisites

| Requirement | Why | How to check |
|---|---|---|
| A working `adb` on your host | every step uses it | `adb version` |
| An Android emulator or device, API 33+ | baseline for this chapter | `adb shell getprop ro.build.version.sdk` |
| **Root on the device** for steps 6–8 | `/data/system/packages.list` is root-only | `adb root` then `adb shell id` |
| One installed third-party app | the subject of the investigation | `adb shell pm list packages -3` |
| Read [`../README.md`](../README.md) sections 1–3 | you need the vocabulary | — |

### Recommended device

Use an **Android Studio emulator with a plain "Google APIs" or AOSP system image, not a "Google
Play" image**. Play-enabled images refuse `adb root`, which blocks half of this lab.

```bash
# host
emulator -list-avds
emulator -avd Pixel_6_API_34 &
adb wait-for-device
adb root                 # must print "restarting adbd as root" or "adbd is already running as root"
adb shell whoami         # must print "root"
```

If `adb root` prints `adbd cannot run as root in production builds`, your image is a Play image.
Create a new AVD and pick a system image whose "Target" column says **Google APIs** (without "Play
Store") or **Android (AOSP)**.

---

## Setup

### S1. Get a subject app onto the device

Any third-party app works. If you have none, build the probe from this chapter's `examples/` folder,
or install any small APK you already have.

```bash
# host
adb install ./app-debug.apk
adb shell pm list packages -3
```

Pick one package name and export it so every later command is copy-paste-able:

```bash
# host
PKG=com.example.probe        # <- change this to your package
echo $PKG
```

```bash
# adb shell — do the same inside the device shell when you get there
PKG=com.example.probe
```

### S2. Make sure the app has actually run at least once

A package that has never been launched has no process, and half this lab inspects a process.

```bash
# host
adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1
adb shell pidof $PKG
```

`pidof` must print a number. If it prints nothing, open the app manually on the emulator screen.

---

## Steps

### Step 1 — Ask the package manager for the UID

```bash
# adb shell
pm list packages -U | grep -w "package:$PKG"
```

**Expected output:**

```text
package:com.example.probe uid:10234
```

Write that number down. Everything else in this lab either confirms it or explains it.

> **Definition — appId**
> The number after `uid:` here is technically the **appId**: the per-package identifier
> `PackageManagerService` allocated from the range 10000–19999. For the owner user (userId 0) the
> appId and the UID happen to be the same number, which is why the two words get used
> interchangeably. They stop being the same the moment a second user is involved — Step 9.

### Step 2 — Do the arithmetic yourself

```bash
# host
UID_VAL=10234                       # <- the number from Step 1
echo "userId = $((UID_VAL / 100000))"
echo "appId  = $((UID_VAL % 100000))"
```

**Expected output:**

```text
userId = 0
appId  = 10234
```

The formula, memorise it:

```text
UID    = userId * 100000 + appId
userId = UID / 100000
appId  = UID % 100000
```

The constant 100000 is `UserHandle.PER_USER_RANGE` in
`frameworks/base/core/java/android/os/UserHandle.java`, and `AID_USER_OFFSET` in
`system/core/libcutils/include/private/android_filesystem_config.h`. It is a hard architectural limit:
Android supports at most 100000 apps per user because the arithmetic says so.

### Step 3 — Corroborate with `dumpsys package`

```bash
# adb shell
dumpsys package $PKG | grep -E 'userId=|sharedUser|dataDir=|codePath=|primaryCpuAbi=|targetSdk=|flags=\[|gids='
```

**Expected output (abridged, yours will differ):**

```text
    codePath=/data/app/~~kQ3n8LmA==~~/com.example.probe-9dK2vP1w==
    dataDir=/data/user/0/com.example.probe
    primaryCpuAbi=arm64-v8a
    versionCode=1 minSdk=24 targetSdk=34
    flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
    userId=10234
    gids=[3003]
```

Three things to notice:

| Line | Meaning |
|---|---|
| `userId=10234` | PMS calls the appId `userId` internally. The name is historic and misleading; it is **not** the Android multi-user id. |
| `gids=[3003]` | GID 3003 is `AID_INET`. The app holds `android.permission.INTERNET`. |
| `dataDir=/data/user/0/…` | the canonical per-user path, not `/data/data/…` |

If you also see a line beginning `sharedUser=`, your subject is in a shared-UID group and Lab 03
becomes very relevant. Pick a different subject for now.

### Step 4 — Find the running process and its UID from the kernel's own records

```bash
# adb shell
PID=$(pidof $PKG)
echo "pid=$PID"
cat /proc/$PID/status | grep -E '^(Name|Uid|Gid|Groups|TracerPid|Threads)'
```

**Expected output:**

```text
pid=4821
Name:	xample.probe
Uid:	10234	10234	10234	10234
Gid:	10234	10234	10234	10234
Groups:	3003 9997 20234 50234
TracerPid:	0
Threads:	17
```

| Field | Read it as |
|---|---|
| `Name:` | truncated to 15 characters by the kernel — this is `comm`, not the full process name |
| `Uid:` | real, effective, saved-set, filesystem UID. All four are 10234; the app cannot change them. |
| `Groups:` | supplementary GIDs. **3003** is `INTERNET`. 9997 is `AID_EVERYBODY`. 20234 and 50234 are the per-app cache GID and shared GID derived from the appId. |
| `TracerPid:` | 0 means nothing is debugging it. If Frida is attached, this becomes non-zero. |

> **Under the Hood**
> The `Uid:` line has four numbers because Linux tracks four UIDs per process. Zygote sets all four
> with `setresuid()` immediately after forking, *and drops all capabilities*, so there is no saved-set
> UID for the app to restore. This is why an app cannot "become root again" — the privilege was not
> merely unused, it was destroyed before the app's first instruction ran.

### Step 5 — Get the real process name from `cmdline`

```bash
# adb shell
cat /proc/$PID/cmdline | tr '\0' '\n'
```

**Expected output:**

```text
com.example.probe
```

`/proc/<pid>/comm` (the `Name:` field above) is capped at 15 bytes, which is why long package names
look mangled in `ps` output on some tools. `cmdline` holds the full name, and for a multi-process app
it is where you see the `:worker` suffix. Try this against a browser to see the difference.

### Step 6 — Read the `packages.list` record (root)

```bash
# adb shell (root)
grep -w "^$PKG" /data/system/packages.list
```

**Expected output:**

```text
com.example.probe 10234 1 /data/user/0/com.example.probe default:targetSdkVersion=34 3003 0 1 null null
```

Map every field:

| # | Value | Field |
|---|---|---|
| 1 | `com.example.probe` | package name |
| 2 | `10234` | uid |
| 3 | `1` | **debuggable flag** — this is the byte `run-as` reads |
| 4 | `/data/user/0/com.example.probe` | CE data dir |
| 5 | `default:targetSdkVersion=34` | seinfo, fed into `seapp_contexts` |
| 6 | `3003` | supplementary GIDs |
| 7 | `0` | profileable from shell |
| 8 | `1` | longVersionCode |
| 9+ | `null null` | later additions; the column count grows between releases |

Verify field 3 by using it:

```bash
# adb shell
run-as $PKG id
```

If field 3 was `1`, this prints `uid=10234(u0_a234) gid=10234(u0_a234) …`. If it was `0`, it prints
`run-as: package not debuggable`. You have just watched a single byte in a text file decide whether
an attacker with USB access owns the app's data.

### Step 7 — Read the `packages.xml` record (root)

```bash
# adb shell (root)
grep -A 12 "package name=\"$PKG\"" /data/system/packages.xml
```

**Expected output (abridged):**

```xml
<package name="com.example.probe"
    codePath="/data/app/~~kQ3n8LmA==~~/com.example.probe-9dK2vP1w=="
    nativeLibraryPath="/data/app/~~kQ3n8LmA==~~/com.example.probe-9dK2vP1w==/lib"
    primaryCpuAbi="arm64-v8a" publicFlags="944291398" privateFlags="536870912"
    ft="18f2c1a4b00" it="18f2c1a4c11" ut="18f2c1a4c11" version="1"
    userId="10234">
    <sigs count="1" schemeVersion="3">
        <cert index="0" key="30820...." />
    </sigs>
    <perms>
        <item name="android.permission.INTERNET" granted="true" flags="0" />
    </perms>
    <proper-signing-keyset identifier="7" />
</package>
```

| Attribute | Meaning |
|---|---|
| `userId="10234"` | **the appId again** — third independent source now agrees |
| `ft` / `it` / `ut` | APK file time, first install time, last update time, as **hexadecimal** milliseconds since the Unix epoch |
| `publicFlags` / `privateFlags` | decimal bitmaps of `ApplicationInfo` flags |
| `<sigs>` | the signing certificate; `key=` appears only the first time a cert is seen in the file |
| `<perms>` | granted permission state |

Convert an install timestamp to something human:

```bash
# host — hex ms since epoch -> date
python3 -c "import datetime;print(datetime.datetime.fromtimestamp(int('18f2c1a4c11',16)/1000))"
```

### Step 8 — Read the SELinux label on the process and on the data

```bash
# adb shell
ps -A -Z | grep $PKG
cat /proc/$PID/attr/current
```

**Expected output:**

```text
u:r:untrusted_app:s0:c234,c256,c512,c768 u0_a234 4821 289 ... com.example.probe
u:r:untrusted_app:s0:c234,c256,c512,c768
```

```bash
# adb shell (root)
ls -ldZ /data/user/0/$PKG
ls -ldZ /data/user_de/0/$PKG
```

**Expected output:**

```text
drwx------ 5 u0_a234 u0_a234 u:object_r:app_data_file:s0:c234,c256,c512,c768 4096 ... /data/user/0/com.example.probe
drwx------ 4 u0_a234 u0_a234 u:object_r:app_data_file:s0:c234,c256,c512,c768 4096 ... /data/user_de/0/com.example.probe
```

Now decode the categories, and check the arithmetic yourself:

```bash
# host
u=10234; a=$((u % 100000 - 10000)); n=$((u / 100000))
echo "c$((a & 255)),c$((256 + (a >> 8))),c$((512 + (n & 255))),c$((768 + (n >> 8)))"
```

**Expected output:**

```text
c234,c256,c512,c768
```

The four categories are a lossless encoding of `(appId, userId)`:

| Category slot | Formula | For appId 10234, user 0 |
|---|---|---|
| first | `(appId - 10000) & 0xff` | `c234` |
| second | `256 + ((appId - 10000) >> 8)` | `c256` |
| third | `512 + (userId & 0xff)` | `c512` |
| fourth | `768 + (userId >> 8)` | `c768` |

> **Under the Hood**
> This encoding is produced by libselinux's Android backend under
> `external/selinux/libselinux/src/android/` when `system/sepolicy/private/seapp_contexts` marks the
> entry `levelFrom=all`. Because SELinux MLS requires the category sets to match **exactly** for
> access, this gives Android a second, independent isolation mechanism layered on top of UIDs. Even a
> process that somehow acquired the wrong UID would still be refused by the label mismatch.

### Step 9 — Watch the UID change in a second Android user

This is the step that proves appId and UID are different things.

```bash
# adb shell
pm list users
pm create-user Lab                      # note the id it prints, usually 10
pm install-existing --user 10 $PKG
pm list packages --user 10 -U | grep -w "package:$PKG"
```

**Expected output:**

```text
UserInfo{0:Owner:4c13} running
UserInfo{10:Lab:10} 
Success: created user id 10
Package com.example.probe installed for user: 10
package:com.example.probe uid:1010234
```

The appId did not change. The **UID** did:

```text
appId  = 10234   (unchanged — it is a property of the package)
userId = 10      (new)
UID    = 10 * 100000 + 10234 = 1010234
```

```bash
# adb shell (root)
ls -ldZ /data/user/10/$PKG
```

**Expected output:**

```text
drwx------ 4 u10_a234 u10_a234 u:object_r:app_data_file:s0:c234,c256,c522,c768 4096 ... /data/user/10/com.example.probe
```

Two things changed and one did not:

| | User 0 | User 10 |
|---|---|---|
| UID | 10234 | 1010234 |
| Username string | `u0_a234` | `u10_a234` |
| MLS third category | `c512` | `c522` (512 + 10) |
| MLS first two categories | `c234,c256` | `c234,c256` (same appId) |
| Data directory | `/data/user/0/…` | `/data/user/10/…` |

Clean up when you are done:

```bash
# adb shell
pm remove-user 10
```

### Step 10 — Enumerate the whole device and find the shared UIDs

```bash
# adb shell
pm list packages -U | sed 's/package://;s/uid://' | awk '{print $2, $1}' | sort -n | head -30
```

Then find every UID backing more than one package:

```bash
# adb shell
pm list packages -U | sed 's/package://;s/uid://' | awk '{print $2, $1}' | sort -n \
 | awk '{m[$1] = m[$1] " " $2} END {for (u in m) {n = split(m[u], a, " "); if (n > 1) print u ":" m[u]}}'
```

**Expected output (an emulator will show something like):**

```text
1000: android com.android.settings com.android.providers.settings ...
1001: com.android.phone com.android.providers.telephony ...
1002: com.android.bluetooth ...
```

Those are the platform's own shared users, signed with the platform key. On a real device you may
also find third-party groups in the 10000+ range — an app and its companion, a vendor suite, or a
launcher and its widget host. Note them; they are the highest-value targets in Lab 03.

---

## Hints

<details>
<summary>Hint 1 — <code>pm list packages -U</code> prints nothing for my package</summary>

Either the package is not installed for the current user, or you typed the name wrong. Check with a
substring search rather than an exact match, and check other users:

```bash
# adb shell
pm list packages | grep -i probe
pm list packages --user 10 | grep -i probe
pm list packages -u | grep -i probe      # includes uninstalled-with-data
```
</details>

<details>
<summary>Hint 2 — <code>cat /data/system/packages.list</code> says Permission denied</summary>

You are running as `shell` (uid 2000), not root. The file is mode `0640` owned by
`system:package_info`. Run `adb root` on the host first; if that is refused, your emulator image
includes Google Play and cannot be rooted this way. Recreate the AVD with a "Google APIs" or AOSP
image. On a physical device you need Magisk or an equivalent.
</details>

<details>
<summary>Hint 3 — <code>pidof</code> returns nothing</summary>

The app has no running process. Either it was never launched, or the system killed it. Launch it:

```bash
# adb shell
monkey -p com.example.probe -c android.intent.category.LAUNCHER 1
# or, if you know the activity
am start -n com.example.probe/.MainActivity
```

Apps with no launcher activity (widgets, some services) need `am start-service` or a triggering
intent. Some apps also stop themselves quickly; run `pidof` immediately after launching.
</details>

<details>
<summary>Hint 4 — my SELinux categories do not match the formula</summary>

Three legitimate reasons. First, the app is not `untrusted_app` — platform, privileged and system
apps use `levelFrom=user` or no level at all, so they get only `c512,c768` or no categories.
Second, you computed with the full UID instead of `appId - 10000`. Third, you are on a device whose
vendor policy differs from AOSP. Check the domain in `ps -A -Z` first: the formula in Step 8 applies
to `untrusted_app*` domains.
</details>

<details>
<summary>Hint 5 — <code>pm create-user</code> fails</summary>

Some builds limit the number of users (`fw.max_users`), and some emulator images disable multi-user.
Check the limit and the current list:

```bash
# adb shell
pm list users
getprop fw.max_users
dumpsys user | head -20
```

You can raise the limit on an emulator with `adb shell setprop fw.max_users 5` followed by a reboot,
or skip Step 9 and reason through the arithmetic on paper — the numbers are given in the step.
</details>

---

## Success criteria

You have completed the lab when you can, for your chosen package, fill in this table from memory of
the commands (not from memory of the values) and explain each row in one sentence:

| Fact | Value | Source you used |
|---|---|---|
| Package name | | `pm list packages` |
| appId | | `dumpsys package` `userId=` |
| UID in user 0 | | `/proc/<pid>/status` `Uid:` |
| UID in user 10 | | `pm list packages --user 10 -U` |
| Supplementary GIDs | | `/proc/<pid>/status` `Groups:` |
| Which permission gave GID 3003 | | `platform.xml` / `dumpsys package` |
| CE data dir | | `dumpsys package` `dataDir=` |
| DE data dir | | `ls /data/user_de/0/` |
| Code path | | `pm path` |
| Debuggable? | | `packages.list` field 3, confirmed with `run-as` |
| SELinux process domain | | `ps -A -Z` |
| SELinux data label | | `ls -ldZ` |
| MLS categories, and why those numbers | | computed by hand |

And when you can answer these three without looking anything up:

1. Why does `dumpsys package` call the appId `userId=`, and why is that name wrong?
2. If an app is uninstalled and a different app is installed, can the new app receive the old app's
   appId? What does that mean for any log entry that recorded only a UID?
3. A colleague says "the app runs as UID 1010234, so it must be a system app because the number is
   over a million". Correct them in one sentence.

---

## What you learned

- **The package name is the framework's identity; the UID is the kernel's identity.** Everything
  Android does for security has to be expressible as one of the two, and translating between them is
  the first move in almost every investigation.
- **`UID = userId * 100000 + appId`** is not trivia. It is why a work-profile app is a genuinely
  different Linux user, why `/data/user/10/` exists, and why a hard-coded `/data/data` path in your
  tooling silently examines the wrong profile.
- **The same fact is recorded in at least four places** — the in-memory `Settings` object exposed by
  `dumpsys`, `packages.xml`, `packages.list`, and the kernel's `/proc`. They agree on a healthy
  device. Where they *disagree*, something interesting is happening: a rootkit hiding a package, a
  corrupted upgrade, or a tool lying to you.
- **A single character in a text file (`packages.list` field 3) decides whether `run-as` works.** The
  distance between "release build" and "attacker has full read/write on user data" is that byte.
- **SELinux labels encode the same identity a second time, arithmetically.** Defence in depth is not
  a slogan here; it is `c234,c256,c512,c768`.
- **Supplementary GIDs are the visible remnant of the old, pre-runtime-permission world.** GID 3003
  in `Groups:` means the kernel itself will let this process create a network socket. No framework
  check is involved.

---

## Next

- [Lab 02 — Tracing the install flow](lab-02-tracing-the-install-flow.md) — watch the record you just
  read get created, step by step.
- [Lab 03 — CTF: The shared UID heist](lab-03-ctf-the-shared-uid-heist.md) — attack the identity
  model you just mapped.
- [`../examples/AppIdentityProbe.kt`](../examples/AppIdentityProbe.kt) — the same investigation, from
  inside the app.
- [`../scripts/app-identity-dump.sh`](../scripts/app-identity-dump.sh) — all of Steps 1–8, automated.
