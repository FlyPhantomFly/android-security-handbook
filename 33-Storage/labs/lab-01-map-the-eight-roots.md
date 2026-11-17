# Lab 01 — Map the Eight Roots

**Difficulty:** Beginner
**Time:** 90 minutes
**Prerequisites:** [Chapter 33 §3.1–3.7](../README.md),
[09-Android-App-Internals §3.11](../../09-Android-App-Internals/README.md),
[21-App-Sandbox](../../21-App-Sandbox/README.md), a rooted device or emulator with `adb`,
a POSIX shell (Git Bash on Windows is fine)

---

## Objective

Enumerate **every place one installed app can put a byte** on a real device, and classify each of
those places by who can reach it. You will do this against apps that are already on the phone —
`com.google.android.gms` and `com.android.chrome` — so nothing has to be built, installed or
compiled before you start.

You finish with three artefacts:

1. A completed **roots table** for one package, filled in from measurement rather than from memory.
2. A **reachability verdict** for every world-readable file the map turned up, each one argued at
   three separate layers: discretionary permissions, mandatory access control, and content.
3. A one-paragraph **severity argument** for the single most interesting file you found, written
   the way it would appear in a report — including, if that is the honest answer, the sentence
   "this is not a finding".

## Why this matters

Nearly every incomplete storage assessment in the wild is incomplete for the same reason: the
tester recursed `/data/data/<pkg>` and stopped. That single habit misses device-encrypted storage,
which is a **different tree** and not a subdirectory of the credential-encrypted one. It misses
`getExternalFilesDir()`, which is app-specific but is not protected by the app's uid. It misses
`getExternalMediaDirs()`, which is indexed by MediaStore and therefore visible to any app holding a
media read permission. It misses the ART profile, which records which of the app's methods ran. And
it misses everything the app wrote into a shared collection, because those files live at paths that
contain no trace of the package name.

You cannot say "the app leaks X" until you can say where the app's bytes could possibly be. This
lab builds that map once, by hand, so that every later lab in the chapter has something to diff
against.

The second half of the lab is the more important half. Finding a world-readable file is easy and
almost always wrong. Deciding whether a world-readable file **matters** requires three independent
questions answered in order, and the whole professional difference between a storage assessment and
a scanner report lives in the discipline of asking all three.

> **Mental Model**
> An Android app's storage is not one box. It is a set of boxes with different lids, and the lids
> are held shut by different mechanisms: the uid sandbox holds two of them, a FUSE daemon holds
> three, a content provider holds one, and the system holds the rest on the app's behalf without
> asking. When you ask "is this data safe", you are really asking "which box, whose lid, and who
> else holds a key".

---

## Setup

### What you need

You need a device you own, with root, and `adb` on your host. Root is not optional for this lab:
without it the `/data` roots are unreadable and half the map comes back blank. The lab still runs
`--no-root` at one point on purpose, so that you see exactly how much an unprivileged attacker on
the same device can enumerate, but the baseline needs `su`.

The measurements quoted throughout this lab were taken on:

| Property | Value |
|---|---|
| Model | Redmi `M2101K6P` (`sweetin`) |
| Android | 11, API 30, MIUI 12.5 |
| Root | Magisk |
| SELinux | Enforcing |
| `/data` filesystem | f2fs |
| Encryption | File-based (`ro.crypto.type=file`, `ro.crypto.state=encrypted`) |
| Filenames mode | `aes-256-cts` |

Your device will differ. **That is the point of the lab** — every number below is an observation on
one handset, and the skill being trained is producing your own, not memorising these.

### Confirm the ground truth before you measure anything

```bash
# host
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.crypto.type
adb shell getprop ro.crypto.state
adb shell getenforce
adb shell "su -c 'id'"
```

On the reference device those return `M2101K6P`, `11`, `30`, `file`, `encrypted`, `Enforcing`, and
`uid=0(root) gid=0(root)` respectively.

> **Definition — FBE (file-based encryption)**
> A scheme in which each file (and each filename) under `/data` is encrypted with a key derived per
> directory tree, rather than the whole partition being encrypted with one key. `ro.crypto.type=file`
> means FBE is in use. FBE is what makes "credential-encrypted" and "device-encrypted" storage two
> genuinely different security domains rather than two directory names, and it is why the CE tree is
> unreadable — not merely unreadable *by policy*, but cryptographically unavailable — until the user
> has unlocked the device once since boot.

> **Warning**
> FBE is irrelevant to every finding in this chapter, and saying so out loud saves you an argument
> with a developer later. FBE protects the data on a handset that is **powered off or before first
> unlock**. It does nothing at all against a process running as another uid on a booted, unlocked
> phone, which is the adversary in every lab here.

### Make the script executable

```bash
# host
cd Android-Security-Handbook/33-Storage
chmod +x scripts/storage-map.sh
./scripts/storage-map.sh --help
```

Read the `WHAT THIS WILL *NOT* TELL YOU` block in
[`../scripts/storage-map.sh`](../scripts/storage-map.sh) before you run it once. A tool whose limits
you have not read is a tool whose output you cannot defend.

---

## Steps

### Step 1 — Establish the shell you are attacking from

Before mapping anything, find out what your own `adb shell` can do. Every later result is relative
to this.

```bash
# adb shell
id
```

On the reference device:

```
# adb shell — measured
uid=2000(shell) gid=2000(shell) groups=1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),...
```

Three of those group memberships decide most of this lab. `sdcard_rw` (1015) and `sdcard_r` (1028)
are the historical shared-storage groups. `ext_data_rw` (**1078**) is the one introduced for
Android 11, and it is why the shell can do something an ordinary app cannot:

```bash
# adb shell
ls /sdcard/Android/data | wc -l
```

The reference device answers `111`. Hold on to that number — in [Lab 03](lab-03-scoped-storage-and-fuse.md)
you will run the equivalent call from inside an app and get `null`.

**Question 1.** `adb shell` is uid 2000, not uid 0 and not the app's uid. Which of the eight roots
below do you expect it to read without `su`, and which do you expect it to be refused? Write your
prediction down now, before measuring.

### Step 2 — Run the map against a preinstalled app

```bash
# host
./scripts/storage-map.sh com.google.android.gms
```

Then again with the media census, which asks MediaStore rather than the filesystem:

```bash
# host
./scripts/storage-map.sh com.google.android.gms --media
```

And once with root disabled, to see the unprivileged view:

```bash
# host
./scripts/storage-map.sh com.google.android.gms --no-root --brief
```

The script prints a header, then one block per root. The header line that matters most is the
privilege line — when it says `shell uid 2000 -- /data roots will be unreadable`, every "missing"
below it means "I was not allowed to look", not "it is not there".

> **Pentester's Note**
> Absence of evidence is the single most common lie a storage tool tells you. `storage-map.sh`
> distinguishes `MISSING` from `UNREADABLE` for exactly this reason. If a tool you are using does
> not make that distinction, you must make it yourself, every time, before writing anything down.

### Step 3 — The eight roots, filled in by hand

Now fill this table in from your own output. Six of the eight are directories derived from the
package name; the seventh is not a path at all; the eighth is not the app's.

| # | Root | Path (user 0) | API that returns it |
|---|---|---|---|
| 1 | CE — credential-encrypted | `/data/user/0/<pkg>` | `getDataDir()`, `getFilesDir()`, `getCacheDir()` |
| 2 | DE — device-encrypted | `/data/user_de/0/<pkg>` | `createDeviceProtectedStorageContext().getFilesDir()` |
| 3 | External app-specific | `/storage/emulated/0/Android/data/<pkg>` | `getExternalFilesDir()`, `getExternalCacheDir()` |
| 4 | External media | `/storage/emulated/0/Android/media/<pkg>` | `getExternalMediaDirs()` |
| 5 | OBB | `/storage/emulated/0/Android/obb/<pkg>` | expansion files |
| 6 | ART profile | `/data/misc/profiles/cur/0/<pkg>` | none — written by the runtime |
| 7 | Shared collections | scattered: `Download/`, `DCIM/`, `Documents/` | `MediaStore` inserts |
| 8 | System-held copies | logcat ring buffer, recents task snapshot, backup transport | none — the app cannot see or delete these |

Roots 1–6 are what `storage-map.sh` walks. Root 7 is what `--media` asks MediaStore about, because
the filesystem cannot attribute `/sdcard/Download/report.pdf` to any package. Root 8 the script
cannot enumerate at all, and neither can the app: those bytes are written by `system_server` or by
`logd` on the app's behalf, live outside the app's sandbox, and are not the app's to delete.

**Question 2.** For each of the eight, write one sentence naming the mechanism that keeps other apps
out — or stating that nothing does.

### Step 4 — Why `/data/data` and `/data/user/0` are the same directory

Folklore says `/data/data` is a symlink to `/data/user/0`. Even this repository's
[79-Glossary](../../79-Glossary/README.md) has said so. On the reference device it is not a symlink;
it is a **bind mount**, and you can prove it in three commands.

```bash
# adb shell as root
readlink /data/user/0 ; echo "readlink exit: $?"
stat -c %i /data/data
stat -c %i /data/user/0
grep ' /data/user/0 ' /proc/mounts
```

Measured:

```
# adb shell as root — measured
readlink exit: 1
118
118
/dev/block/dm-10 /data/user/0 f2fs rw,lazytime,...
```

`readlink` exits 1 because the path is not a symbolic link. Both paths report inode **118**, which
means they resolve to the same directory object on the same filesystem. And `/proc/mounts` lists
`/data/user/0` as a mount point in its own right.

> **Definition — bind mount**
> A Linux mount that makes an existing directory subtree visible at a second path. Both paths are
> real directory entries resolving to the same inode; neither is a link to the other. `mount --bind`
> creates one. Unlike a symlink, a bind mount is invisible to `readlink`, survives a chroot, and can
> carry different mount options at each location.

Android 11 adds two more bind mounts you will see in `/proc/mounts` and should recognise:

```bash
# adb shell as root
grep data_mirror /proc/mounts
```

```
# adb shell as root — measured
/data_mirror/data_ce/null/0
/data_mirror/data_de/null
```

These are the mirrors the platform uses to hand an app its own data directory without exposing the
whole tree, and they are why a naive `find /data -name '*.xml'` produces every app file twice.

**Question 3.** Why does the distinction between symlink and bind mount matter operationally? Name
one command whose output differs, and one security conclusion that would be wrong if you assumed
symlink.

### Step 5 — `/sdcard`, FUSE, and the sdcardfs split

```bash
# adb shell
ls -ld /sdcard
```

```
# adb shell — measured
lrwxrwxrwx 1 root root 21 ... /sdcard -> /storage/self/primary
```

That one *is* a symlink. Now look at what is underneath it:

```bash
# adb shell as root
grep -E 'emulated|sdcardfs|fuse' /proc/mounts
```

The reference device shows a layered arrangement that surprises most people:

```
# adb shell as root — measured
/dev/fuse /storage/emulated fuse rw,lazytime,nosuid,nodev,noexec,noatime,user_id=0,group_id=0,allow_other
/data/media /storage/emulated/0/Android/data sdcardfs rw,nosuid,nodev,noexec,noatime,fsuid=1023,fsgid=1023,gid=1015,multiuser,mask=6,derive_gid,default_normal,unshared_obb
```

plus `/mnt/pass_through/0/emulated`, `/mnt/runtime/{default,read,write,full}/emulated` (all
`sdcardfs`), and `/mnt/user/0/emulated` (FUSE).

So on this device the shared root is served by the **FUSE daemon**, while `Android/data` and
`Android/obb` are **bind-mounted sdcardfs** underneath it — a performance shortcut, because routing
every app's own external I/O through userspace FUSE is expensive.

> **Under the Hood**
> FUSE ("Filesystem in Userspace") means a userspace process, here the `MediaProvider`-backed
> daemon, answers every `open`, `read`, `getattr` and `unlink` on that mount. That is what makes
> scoped storage enforceable at all: the restriction is implemented in the daemon that services the
> syscall, not in a permission check the app could route around with a raw `File` call. It is also
> why file ownership under `/sdcard` is uninformative — the daemon reports a synthetic owner
> (`fsuid=1023`, i.e. `media_rw`), not the uid that actually wrote the bytes.

**Question 4.** `ls -l /sdcard/Download/something.apk` shows an owner. Why can you not use that owner
to say which app created the file? What *can* answer that question?

### Step 6 — Read the SELinux labels, and decode the categories

Discretionary permissions ("mode bits") are only the first gate. The second is SELinux, and on
Android it does most of the work of keeping apps apart.

```bash
# adb shell as root
ls -ldZ /data/data/com.android.chrome
ls -ldZ /data/data/com.google.android.gms
ls -ldZ /data/misc/profiles/cur/0/com.android.chrome
ls -ldZ /storage/emulated/0/Android/media/com.android.chrome
```

Measured on the reference device:

| Path | Label |
|---|---|
| `/data/data/com.android.chrome` | `u:object_r:app_data_file:s0:c196,c256,c512,c768` |
| `/data/data/me.bmax.apatch` | `u:object_r:app_data_file:s0:c13,c257,c512,c768` |
| `/data/data/com.google.android.gms` | `u:object_r:privapp_data_file:s0:c512,c768` |
| `/storage/emulated/0/Android/media/<pkg>` | `u:object_r:fuse:s0` |
| `/data/misc/profiles/cur/0/<pkg>` | `user_profile_data_file` |

Look at the numbers after `s0:`. Those are **MCS categories**, and they are computed from the app's
uid.

> **Definition — MCS (Multi-Category Security)**
> An SELinux mechanism that attaches a set of opaque categories to a label. A subject may access an
> object only if the subject's category set **dominates** (is a superset of) the object's. Android
> uses it to isolate apps from one another *within* the single `untrusted_app` domain: two apps that
> share a type still cannot read each other, because their category sets differ.

Android derives the two per-app categories from the app id with this formula
([22-SELinux](../../22-SELinux/README.md) has the source):

```
# host — the derivation, not a command
c[ appId & 0xff ]          and          c[ 256 + (appId >> 8) ]
```

Verify it yourself against a real app:

```bash
# adb shell as root
dumpsys package me.bmax.apatch | grep -m1 userId=
ls -ldZ /data/data/me.bmax.apatch
```

The app id is 269. Then `269 & 0xff = 13` gives `c13`, and `256 + (269 >> 8) = 256 + 1 = 257` gives
`c257`. The measured label is `app_data_file:s0:c13,c257,c512,c768`. The formula holds.

Now look at the GMS row again. Its label is `privapp_data_file:s0:c512,c768` — **it carries no
per-app categories at all.** Write that down. It is the reason Step 8 works.

**Question 5.** Chrome's label carries `c196,c256`. Compute Chrome's app id from those two
categories and check it against `dumpsys package com.android.chrome | grep userId=`.

### Step 7 — The DAC reachability walk

The `storage-map.sh` output ends each root with a list of world-readable and world-writable files,
and for each one a line reading `DAC-reachable by another uid: yes` or
`no (blocked at <dir> mode <m>)`. That computation is the whole difference between a finding and a
false positive, and you should be able to do it by hand.

> **Mental Model**
> `open("/a/b/c")` is not one permission check. The kernel resolves the path one component at a
> time, and needs **execute** (`x`) on every directory along the way plus **read** on the final
> file. A mode-0644 file inside a mode-0700 directory is unreachable by anyone but its owner,
> regardless of how permissive the file itself looks. Scanners that report the file's mode without
> walking its ancestors are the reason "world-readable file" findings have a bad reputation.

Do the walk manually on the negative case first, because a negative that you have verified is worth
more than a positive you have not:

```bash
# adb shell as root
ls -ld /data/data/me.bmax.apatch
ls -ld /data/data/me.bmax.apatch/patch
ls -l  /data/data/me.bmax.apatch/patch/ramdisk.cpio
```

Measured: the package directory is `drwx------`, `patch/` is `drwx------`, and the file itself is
`-rw-r--r--`. The file is world-readable, and it is completely unreachable. Confirm:

```bash
# adb shell
cat /data/data/me.bmax.apatch/patch/ramdisk.cpio | head -c 16
```

```
# adb shell — measured
/system/bin/sh: cat: /data/data/me.bmax.apatch/patch/ramdisk.cpio: Permission denied
```

**Question 6.** A scanner reports that file as "sensitive data world-readable, High". Write the two
sentences you would send back to the person who filed it.

### Step 8 — The cross-app read (the climax)

Now the positive case. Walk the same three levels on a GMS shared preference:

```bash
# adb shell as root
ls -ld /data/data/com.google.android.gms
ls -ld /data/data/com.google.android.gms/shared_prefs
ls -l  /data/data/com.google.android.gms/shared_prefs/google_sdk_flags.xml
```

Measured:

| Component | Mode |
|---|---|
| `com.google.android.gms/` | `drwx--x--x` |
| `shared_prefs/` | `drwxrwx--x` |
| `google_sdk_flags.xml` | `-rw-rw-r--`, 978 bytes |

Every directory on the path grants `o+x`, and the file grants `o+r`. The DAC walk says reachable.
Now stop reasoning and measure — **as an unprivileged uid, with no `su`**:

```bash
# adb shell
cat /data/data/com.google.android.gms/shared_prefs/google_sdk_flags.xml | head -c 200
```

That succeeds as uid 2000.

Shell is a privileged uid by Android's standards, though, so it does not settle the question that
matters. The question that matters is whether an **ordinary third-party app with zero permissions**
can read it, because that is the adversary in any real report. On the reference device the answer
was measured directly, with the probe you will run in
[Lab 03](lab-03-scoped-storage-and-fuse.md):

```
# host — measured, from the probe's own report
/data/data/com.google.android.gms/shared_prefs/google_sdk_flags.xml
    canRead()=true   open+read: READ OK (64 bytes)
```

It succeeded. And the reason is the label you noted in Step 6: `privapp_data_file:s0:c512,c768`
carries **no per-app MCS categories**, so the category-domination rule that stops one
`untrusted_app` reading another's `app_data_file` has nothing to enforce here. DAC permits it and
MAC does not object.

**Question 7.** Before you look at the contents, write down what severity you would assign if the
file turned out to contain an OAuth refresh token. Then look at the contents and write the severity
you would actually assign. Justify the gap.

> **Warning**
> The contents are advertising and SDK feature flags. This is **low severity and high teaching
> value**, and it must not be written up as a vulnerability report against Google. What it
> demonstrates is a method: that DAC, MAC and content are three independent questions, that a file
> can pass the first two and still be worth nothing, and that you cannot know which case you are in
> without checking all three. Report the method, not the file.

### Step 9 — CE versus DE, and why the split exists

Both trees exist for GMS. Compare them:

```bash
# adb shell as root
ls -ld /data/user/0/com.google.android.gms
ls -ld /data/user_de/0/com.google.android.gms
du -sk /data/user/0/com.google.android.gms /data/user_de/0/com.google.android.gms
```

[09-Android-App-Internals §3.11](../../09-Android-App-Internals/README.md) covers the API surface —
`createDeviceProtectedStorageContext()`, `directBootAware`, and the migration helpers — and this lab
does not restage it. What this lab adds is the security consequence, stated once:

**Anything an app writes to DE storage is readable from the moment the kernel mounts `/data`, before
anybody enters a PIN.** A before-first-unlock forensic acquisition gets it. Every threat model that
began "the attacker has a locked phone" has to be rewritten for that data.

**Question 8.** Name a value that legitimately belongs in DE storage, and a value that never does.
What distinguishes them?

### Step 10 — Root 7: ask MediaStore, because the filesystem cannot answer

```bash
# adb shell
content query --uri content://media/external/file --projection _id:_data:owner_package_name
```

Measured rows on the reference device include:

```
# adb shell — measured rows
_data=/storage/emulated/0/Download/lsposed-1-9-2.apk, owner_package_name=com.android.chrome
_data=/storage/emulated/0/s1.png,                     owner_package_name=com.android.shell
```

`owner_package_name` is the only reliable attribution for a file in a shared collection. It is also,
in itself, a **privacy surface**: any reader of that column learns which app produced which file,
and "this handset downloaded that APK using Chrome" is frequently more sensitive than the APK.

**Question 9.** The `storage-map.sh --media` output for GMS was probably empty. Does that mean GMS
has written nothing into a shared collection? Give the two readings and say how you would tell them
apart.

### Step 11 — Write the classification

Produce the deliverable. For `com.google.android.gms`, a table with one row per root, and four
columns: **exists**, **who can reach it (DAC)**, **who can reach it (MAC)**, **what it would take to
turn a file here into a finding**. Then the severity paragraph for the file from Step 8.

If your severity paragraph contains the phrase "world-readable" without also naming a reachable
adversary and a consequence, rewrite it.

---

## Hints

<details>
<summary>Hint 1 — the script prints MISSING for everything</summary>

Check the privilege line at the top of the report. If it says `shell uid 2000`, the `su` probe
failed and every `/data` root is being read by a uid that cannot read them.

```bash
# host
adb shell "su -c 'id -u'"
```

That must print `0`. If Magisk is installed but this fails, the shell has not been granted root —
approve the prompt in the Magisk app, or check the superuser access setting is "Apps and ADB".

Note the quoting: the whole `su -c '...'` string is **one** argument. `adb shell` joins its arguments
with spaces and hands the result to the device's `sh`, so `adb shell su -c "ls -l /data/data"` <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this note teaches -->
arrives as `su -c ls -l /data/data` and `su` runs only `ls`.
</details>

<details>
<summary>Hint 2 — the package name is wrong</summary>

```bash
# host
adb shell pm list packages | grep -i chrome
adb shell pm list packages | grep -i gms
```

`storage-map.sh` warns when `pm` does not list the package, because otherwise every root reads as
missing and the report looks like a hardened app rather than a typo.
</details>

<details>
<summary>Hint 3 — `find` or `stat` fails with a strange path on Windows</summary>

Git Bash is MSYS2, and MSYS2 rewrites any argument that looks like a Unix absolute path into a
Windows one before the program ever sees it. A `/data/local/tmp/x` in your argv arrives as
`C:/Program Files/Git/data/local/tmp/x`.

```bash
# host
MSYS_NO_PATHCONV=1 ./scripts/storage-map.sh com.android.chrome
```

[`../scripts/storage-diff.py`](../scripts/storage-diff.py) detects this specific corruption and
explains it rather than failing obscurely; `storage-map.sh` does not, so set the variable.
</details>

<details>
<summary>Hint 4 — decoding an MCS category back to an app id</summary>

You have `cA` (low) and `cB` (high), with `B >= 256`. Then:

```
# host — the derivation, not a command
appId = ((B - 256) << 8) | A
```

For Chrome's `c196,c256`: `((256 - 256) << 8) | 196 = 196`. Check it with
`dumpsys package com.android.chrome | grep userId=`. Categories `c512` and `c768` appear on every
app and encode the *user*, not the app — they are not part of this calculation.
</details>

<details>
<summary>Hint 5 — how to tell DAC-refused from MAC-refused</summary>

Both produce `Permission denied` / `EACCES` at the API. The difference is visible in the audit log:

```bash
# adb shell as root
dmesg | grep -i avc | tail -20
```

An SELinux denial emits an `avc: denied` record naming the source context, the target context and
the permission. A DAC refusal emits nothing. If your read failed and `dmesg` is silent, the mode
bits or a parent directory refused you, not the policy.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** Shell without `su` reads roots 3, 4 and 5 (the external ones, courtesy of `ext_data_rw` 1078
and `ext_obb_rw` 1079) and root 7 through MediaStore. It is refused roots 1, 2 and 6, which live
under `/data` and are owned by the app uid with mode `0700`. Root 8 is partly reachable — shell is
in group `log` (1007), so `adb logcat` works — which is worth noticing, because it means the logcat
half of root 8 is available to every host the user has ever authorised over ADB.

**2.** (1) CE — the app's uid plus SELinux MCS categories, and FBE until first unlock. (2) DE — the
app's uid plus MCS, but **no** FBE protection before unlock. (3) External app-specific — the FUSE
daemon's scoped-storage rules; not the uid sandbox. Reachable by `MANAGE_EXTERNAL_STORAGE` holders
and, on Android 11, by `adb shell`. (4) External media — the same, minus the `Android/data`
restriction, plus MediaStore indexing, so any app with a media read permission sees the contents.
(5) OBB — as (3). (6) ART profile — root-owned under `/data/misc`, not app-writable, readable by
root and the runtime. (7) Shared collections — **nothing** app-specific protects them; access is
mediated by MediaStore and permissions, and the file survives the app's uninstall. (8) System-held
copies — nothing the app controls at all; logcat needs `READ_LOGS` or root, task snapshots are
system-owned, and the backup transport is whatever the user's account is.

**3.** `readlink` returns nothing and exits non-zero on a bind mount, so any script branching on
`readlink` behaves differently. `find / -xdev` treats a bind mount as a mount boundary and a symlink
as nothing at all, so a filesystem walk covers different ground. The wrong security conclusion:
"since `/data/data` is just a symlink to `/data/user/0`, per-user separation is cosmetic". It is
not — each user's directory is a separate FBE key domain, and the bind mount exists precisely so
that a process sees only its own user's tree.

**4.** Because the FUSE daemon reports a synthetic owner for everything it serves — `fsuid=1023`
(`media_rw`) on the sdcardfs mounts, `user_id=0` on the FUSE one — rather than the uid that issued
the `write`. Ownership there is an artefact of the mount, not a record of authorship. MediaStore's
`owner_package_name` column answers it, because MediaProvider records the calling package at insert
time.

**5.** `((256 - 256) << 8) | 196 = 196`. Chrome's app id is 196, so its uid on user 0 is
`10000 + 196 = 10196`.

**6.** "The file is mode 0644, but both `/data/data/me.bmax.apatch` and its `patch/` subdirectory are
mode 0700, so no uid other than the owner can resolve a path to it — `cat` as uid 2000 returns
Permission denied, which I have confirmed on the device. Path resolution requires `x` on every
ancestor directory, so the file's own mode is not reachable and this is a false positive."

**7.** If it held an OAuth refresh token the honest severity would be High: a token readable by any
installed app with no permissions is a full account-takeover primitive against every user of that
device, and the fix (mode bits, or moving it) is trivial, which removes the usual mitigating
argument. What it actually holds is advertising and SDK feature flags — configuration values with no
authentication value and no personal data. That is **Informational**, and the write-up should say so
plainly. The gap between the two is the entire reason you read the file instead of grepping for its
mode: reachability decides whether anyone *can* read it, and content decides whether anyone *cares*.

**8.** DE storage legitimately holds anything a Direct Boot component needs to be useful
before unlock and that is not itself secret: an alarm's scheduled time, whether a credential exists,
a non-sensitive account label, a cached list of notification channels. It must never hold anything
whose disclosure is the harm — tokens, keys, message bodies, PII. The distinguishing question is
"if a forensic tool imaged this handset while it was locked, would this value hurt the user?" If
yes, it does not belong in DE storage regardless of how convenient it is.

**9.** Two readings. Either GMS has genuinely inserted no rows into shared collections, or the query
was answered by a provider that did not return the rows to *this* caller — `adb shell` sees a lot,
but not everything, and a `--where` clause on `owner_package_name` returns nothing for rows whose
owner was never recorded (files placed by a legacy-storage app, or by a scan of a file nobody
claimed). Tell them apart by running the query with no `--where` and grepping the full output, and
by checking whether MediaProvider actually answered: the literal text `No result found.` is
MediaProvider replying, whereas a blank line means the command produced nothing at all.

</details>

---

## Success criteria

- [ ] You enumerated all **eight roots** for one package on a real device, and can name the API that returns each of the six package-derived ones
- [ ] You proved from **inode numbers and `/proc/mounts`** that `/data/data` and `/data/user/0` are one directory reached by a bind mount, not a symlink
- [ ] You identified the **FUSE and sdcardfs split** under `/storage/emulated` and can say which mount serves `Android/data`
- [ ] You read a real **SELinux label** and decoded its MCS categories back to an app id with `c[appId & 0xff]` and `c[256 + (appId >> 8)]`
- [ ] You noticed that `privapp_data_file` on this device carries **no per-app categories**, and can say what that permits
- [ ] You performed a **DAC reachability walk** by hand and produced one verified negative — a 0644 file no other uid can open
- [ ] You produced one verified **positive cross-app read** and confirmed it as an unprivileged uid rather than as root
- [ ] You argued that file's **severity honestly**, including the possibility that the correct answer is "not a finding"
- [ ] You can state, in one sentence, why "the file is world-readable" is **not by itself a finding**
