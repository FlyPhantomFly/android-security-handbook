# Lab 03 — Scoped Storage and FUSE, Measured

**Difficulty:** Advanced
**Time:** 150 minutes
**Prerequisites:** [Lab 01](lab-01-map-the-eight-roots.md),
[Lab 02](lab-02-filesystem-diff-across-a-session.md),
[Chapter 33 §3.6–3.8](../README.md),
[21-App-Sandbox §3.11](../../21-App-Sandbox/README.md),
[23-Permissions](../../23-Permissions/README.md), a rooted API 29+ device, Frida

---

## Objective

Measure what scoped storage **actually enforces on the device in your hand**, rather than reading
what it is documented to do on a device somebody else had. You will take the same set of questions
to three different vantage points — `adb shell` (uid 2000), an ordinary third-party app with no
permissions (uid 10314 on the reference device), and root — and record where the three answers
disagree.

The deliverable is a written argument, one paragraph per case, titled *what scoped storage is
actually worth*, in which every claim names **the specific adversary it holds against**. A sentence
about scoped storage that does not name an adversary is not a security claim.

## Why this matters

Scoped storage is the most misdescribed mechanism in modern Android. Three claims circulate, and all
three are wrong in ways that change findings:

- *"Apps can no longer read external storage."* They can. An app writes to and reads its own
  `Android/data/<pkg>` with no permission at all, exactly as before.
- *"`Android/data` is now private."* It is not private from `adb shell`, which on Android 11 holds
  `ext_data_rw` (gid 1078), and it is not private from a `MANAGE_EXTERNAL_STORAGE` holder, and on
  many OEM builds it is not private from the vendor's own file manager.
- *"An app can no longer tell what other apps are installed by looking at storage."* It can. The
  measurement below shows an app that cannot **enumerate** `Android/data` and cannot **read** any
  entry in it, but can still confirm that a specific package's directory **exists**.

[21-App-Sandbox §3.11](../../21-App-Sandbox/README.md) covers what scoped storage *is* — the API
surface, the volume model, the permission changes — and this lab does not restage it. What this lab
adds is the measurement: which of the mechanism's edges are sharp, which are soft, and which are
enforced somewhere other than where people look for them.

> **Mental Model**
> Scoped storage is not one rule. It is at least four independent mechanisms wearing one name: a
> **FUSE daemon** that refuses some `open` calls, a **permission** that gates the shared collections,
> a **content provider** (MediaStore) that mediates access and records ownership, and a **package
> visibility** rule that decides which of the above you can even see the results of. When a
> measurement surprises you, the first question is always: *which of the four just answered me?*

---

## Setup

You need the leaky-vault app from [Lab 02](lab-02-filesystem-diff-across-a-session.md) installed,
because it carries [`StorageProbe`](../examples/leaky-vault/StorageProbe.java) — a measurement
instrument, not a vulnerability. Everything the probe prints is an **observation phrased in terms of
what was observed**, never in terms of what should have happened. A probe that fails to fail is the
finding.

```bash
# host
cd Android-Security-Handbook/33-Storage
./examples/build.sh --install
adb shell dumpsys package com.pentest.ch33.vault | grep -m1 userId=
```

On the reference device that reports `userId=10314`, and `targetSdkVersion` is 30. Record both; the
target SDK is half of the API 29/30 hinge you are about to measure.

The reference measurements throughout were taken on a Redmi `M2101K6P`, Android 11 / API 30, MIUI
12.5, rooted with Magisk, SELinux Enforcing, `/data` on f2fs with file-based encryption. Your device
will differ, and reproducing the *method* matters more than reproducing the *numbers*.

---

## Steps

### Step 1 — Fix the three vantage points before measuring anything

Every result in this lab is meaningless without knowing who asked.

```bash
# adb shell
id
```

```
# adb shell — measured
uid=2000(shell) gid=2000(shell) groups=1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),...
```

| Vantage point | uid | Relevant privileges |
|---|---|---|
| `adb shell` | 2000 | `sdcard_rw` 1015, `sdcard_r` 1028, **`ext_data_rw` 1078**, `ext_obb_rw` 1079, `log` 1007 |
| The probe app | 10314 | none — no storage permission is declared in its manifest |
| root via `su` | 0 | everything, subject to SELinux |

> **Warning**
> `adb shell` is **not** a proxy for "an app on the device". It is a privileged, platform-signed
> vantage point that Android deliberately gives more storage reach than any third-party app. Testing
> from `adb shell` and reporting the result as what an attacking app can do is the single most common
> methodological error in scoped-storage assessments, and it inflates severities in both directions.

### Step 2 — The API 29/30 hinge

```bash
# host
adb shell "am start -n com.pentest.ch33.vault/.VaultActivity --es action probe"
adb logcat -d -s CH33Probe:V | head -60
```

The `scoped storage state` block reports:

```
# host — measured
  targetSdkVersion               30
  isExternalStorageLegacy()      false
  getExternalStorageState()      mounted
```

> **Definition — `isExternalStorageLegacy()`**
> A static call on `android.os.Environment` that answers a single question: *is this process still
> seeing the pre-Android-10 filesystem view of external storage?* `true` means the app has the legacy
> view — broad file access with the storage permission. `false` means scoped storage is in force for
> this app.

The value is not a property of the device. It is a property of **this app on this device**, decided
by an interaction that is genuinely confusing:

| App's `targetSdkVersion` | Device API | `requestLegacyExternalStorage` | Result |
|---|---|---|---|
| 28 or below | 29 | ignored | legacy view (implicit) |
| 29 | 29 or 30 | `true` | legacy view — the opt-out is **honoured** |
| 29 | 29 or 30 | absent/`false` | scoped |
| **30 or above** | 30+ | **ignored entirely** | **scoped, no opt-out exists** |

The opt-out was honoured for API 29 targets only. From target 30 the manifest flag has no effect at
all, which is why the probe prints the value rather than reasoning about it — the platform will just
tell you, and asking beats deducing.

**Question 1.** An app on your device targets 29 and sets `requestLegacyExternalStorage="true"`. The
user then updates the app to a version targeting 30. What is `isExternalStorageLegacy()` immediately
after that update, and does a factory-fresh install of the same APK give the same answer?

### Step 3 — The three-way asymmetry (the core measurement)

Ask one question — *can you list `/sdcard/Android/data`?* — from all three vantage points.

**From `adb shell` (uid 2000):**

```bash
# adb shell
ls /sdcard/Android/data | wc -l
```

```
# adb shell — measured
111
```

**From the app (uid 10314), in the probe's output:**

```
# host — measured
  listing /storage/emulated/0/Android/data ...
  RESULT: list() returned null -- the directory is not enumerable
          by this app. This is the scoped-storage behaviour.
```

**And yet, in the very same block:**

```
# host — measured
  com.android.chrome/files                   exists=true  read=false list=null
  com.google.android.gms/files               exists=true  read=false list=null
  com.android.vending/files                  exists=true  read=false list=null
```

Sit with that for a moment. The app **cannot enumerate** the directory. It **cannot read** any entry
in it. And it **can still confirm that a named package's external data directory exists.**

Existence leaks. Contents do not.

> **Pentester's Note**
> That is a package-detection primitive that survives the `QUERY_ALL_PACKAGES` restrictions
> introduced in the same release. If an app can test `exists()` on
> `Android/data/<pkg>/files` for a list of candidate packages, it can build an installed-app
> inventory — the exact profiling signal the package visibility rules were introduced to stop —
> without holding any permission and without appearing in any manifest audit. Whether this is
> currently blocked depends on the device and the patch level, which is precisely why you measure it
> on the target rather than citing a release note.

**Question 2.** Why does `exists()` return true when `list()` returns null? Reason about which layer
answers each call, and what information each layer is willing to give up.

### Step 4 — The `exists()` trap in the other direction

Now the same question about another app's *private* directory:

```
# host — measured
  /data/data/com.android.chrome              exists=false read=false
```

The directory does exist — you listed it as root in
[Lab 01](lab-01-map-the-eight-roots.md). What the app measured is not absence; it is refusal.

> **Under the Hood**
> `File.exists()` is implemented as a `stat(2)` on the path, returning `true` if the syscall
> succeeds. `stat(2)` on a path whose parent directory the caller cannot traverse fails with
> `EACCES` — permission denied — and `File.exists()` reports any failure as `false`. The Java API
> has **no way** to distinguish *"no such file"* from *"you are not allowed to look"*. Every
> conclusion of the form "the directory is not there, so the app does not use it" that was drawn
> from `exists()` is unsound.

Confirm the distinction yourself, from a vantage point that can see both answers:

```bash
# adb shell
ls -d /data/data/com.android.chrome ; echo "exit=$?"
```

```
# adb shell — measured
ls: /data/data/com.android.chrome: Permission denied
exit=1
```

```bash
# adb shell as root
ls -d /data/data/com.android.chrome ; echo "exit=$?"
```

```
# adb shell as root — measured
/data/data/com.android.chrome
exit=0
```

**Question 3.** Write the one-line shell test that distinguishes ENOENT from EACCES from a vantage
point that lacks root. (Hint: you cannot, for a path under a directory you cannot traverse — and
saying so precisely is the answer.)

### Step 5 — Writing to the shared root

The probe attempts a plain `FileOutputStream` on `/storage/emulated/0/ch33-probe-write.txt`, from an
app that declares **no storage permission at all**:

```
# host — measured
  WRITE to the shared root DENIED: FileNotFoundException --
      /storage/emulated/0/ch33-probe-write.txt: open failed: EPERM (Operation not permitted)
```

Note the errno: **`EPERM`, not `EACCES`.** That is a deliberate signal. `EACCES` is what a
conventional permission failure produces. `EPERM` here is the FUSE daemon refusing the operation on
policy grounds — the restriction is implemented in the process servicing the syscall, not in a
permission check the app could route around by using a raw `File` API instead of a framework helper.

That is the single most important structural fact about scoped storage: **it is enforced below the
API**, so there is no "just use `java.io.File` instead" bypass. Contrast it with the pre-Android-10
model, where `WRITE_EXTERNAL_STORAGE` mapped to membership of gid 1015 and the kernel's ordinary DAC
did the enforcing.

**Question 4.** The app can still write freely to `/storage/emulated/0/Android/data/<its own pkg>/`
with no permission. Both paths are on the same volume, served by the same stack. What distinguishes
them, and where is that distinction encoded?

### Step 6 — The mount split, and why `/sdcard` ownership is uninformative

```bash
# adb shell as root
grep -E 'emulated|sdcardfs|fuse' /proc/mounts
```

Measured on the reference device:

```
# adb shell as root — measured
/dev/fuse /storage/emulated fuse rw,lazytime,nosuid,nodev,noexec,noatime,user_id=0,group_id=0,allow_other
/data/media /storage/emulated/0/Android/data sdcardfs rw,nosuid,nodev,noexec,noatime,fsuid=1023,fsgid=1023,gid=1015,multiuser,mask=6,derive_gid,default_normal,unshared_obb
```

plus `/mnt/pass_through/0/emulated`, `/mnt/runtime/{default,read,write,full}/emulated` (all
`sdcardfs`), and `/mnt/user/0/emulated` (FUSE). And:

```bash
# adb shell
ls -ld /sdcard
```

```
# adb shell — measured
lrwxrwxrwx 1 root root 21 ... /sdcard -> /storage/self/primary
```

So the shared root is served by the FUSE daemon, while `Android/data` and `Android/obb` are
**bind-mounted sdcardfs underneath it** — a performance shortcut, because routing every app's own
external I/O through userspace FUSE is expensive and an app's own directory needs none of the
per-file policy that FUSE exists to apply.

The security consequence is one you will use constantly:

```bash
# adb shell
ls -l /sdcard/Download/ | head -5
```

Every file is owned by something like `root:everybody` or `media_rw:media_rw`, because the mount
options say so (`fsuid=1023`, `fsgid=1023`, `user_id=0`). **The owner shown is an artefact of the
mount, not a record of who wrote the bytes.** You cannot attribute a file on shared storage by
looking at its owner. Ever.

> **Definition — sdcardfs**
> A kernel-side stacking filesystem that presents `/data/media` under a synthetic ownership and
> permission model, deriving each file's apparent uid/gid from mount options rather than from the
> writer. It exists because emulated external storage must present FAT-like semantics (no real
> ownership, no real modes) to apps that expect a removable card. Android 11 moved general external
> access to FUSE for policy reasons but kept sdcardfs bind-mounted for the app-specific directories,
> which is why you see both on one device.

**Question 5.** If ownership cannot attribute a file on `/sdcard`, what can? Give the mechanism and
one reason it is *also* a privacy problem.

### Step 7 — MediaStore from two sides

**From the app, with no permission** (probe output):

```
# host — measured
  rows visible to this app: 0
```

**From `adb shell`:**

```bash
# adb shell
content query --uri content://media/external/file --projection _id:_data:owner_package_name
```

Measured rows include:

```
# adb shell — measured rows
_data=/storage/emulated/0/Download/lsposed-1-9-2.apk, owner_package_name=com.android.chrome
_data=/storage/emulated/0/s1.png,                     owner_package_name=com.android.shell
```

Two things are happening at once and it is worth separating them.

First, **MediaStore is doing its job**: an app with no media permission sees only rows it owns, and
this app owns none, so it gets zero rows rather than a `SecurityException`.an empty
cursor and a refusal are different outcomes with the same practical effect and very different
diagnostic meaning; the probe reports which one it got.

Second, `owner_package_name` is **attribution and a privacy surface in one column**. It is the only
reliable way to say which app created `/sdcard/Download/x.pdf` — the filesystem cannot, as Step 6
established — and it simultaneously tells any reader with media permissions *which app downloaded
which file*. On many handsets, knowing that a particular app produced a particular file is more
sensitive than the file's contents.

Now look at `IS_PENDING`:

```bash
# adb shell
content query --uri content://media/external/file --projection _id:_display_name:is_pending --where "is_pending=1"
```

> **Definition — `IS_PENDING`**
> A MediaStore column an app sets to `1` when it inserts a row before writing the file's bytes, and
> clears to `0` when the write is complete. While it is `1`, MediaStore hides the row from every
> other app. It exists to close the window in which a half-written file is visible and readable by
> anyone with media permissions.
> [`../examples/leaky-vault/ExportActivity.java`](../examples/leaky-vault/ExportActivity.java)
> uses it correctly, and comments on what skipping it would cost — for an export containing a token,
> a real if narrow exposure window.

Drive the export and watch both paths:

```bash
# host
adb shell "am start -n com.pentest.ch33.vault/.ExportActivity"
adb shell "content query --uri content://media/external/file --projection _display_name:owner_package_name --where \"_display_name='ch33-vault-export.txt'\""
```

`ExportActivity` deliberately implements **two** routes: the sanctioned MediaStore insert, and the
pre-scoped-storage `Environment.getExternalStoragePublicDirectory()` plus raw `File`. The legacy
branch is kept so that you see it fail rather than read that it would:

```
# host — measured, from ExportActivity's on-screen output
legacy path FAILED (expected on API 30+): java.io.FileNotFoundException: ... EPERM (Operation not permitted)
```

**Question 6.** The modern path needed **no permission at all**. Explain why writing to a shared
collection through MediaStore requires no permission while writing to the same directory through
`File` is refused.

### Step 8 — `MANAGE_EXTERNAL_STORAGE`, and what it really grants

```bash
# adb shell
pm list permissions -f | grep -A5 MANAGE_EXTERNAL_STORAGE
appops get com.pentest.ch33.vault MANAGE_EXTERNAL_STORAGE
```

Measured, the permission's protection level is `signature|appop|preinstalled`, and the associated
supplementary gid is **1077**.

Unpack the three protection flags, because each one is a separate barrier and people quote only the
first:

| Flag | Meaning |
|---|---|
| `signature` | Granted automatically to an app signed with the platform key |
| `appop` | Even when granted, the actual capability is gated by an **app op** the user toggles in Settings, not by the permission alone |
| `preinstalled` | Granted to apps shipped in the system image |

An ordinary Play Store app therefore cannot obtain this by declaring it; it must be declared **and**
the user must enable "All files access" in Settings **and** Google Play policy must have permitted
its distribution. When it is fully granted, the holder gets a legacy-like view: broad read/write to
the shared volume including other apps' `Android/data`, subject to a short list of exceptions.

> **Pentester's Note**
> When you find an app holding `MANAGE_EXTERNAL_STORAGE`, the finding is almost never "it holds a
> dangerous permission". It is either (a) the app does not need it and a narrower API would do — a
> real, fixable finding with a code-level remediation — or (b) the app genuinely is a file manager
> and the finding is about what it does with the reach, not that it has it. Write the one you can
> demonstrate.

**Question 7.** Your target app holds `MANAGE_EXTERNAL_STORAGE` and stores its own credentials in
`Android/data/<pkg>/files/`. Has the permission made that storage decision worse? Argue both ways
and then decide.

### Step 9 — Watch the refusal happen

The probe tells you the outcome. Frida tells you the mechanism. Attach and watch the actual syscalls
and their errnos, so that "FUSE refused it" stops being something you were told.

```bash
# host
frida -U -f com.pentest.ch33.vault -l scripts/storage-trace.js
```

`storage-trace.js` already hooks libc `open`/`openat` for write flags. For this lab you want failures
too, including read-only ones, so run this small script alongside it:

```javascript
// frida — watch openat() outcomes on external storage
Interceptor.attach(Module.findExportByName('libc.so', 'openat'), {
    onEnter: function (args) {
        this.path = '';
        try { this.path = Memory.readUtf8String(args[1]); } catch (e) {}
        this.interesting = this.path &&
            (this.path.indexOf('/storage/') === 0 || this.path.indexOf('/sdcard/') === 0);
    },
    onLeave: function (retval) {
        if (!this.interesting) return;
        var fd = retval.toInt32();
        if (fd >= 0) {
            console.log('[ok   ] fd=' + fd + '  ' + this.path);
        } else {
            // Frida exposes the thread's errno after a failed syscall.
            console.log('[FAIL ] errno=' + this.lastError + '  ' + this.path);
        }
    }
});
```

Then, from a second terminal:

```bash
# host — second terminal
adb shell "am start -n com.pentest.ch33.vault/.VaultActivity --es action probe"
```

You are looking for two distinct outcomes on two paths: a success on the app's own
`Android/data/<pkg>/files/...`, and a failure with errno 1 (`EPERM`) on `/storage/emulated/0/...`.
Same volume, same process, same API, two answers — decided by the daemon, per path.

Compare with the `strace`-style view from outside, if your device has `strace`:

```bash
# adb shell as root
strace -f -e trace=openat -p $(pidof com.pentest.ch33.vault) 2>&1 | grep -i storage
```

**Question 8.** The Frida hook sees the app-side `openat`. Name one write to shared storage that this
hook will **never** see, and say which process performs it.

### Step 10 — Write the argument

Produce the deliverable: *what scoped storage is actually worth*, one paragraph per case. Each
paragraph names the adversary and states what the mechanism does and does not do against that
specific adversary.

Cover at least these five:

1. **A malicious app with no permissions.** What has scoped storage taken away from it? What has it
   left — including the existence-probing result from Step 3?
2. **A malicious app holding `MANAGE_EXTERNAL_STORAGE`.** What is the practical difference from the
   pre-Android-10 world?
3. **A user with a USB cable and `adb`.** Remember gid 1078, and remember that this vantage point
   requires the user to authorise the host.
4. **Root, or an OEM file manager on a vendor build.** Be honest about how much of this mechanism
   applies here at all.
5. **A forensic acquisition of the powered-off handset.** Scoped storage is irrelevant here; say why,
   and say what *is* relevant.

Finish with one sentence: *the single thing scoped storage does that nothing else on the platform
does.* If you cannot write that sentence, you have not finished the lab.

---

## Hints

<details>
<summary>Hint 1 — the probe produces no output</summary>

```bash
# host
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"
```

On MIUI, while the keyguard is up, app-originated activity starts are refused and `am start` appears
to succeed while doing nothing. Unlock the screen and re-run.

If the screen is unlocked and there is still nothing, check the logcat tag and the buffer:

```bash
# host
adb logcat -d -s CH33Probe:V
adb shell "su -c 'cat /data/user/0/com.pentest.ch33.vault/files/probe.txt'"
```

The probe writes the same report to `files/probe.txt` (4402 bytes on the reference device) precisely
so that a logcat problem does not cost you the measurement.
</details>

<details>
<summary>Hint 2 — `content query` returns nothing and you cannot tell why</summary>

The literal text `No result found.` is MediaProvider answering with an empty cursor. A completely
blank line means the command produced no output at all, which usually means a syntax error in the
`--where` clause or a quoting problem. Test with a query that must return rows:

```bash
# adb shell
content query --uri content://media/external/file --projection _id | head -3
```
</details>

<details>
<summary>Hint 3 — you want to compare an API 29 target</summary>

You do not need a second app. Rebuild the same sources with a different `--target-sdk-version` and a
different package name, then compare `isExternalStorageLegacy()`:

```bash
# host
grep -n 'target-sdk-version' examples/build.sh
```

Change the value in your own copy of the build invocation, add
`android:requestLegacyExternalStorage="true"` to your copy of the manifest, and install alongside.
Two APKs differing only in target SDK is the cleanest possible demonstration of the hinge.
</details>

<details>
<summary>Hint 4 — `errno` in the Frida hook is always 0</summary>

`this.lastError` is populated on the `onLeave` of a failing syscall on most builds, but it is not
universally reliable across Frida versions and ABIs. The portable fallback is to read the negative
return value directly, since the kernel returns `-errno` and libc translates it:

```javascript
// frida — portable-ish errno
var r = retval.toInt32();
console.log(r < 0 ? 'FAIL rc=' + r : 'ok fd=' + r);
```

If you need the exact errno and this is fighting you, get it from the Java side instead: the
`FileNotFoundException` message on Android carries `open failed: EPERM (Operation not permitted)`
verbatim, which is where the probe's own measurement came from.
</details>

<details>
<summary>Hint 5 — `strace` is not on the device</summary>

Most stock builds do not ship it, and neither does MIUI. Options, in order of effort: use the Frida
hook above (works everywhere Frida works); push a static `strace` binary to `/data/local/tmp` and run
it as root; or accept the Java-level evidence, which for this lab is sufficient — the exception
message names the errno.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** Immediately after the update, `isExternalStorageLegacy()` is still `true` for the already
installed app on some releases: the platform preserves the legacy view across an *upgrade* so that an
app updating to target 30 does not lose access to files it already wrote, until the app is
reinstalled. A factory-fresh install of the same target-30 APK gets `false`. This is why two devices
running the same OS and the same app version can behave differently, why the probe prints the value
instead of computing it, and why "we tested it and it worked" is not evidence about a user who
installed the app cleanly.

**2.** Different layers answer. `list()` on `Android/data` is a directory enumeration, which the FUSE
daemon refuses outright for an app that does not hold `MANAGE_EXTERNAL_STORAGE` — the whole point of
the restriction is to stop an app inventorying its neighbours. `exists()` is a `stat(2)` on a
*specific* path, and the daemon (and, for the bind-mounted sdcardfs region, the kernel's ordinary
path resolution) answers it because the path's parent components are traversable. The information
released is different in kind: enumeration hands over the full list of installed packages that use
external storage, while `stat` confirms one guess at a time. The platform judged the second cheap;
whether it is depends on how many guesses an attacker is willing to make, and the answer is "all of
them, from a wordlist".

**3.** You cannot, and the precise reason is the answer: `stat(2)` fails with `EACCES` before it ever
reaches the question of whether the final component exists, so no user-space call from that vantage
point can separate the two cases. In Java the situation is worse, because `File.exists()` collapses
every failure to `false` and discards the errno. To distinguish them you need either a vantage point
that can traverse the parent (root, or the owning uid), or a side channel — timing, or an API that
surfaces the errno, such as catching the `FileNotFoundException` from an actual `open` and reading
its message.

**4.** The app's own `Android/data/<pkg>` is *app-specific external storage*. The platform grants
every app unconditional access to its own directory there — that is the whole design, and it is why
`getExternalFilesDir()` has needed no permission since API 19. The shared root is not app-specific,
so writes to it are policy decisions. The distinction is encoded in the FUSE daemon's path handling
(and in the sdcardfs bind mount, which is what serves the app-specific region on this device), keyed
on the package name embedded in the path. Note the consequence for a manifest audit: an app can write
outside its uid-protected sandbox while declaring **no storage permission at all**, which is exactly
what LEAK-2 in [`../examples/leaky-vault/Vault.java`](../examples/leaky-vault/Vault.java) does.

**5.** MediaStore's `owner_package_name` column, populated by MediaProvider from the calling package
at insert time. It is also a privacy problem because it is readable by anything with a media read
permission, so an app that legitimately reads the user's photos also learns the full inventory of
which app produced which file — a behavioural profile of the user assembled from metadata the user
never considered sensitive, without a single additional permission.

**6.** Because the two routes cross a different boundary. Writing through MediaStore is an IPC call
to MediaProvider, which performs the write **in its own process, with its own privileges**, after
deciding whether to allow it. The app never touches the filesystem, so no permission is needed to
touch the filesystem. Writing through `File` is the app asking the kernel directly, and the FUSE
daemon servicing that mount refuses it with `EPERM`. This is the same delegation pattern as a
`ContentProvider` in general — see [27-ContentProviders](../../27-ContentProviders/README.md) — and
recognising it saves you from the common wrong conclusion that "the app has no storage permission,
so it cannot write to shared storage".

**7.** For: it does not change the file's mode bits or its path, so the storage decision is exactly as
bad as it was; the permission is about what *this* app can reach elsewhere, not about who can reach
*this* app's files. Against: it materially raises the population of software that can reach the
credential, because any other `MANAGE_EXTERNAL_STORAGE` holder on the device — the vendor file
manager, a backup app, a cleaner — can now read `Android/data/<pkg>/files/`, and the presence of one
such app on the device is close to certain. The defensible decision: the permission does not make
this app's storage worse, but it demonstrates on the same handset that the adversary class the
storage decision assumed away actually exists. File one finding for the credential location, and cite
the permission as evidence of reachability rather than as a finding of its own.

**8.** Anything MediaProvider performs on the app's behalf. When the app writes through
`ContentResolver.openOutputStream()`, the app-side call goes to a file descriptor the provider handed
back, and the real write into the shared collection is performed by **MediaProvider's process**. A
hook inside the app sees the app-side write and never sees what MediaProvider does with it. The same
applies to the system share sheet copying a URI, and to `system_server` writing a recents task
snapshot. This is the same class of blind spot as the one that hid LEAK-1 from the filesystem diff in
[Lab 02](lab-02-filesystem-diff-across-a-session.md): the instrument is attached to the wrong
process.

</details>

---

## Success criteria

- [ ] You measured `isExternalStorageLegacy()` on a real app and can state the **API 29 versus 30 hinge** without looking it up
- [ ] You demonstrated the **three-way asymmetry**: shell can list `Android/data`, an ordinary app cannot, and the app can still see that a named package's directory exists
- [ ] You can explain why `File.exists()` returning `false` for `/data/data/com.android.chrome` is **not evidence of absence**
- [ ] You observed the **`EPERM`** on writing to the shared root and can say which component refused it and why the errno differs from `EACCES`
- [ ] You read `/proc/mounts` and can describe the **FUSE and sdcardfs split**, including why `/sdcard` file ownership cannot attribute a writer
- [ ] You queried MediaStore from two vantage points and can explain `owner_package_name` as **both attribution and a privacy leak**
- [ ] You can state what `IS_PENDING` protects against, in terms of a concrete exposure window
- [ ] You looked up `MANAGE_EXTERNAL_STORAGE`'s **protection level** and can explain what `signature|appop|preinstalled` means barrier by barrier
- [ ] You wrote the *what scoped storage is actually worth* argument, **naming the adversary** in every one of the five cases
- [ ] You can state, in one sentence, the single thing scoped storage does that nothing else on the platform does
