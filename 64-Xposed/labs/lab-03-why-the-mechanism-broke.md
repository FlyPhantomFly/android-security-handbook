# Lab 03 — Why the mechanism broke

| | |
|---|---|
| **Difficulty** | Intermediate → Advanced |
| **Time** | 2 to 3 hours |
| **Needs classic Xposed?** | **No.** Demonstrating that you *cannot install it* is the lab |
| **Needs LSPosed?** | **No** |
| **Needs a device?** | **Yes.** An emulator is fine and in some ways better |
| **Needs root?** | For Parts 2 and 4. Parts 1, 3 and 5 work unrooted |
| **You come out with** | Direct evidence, on your own device, for each of the five forces in README §3.10 — and a demonstration that the install is *impossible* rather than merely inadvisable |

---

## Why this lab exists

"Classic Xposed is dead" is the sort of sentence people repeat without checking. This lab makes you
check it — not by trying to install the framework, which would damage your device, but by measuring
each precondition it required and showing that the precondition is gone.

The transferable skill is the one in README §5.2: **a client-side integrity check has an expiry date
and no expiry mechanism.** You are going to establish the expiry date of an entire framework, from
first principles, using nothing but a device and `adb`. Once you have done it for Xposed you can do
it for any check you find in an APK.

> **This lab deliberately contains no instructions for installing classic Xposed.** It required
> disabling Verified Boot, which [61-Fastboot](../../61-Fastboot/README.md) measured to be a
> deliberate corruption of the image's own AVB signature — not a supported option — and which makes a
> subsequently relocked device a brick. If you want managed-code hooking, use
> [63-LSPosed](../../63-LSPosed/README.md).

---

## Setup

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.release
```

Record all four. Every result below is gated on the API level, and the whole lab is about a
version-dependent claim.

**Note which device you are on**, because the two classes behave differently and both are
instructive:

| Device class | What you will see |
|---|---|
| A modern emulator or a current phone (API 29+) | Every precondition gone. Clean, decisive results |
| An old device (API 21 to 27) you own and can wipe | Some preconditions *present*. This is the more interesting run, and it lets you demonstrate why the framework worked rather than only why it does not |

---

## Part 1 — Force 1: the partition is not writable

### 1.1 Find out what `/system` actually is

```bash
# host
adb shell 'cat /proc/self/mounts' | grep -E ' / | /system '
```

On a current device, expect something like:

```
/dev/block/dm-5 / ext4 ro,seclabel,relatime 0 0
```

Three things to notice and write down:

1. **`ro`** — read-only.
2. **`dm-`** — a device-mapper device, not a raw partition. That is dm-verity in the path.
3. **There may be no separate `/system` line at all.** On modern images `/system` *is* the root
   mount. A script grepping for ` /system ` finds nothing and concludes the partition is missing,
   which is wrong. Grep for both.

### 1.2 Confirm verity is enforcing

```bash
# host
adb shell getprop ro.boot.veritymode
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.flash.locked
adb shell getprop ro.build.type
```

Expected on the chapter's AVD:

```
ro.boot.veritymode        = enforcing
ro.boot.verifiedbootstate =            <- EMPTY, not "orange"
ro.boot.flash.locked      =            <- EMPTY
ro.build.type             = userdebug
```

> **The empty string is not a null result, it is a finding.** Chapter 61 traced it on this same AVD:
> `/proc/bootconfig` carries `androidboot.veritymode` but **not** `androidboot.verifiedbootstate`, and
> a `ro.boot.X` property is empty exactly when `androidboot.X` is absent. The consequence is a real
> app bug: the widely-written check `!"orange".equals(state)` returns **`true`** here, so it passes on
> the least trustworthy platform it can meet.
>
> **Exercise:** write down why that is the *same failure shape* as `File.exists()` mapping `ENOENT`
> and `EACCES` both to `false`. (Answer at the end of Part 1.)

Check it yourself:

```bash
# host
adb shell 'cat /proc/bootconfig 2>/dev/null | grep -i androidboot' | sort
```

### 1.3 Try to write

Do this. It is safe, it will fail, and the failure is the point.

```bash
# host — unrooted
adb shell 'touch /system/ch64-test'
# expect: Read-only file system

# host — with root, if you have it. STILL SAFE: the remount is what fails.
adb shell 'su 0 mount -o rw,remount /system' ; echo "exit=$?"
adb shell 'su 0 touch /system/ch64-test' ; echo "exit=$?"
adb shell 'su 0 ls -l /system/ch64-test'
```

**If the file was created, delete it immediately** and confirm that your device has verity disabled or
is using a writable overlay — which is itself a finding worth recording about your test device.

```bash
# host — clean up if anything was created
adb shell 'su 0 rm -f /system/ch64-test'
adb shell 'su 0 ls /system/ch64-test'          # expect: No such file or directory
```

**Success criterion:** you can state, with evidence from your own device, whether the six files in
README §2.3 could be written. On any current device the answer is no, and the reason is `ro` plus
`veritymode=enforcing`, not a permission bit.

> **Answer to the 1.2 exercise.** Both are cases of **an absent value and a bad value producing the
> same output.** `File.exists()` returns `false` for "not there" and for "not allowed to look";
> `!"orange".equals(state)` returns `true` for "the state is good" and for "there is no state". In
> both, the code was written assuming the answer would always be one of the *expected* values, and the
> unexpected one lands on the safe-looking side. That is the single most common shape of a broken
> integrity check, and you will now recognise it everywhere.

---

## Part 2 — Force 2 and the binary itself

### 2.1 What is actually at that path

```bash
# host
adb shell 'ls -l /system/bin/app_process*'
```

Expected on the chapter's AVD:

```
lrwxr-xr-x 1 root shell    13 2025-01-23 23:03 /system/bin/app_process -> app_process64
-rwxr-xr-x 1 root shell 51616 2025-01-23 23:03 /system/bin/app_process64
ls: /system/bin/app_process32: No such file or directory
```

Record **your** size. Then answer:

| Question | Why it matters |
|---|---|
| Is `app_process` a symlink on your device? | `File.length()` on a symlink and on its target answer different questions |
| Is there an `app_process32`? | A 64-bit-only image has none, and a check that stats it gets `ENOENT` on a perfectly clean device |
| What is the size? | Compare with the chapter's 51,616. **They will not match** |

### 2.2 Demonstrate that no baseline exists

This is Force 2 made concrete. Collect the size from every device you can reach — an emulator at two
different API levels, a phone, a colleague's phone:

| Device | API | ABI | `app_process64` size |
|---|---|---|---|
| chapter's AVD | 35 | x86_64 | **51616** |
| yours | | | |
| another | | | |

**Success criterion:** you have at least two different sizes, and can therefore state that the
hard-coded baseline in README §5.4's vulnerable code produces a false positive on every device except
the developer's own.

> If you only have one device, you can still make the argument from the ABI: `app_process64` and
> `app_process32` are different binaries with different sizes on any image that ships both, so a
> single constant is already wrong for half the processes on that device.

### 2.3 Prove it is the real one

```bash
# host — is this binary from the platform, or was it replaced?
adb shell 'su 0 sha256sum /system/bin/app_process64' 2>/dev/null || \
  adb shell 'sha256sum /system/bin/app_process64'
```

Now answer the question that makes the check useless: **what do you compare that hash against?**

You need the manufacturer's factory image for this exact build. Note what that implies — the only
party who can meaningfully perform this check is one who has population data or the OEM image, which
is precisely why README §5.4's fix is "report the value, do not judge it".

---

## Part 3 — Force 3: the runtime layout is not tied to the OS version

You cannot easily measure `ArtMethod`'s field offsets without native code. You *can* measure the fact
that makes tabulating them impossible.

```bash
# host — is ART a Mainline module on this device, and at what version?
adb shell 'pm list packages --show-versioncode | grep -iE "art|runtime"'
adb shell 'ls -d /apex/com.android.art*'
adb shell 'cat /apex/com.android.art/apex_manifest.pb 2>/dev/null | strings | head'
adb shell getprop ro.build.version.sdk
```

**Success criterion:** you can point at an ART APEX whose version is **not** the platform version,
and state the consequence: two devices reporting the same `ro.build.version.release` can carry
different ART builds with different `ArtMethod` layouts, so a per-Android-version offset table is not
merely fragile — it is **not well-defined**.

That is why [`13-ART/scripts/artmethod-inspect.js`](../../13-ART/scripts/artmethod-inspect.js)
derives the offset at runtime, and why README §3.5's reason 2 was fatal in a way reason 1 was not.

---

## Part 4 — Force 4 and 5: what replaced it

### 4.1 The successor is present and the ancestor is not

```bash
# host
./scripts/xposed-artefact-probe.sh --serial <your-serial>
```

You did this in [Lab 01](lab-01-the-detection-surface.md). Read it again with a different question in
mind: **which rows are PRESENT?**

On a Magisk-rooted device the answer is `/data/adb/modules` — a directory holding modules that
achieve the same end without touching a partition. On an unrooted device nothing is present at all.

### 4.2 The systemless contrast, measured

```bash
# host — what does a systemless root actually do to the filesystem?
adb shell 'cat /proc/self/mountinfo' | grep -iE 'magisk|overlay|tmpfs' | head -10
```

If the device is Magisk-rooted you will see mounts whose source is literally `magisk`
— [63-LSPosed](../../63-LSPosed/README.md) measured three of them on the chapter's AVD, readable from
every vantage including an app uid, with no permissions at all.

**The comparison to write down:**

| | Classic Xposed | Magisk / Zygisk |
|---|---|---|
| Files written to a verified partition | **6** | **0** |
| Survives dm-verity | No | Yes |
| Survives an OTA | No | Reapplied |
| Needs a per-release binary port | Yes | No |
| Evidence on disk | Six files, plus a `dalvik-cache` regeneration | Mount entries in `/proc/self/mountinfo` |

That last row is the interesting inversion: **the systemless approach is harder to remove and easier
to see at runtime.** Classic Xposed was loud on disk and quiet in `mountinfo`; Magisk is the reverse.
Neither is "stealthier" in general — they are visible to different observers.

### 4.3 The `dalvik-cache` dating primitive, and why it is gone

Classic Xposed added a jar to the boot class path, which invalidated every AOT artefact on the device
and forced a full recompile. That left a **cluster of identical timestamps** — a genuinely good
forensic dating primitive (README §5.9).

```bash
# host — look for the modern equivalent
adb shell 'su 0 ls -la /data/misc/apexdata/com.android.art/dalvik-cache/*/ 2>/dev/null | head'
adb shell 'su 0 ls -la /data/dalvik-cache/*/ 2>/dev/null | head'
```

**Success criterion:** you can explain why a systemless framework does **not** produce that cluster,
and therefore why this dating primitive has no modern equivalent. (Because it does not change the
boot class path, so the BCP checksums recorded in the OAT key-value store still match — see
[13-ART §3.7](../../13-ART/README.md).)

---

## Part 5 — Write the expiry date

Now generalise. You have just established the expiry date of a framework. Do the same for a check.

Take any Xposed-detection check — from [`../examples/XposedDetector.java`](../examples/XposedDetector.java),
or from a real APK you scanned in [Lab 01](lab-01-the-detection-surface.md) — and fill in this form:

```
CHECK:      new File("/system/framework/XposedBridge.jar").exists()

PREMISE:    A framework is installed which writes that file to the system partition.

PRECONDITIONS OF THE PREMISE:
    1. /system is writable at install time      -> Part 1: FALSE since verity became mandatory
    2. A framework exists that writes it        -> only classic Xposed ever did; LSPosed never has
    3. The app can read the path                -> Part 1 / Lab 01: ENOENT from every vantage

EXPIRES WHEN:  any one of the three fails.

MEASURED:      <your device>, API <n>: all three fail. The check cannot return true.

CONSEQUENCE:   The control gated by this check is unenforced. Rate the CONTROL.
```

Do it for at least three checks. One of them should be a check that **still works** — the
`Class.forName("de.robv.android.xposed.XposedBridge")` one is the obvious candidate — so that you have
written the form for both outcomes and can see the difference.

**Success criterion:** for each check, you can name the precondition that failed and the device
measurement that shows it failing. A check with no identifiable premise is itself a finding: nobody
can maintain it.

---

## Success criteria

| # | Criterion | Check against |
|---|---|---|
| 1 | You recorded device model, API level and release before anything else | Setup |
| 2 | You showed `/` or `/system` mounted `ro` with verity enforcing, on your device | Part 1.1–1.2 |
| 3 | You attempted a write, it failed, and you cleaned up if it did not | Part 1.3 |
| 4 | You can explain why an empty `ro.boot.verifiedbootstate` and a `false` from `File.exists()` are the same class of bug | Part 1.2 exercise |
| 5 | You collected `app_process64` sizes from two or more devices and they differ | Part 2.2 |
| 6 | You located an ART APEX whose version is not the platform version | Part 3 |
| 7 | You produced the six-files-versus-zero-files comparison from your own device | Part 4.2 |
| 8 | You completed the expiry form for three checks, one of which still works | Part 5 |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| No ` /system ` line in `/proc/self/mounts` | On modern images `/system` **is** the root mount | Grep for ` / ` as well. This is not a missing partition |
| `ro.boot.verifiedbootstate` is empty | `androidboot.verifiedbootstate` is absent from `/proc/bootconfig` | Not an error. It is Part 1.2's finding |
| `mount -o rw,remount /system` appears to succeed | Verity is disabled, or you are on a writable overlay | Record it as a property of your test device, and delete anything you created |
| `su: invalid uid/gid '-c'` | The emulator's `su` takes `su 0 <cmd>` | Try both forms |
| `sha256sum` not found | Some images ship it as `toybox sha256sum` only | `adb shell 'toybox sha256sum <path>'` |
| No `/apex/com.android.art` | Pre-API-29 device. ART is not Mainline there | That is Part 3's answer for *your* device: the offsets *were* determined by the OS version, which is why tabulating them worked then |
| `/proc/self/mountinfo` shows no magisk mounts | The device is not Magisk-rooted | Part 4.2's contrast still works; your left column is just empty |

---

## Cleanup

```bash
# host
adb shell 'ls /system/ch64-test'        # must report No such file or directory
adb shell 'ls /data/local/tmp'          # confirm you left nothing
```

This lab writes nothing to the device by design. The only exception is the deliberate `touch` in Part
1.3, and the lab tells you to remove it in the same block.

---

## Where to go next

- [Lab 04 — CTF: The Ghost of `app_process`](lab-04-ctf-the-ghost-of-app-process.md) — an application
  built on the checks you have just expired.
- [61-Fastboot](../../61-Fastboot/README.md) — what `--disable-verity` actually does to an image, at
  byte level, and why "disable verity then relock" is a brick.
- [62-Magisk](../../62-Magisk/README.md) — the systemless answer, in full.
- [20-Security-Architecture](../../20-Security-Architecture/README.md) — the integrity model this lab
  measured the edges of.
