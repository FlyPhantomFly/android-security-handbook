# Lab 01 — Root a Device From Scratch

**Difficulty:** Beginner (in concepts) — **the only lab in this repository that can permanently
destroy hardware**
**Time:** 2–4 hours for the procedure. Budget a full day the first time, including recovery drills.
**Prerequisites:** [Chapter 62 §1](../README.md#1-introduction),
[§3.1](../README.md#31-the-boot-image-and-what-patching-actually-changes),
[§9.1](../README.md#91-simple--install-magisk-end-to-end),
[02-Linux-Basics](../../02-Linux-Basics/README.md),
[20-Security-Architecture](../../20-Security-Architecture/README.md),
[60-ADB](../../60-ADB/README.md), [61-Fastboot](../../61-Fastboot/README.md).
This lab is self-contained — everything it needs from 60 and 61 is repeated here — but read
[61-Fastboot §3.9](../../61-Fastboot/README.md#39-the-factory-reset-guarantee) and
[§3.11](../../61-Fastboot/README.md#311-fastboot-boot--the-run-without-flashing-primitive) first if
you have not: they are why the wipe in Step 2 is a security property rather than an inconvenience,
and why Step 6 tests in RAM before Step 7 writes anything.

---

## Read this before you plug anything in

This lab is not a tutorial you can skim. Two of its steps are irreversible, and one of them can leave
you holding a device that does not boot and cannot be recovered by any software you own.

> **Warning — what "irreversible" means here, concretely**
>
> 1. **Unlocking the bootloader erases every byte of user data on the device.** Not "resets the
>    launcher" — the userdata partition is wiped, and on modern devices the disk encryption key is
>    destroyed, so the old data is not recoverable even with forensic tooling. Photos, accounts,
>    two-factor authenticator seeds, WhatsApp history: gone. This is a deliberate security property,
>    not an inconvenience, and it exists precisely so that unlocking cannot be used as a data
>    extraction attack against a stolen phone.
> 2. **On some devices unlocking blows a one-time fuse.** Samsung's KNOX warranty bit is the
>    best-known example: once tripped, Samsung Pay, Secure Folder and several enterprise features
>    stop working permanently, and re-locking does not restore them. There is no software that undoes
>    a blown fuse, because it is not software.
> 3. **`fastboot flash` of the wrong image bricks the device.** Flashing a boot image built for a
>    different device, a different Android version, or the wrong slot produces, at best, a bootloop;
>    at worst, a device that will not enter fastboot mode again, which means no recovery path
>    without specialist hardware.
> 4. **Some devices cannot be unlocked at all.** Carrier-locked units in several markets ship with
>    the OEM-unlocking toggle permanently greyed out. There is no legitimate way past that, and this
>    lab ends there for that device.

> **Warning — whose device**
> Do this only on a device that is **yours**, that you bought for testing, that holds no personal
> accounts, and that you can afford to lose entirely. Never on a client device. Never on the phone
> you use for banking. Never on a device you borrowed. If the only Android device you have is your
> daily phone, **stop and read [If you cannot do this lab](#if-you-cannot-do-this-lab) at the
> bottom** — there is a real alternative that teaches most of chapters 62's material, and it is a
> better choice than bricking your phone.

Nobody in this repository assumes you have a spare Pixel in a drawer. Devices cost money. The honest
position is: this procedure needs hardware you are willing to destroy, and if you do not have that
hardware yet, do labs 02–05 on an emulator or a borrowed-but-already-rooted device and come back to
this one when you do.

---

## Objective

Take a stock, locked, unmodified Android device and bring it to a documented, verified,
Magisk-rooted state — unlocking the bootloader, identifying the correct partition, patching its
image, **testing the patched image in RAM before writing it**, flashing, verifying, and producing an
evidence bundle that would let a colleague reproduce your device state exactly three weeks later.

Then practise the recovery paths, deliberately, while nothing is wrong.

## Why this matters

Three reasons, in increasing order of importance.

**You will do this repeatedly.** A testing practice re-images devices constantly: after an
engagement, after an OTA, after a module bootloops something. The first time takes a day; the tenth
takes twenty minutes, but only if you learned the procedure rather than a sequence of copied
commands.

**The failure modes teach the architecture.** When `fastboot boot` produces a device that boots but
has no root, you are looking at a real fact about where the ramdisk lives on your device. When
flashing the right image to the wrong slot bootloops an A/B device, you have learned what A/B
partitioning is in a way no diagram achieves. The errors in this lab are the curriculum.

**The evidence bundle is the professional part.** Anyone can follow an XDA thread. What separates a
tester from a hobbyist is being able to answer, months later, "what exactly was on that device when
you found that bug?" — with a fingerprint, an image hash, a module list and a mount table, not with
a memory. Section 9.5 of the chapter makes this argument; this lab is where you do it for the first
time.

---

## What you need

| Item | Notes |
|---|---|
| An Android device you own and can lose | See the suitability table below |
| A USB **data** cable | Charge-only cables enumerate power and nothing else, and produce "no devices found" with no other symptom. This wastes an hour for someone every week |
| A host with `adb` and `fastboot` | Google's `platform-tools`. Do **not** use a distro-packaged `fastboot` that is years old; protocol features and partition names have changed |
| The exact OEM factory image for the build currently on the device | Non-negotiable. See Step 3 |
| The Magisk APK | From the official GitHub releases page — `github.com/topjohnwu/Magisk`. Not from an APK mirror site; you are about to give this binary permanent boot-time control of the device |
| Time, uninterrupted | Do not start this twenty minutes before you need to leave |

### Device suitability

| Device class | Suitability | Why |
|---|---|---|
| Google Pixel (unlocked/retail, not carrier-locked) | **Best** | Factory images published for every build, `fastboot flashing unlock` supported, `fastboot boot` works, full `flash-all` recovery available |
| Older Pixel / Nexus | **Very good** | Same, and cheap second-hand. A Pixel 4a or 5 is the standard lab device for a reason |
| OnePlus, Sony, Xiaomi, Motorola (unlockable models) | **Usable** | Unlockable, but Xiaomi requires an account-bound waiting period and Motorola/Sony use per-device unlock codes obtained from the vendor |
| Samsung | **Avoid for a first device** | KNOX fuse; Odin rather than fastboot on many models; `fastboot boot` generally unavailable |
| Carrier-locked anything (US carrier variants especially) | **Not usable** | OEM-unlocking permanently disabled |
| Huawei (recent) | **Not usable** | Unlock codes no longer issued |
| A device that is your only phone | **Do not** | See the warning above |

> **Pentester's Note**
> Buy the device the *client's users* have, not the device that is easiest to root. If the target
> app's user base is on mid-range Samsungs, a rooted Pixel tells you how the app behaves on a Pixel.
> In practice most practices keep both: an easily-rooted reference device for instrumentation, and a
> stock representative device for behaviour. This lab builds the first one.

---

## Setup

### Step 0 — Record the pre-state, before you change anything

You cannot diff against a baseline you did not take. Do this first, every time.

```bash
# host — create the evidence directory for this device
SERIAL=$(adb get-serialno)
EV="evidence/$SERIAL/$(date +%Y%m%d-%H%M%S)-preroot"
mkdir -p "$EV"

adb shell getprop                          > "$EV/props.txt"
adb shell getprop ro.build.fingerprint     | tee "$EV/fingerprint.txt"
adb shell getprop ro.product.device        | tee "$EV/codename.txt"
adb shell getprop ro.build.version.release | tee "$EV/android-version.txt"
adb shell getprop ro.build.version.sdk     | tee "$EV/api-level.txt"
adb shell getprop ro.build.version.security_patch | tee "$EV/patch-level.txt"
adb shell getprop ro.boot.verifiedbootstate| tee "$EV/verifiedbootstate.txt"
adb shell getprop ro.boot.flash.locked     | tee "$EV/flash-locked.txt"
adb shell getprop sys.oem_unlock_allowed   | tee "$EV/oem-unlock-allowed.txt"
adb shell pm list packages -f              > "$EV/packages.txt"
adb shell cat /proc/self/mountinfo         > "$EV/mountinfo.txt"
```

Read the three values that decide whether this lab can proceed:

| Value | Expected on a stock locked device | If it is different |
|---|---|---|
| `ro.boot.verifiedbootstate` | `green` | `orange` means the bootloader is already unlocked — skip Step 2 |
| `ro.boot.flash.locked` | `1` | `0` means already unlocked |
| `sys.oem_unlock_allowed` | `0` until you enable it; must become `1` | If it stays `0` after enabling the developer-options toggle, and the toggle is greyed out, **this device cannot be unlocked**. Stop here |

> **Under the Hood**
> `ro.boot.*` properties are not set by Android. The bootloader passes them to the kernel on the
> command line (or in bootconfig on newer devices), and `init` copies them into the property area.
> That is why they are *evidence* rather than *configuration* — and also why `resetprop` can rewrite
> the copy in the property area without changing anything the bootloader actually reported to the
> TEE. Chapter [20-Security-Architecture](../../20-Security-Architecture/README.md) owns the
> attestation half of that story.

### Confirm your host tooling

```bash
# host
adb version            # expect "Android Debug Bridge version 1.0.41" or newer
fastboot --version
adb devices -l         # exactly one device, state "device", not "unauthorized"
```

`unauthorized` means the RSA fingerprint dialog has not been accepted on the device screen. Unlock
the screen and accept it; nothing below works until this reads `device`.

---

## Steps

### Step 1 — Enable developer options and OEM unlocking

On the device:

1. **Settings → About phone → tap "Build number" seven times.** You will see a countdown toast.
2. **Settings → System → Developer options → OEM unlocking → ON.**
3. **Settings → System → Developer options → USB debugging → ON.**

Then verify from the host, because the toggle can appear on and not take effect:

```bash
# host
adb shell getprop sys.oem_unlock_allowed    # must be 1
```

**Q1.** If the OEM unlocking toggle is greyed out with the subtitle "Connect to the internet or
contact your carrier", what is actually being checked, and why is it checked at all? (Hint: it is
not about the internet. It is about whether the device is carrier-financed or was reported stolen.)

### Step 2 — Unlock the bootloader (this erases everything)

Last chance to back out. Everything on the device dies at this command.

```bash
# host
adb reboot bootloader
# The device now shows a fastboot screen. Confirm the host can see it:
fastboot devices        # one line: <serial>  fastboot
```

```bash
# host — the destructive command
fastboot flashing unlock
# Older devices (Android 5 era and some OEMs):
#   fastboot oem unlock
```

The device now shows a confirmation screen. **This is a hardware-confirmed action on purpose** —
volume keys to select "Unlock the bootloader", power to confirm. The device wipes userdata and
reboots. First boot after a wipe takes several minutes and shows the setup wizard.

```bash
# host — after it comes back, skip the setup wizard, re-enable USB debugging, then:
adb shell getprop ro.boot.verifiedbootstate    # now: orange
adb shell getprop ro.boot.flash.locked         # now: 0
```

You will also now see a warning screen for a few seconds at every boot saying the bootloader is
unlocked and the device cannot be trusted. That screen is not a bug and cannot be removed on most
devices without patching the bootloader, which is out of scope and a bad idea.

> **Warning**
> Do **not** re-lock the bootloader later while a patched boot image is flashed. A locked bootloader
> verifies the boot image against the OEM key; a patched image fails that check; and a device that
> fails verification at a locked bootloader will not boot and, on many models, will not offer a way
> to unlock again because unlocking requires the OS to set a flag. The order for returning to stock
> is always: **flash the full stock factory image first, boot it, confirm it works, and only then
> re-lock.** See [Recovery drills](#step-9--recovery-drills-do-these-while-nothing-is-wrong).

**Q2.** Unlocking wipes userdata. Explain precisely why an unlock that did *not* wipe would be a
data-extraction vulnerability, in terms of what an attacker with physical access could then do.

### Step 3 — Get the exact factory image for the build on the device

```bash
# host
cat evidence/*/*-preroot/fingerprint.txt
# e.g. google/<device>/<device>:14/UQ1A.240105.004/11206848:user/release-keys
```

Download the OEM factory image whose build ID matches that fingerprint **character for character**.
For Pixels these are published at Google's factory image page; for other OEMs they come from the
vendor's own firmware site or, in a few cases, from a vendor tool.

```bash
# host — unpack the parts you need
unzip -o <factory-image>.zip                 # yields image-<device>-<build>.zip and flash scripts
unzip -o image-<device>-<build>.zip boot.img init_boot.img vbmeta.img 2>/dev/null || true
ls -la boot.img init_boot.img vbmeta.img 2>/dev/null
sha256sum boot.img init_boot.img 2>/dev/null | tee "$EV/stock-image-hashes.txt"
```

Keep the whole factory image. It is your recovery path, and you will want it in six months when the
device bootloops after an OTA.

> **Warning**
> A boot image from a different build **will** produce a bootloop or a device that cannot mount
> `/data`, because the ramdisk contains version-specific `init` behaviour and, on some devices, the
> AVB descriptors chain to it. "Close enough" is not a thing here. If the fingerprint you recorded
> is not available for download any more, take the OTA to the newest build first, re-record the
> fingerprint, and use that.

### Step 4 — Decide which partition holds the ramdisk

This is the single most common point of failure, and the answer differs by device generation. Do not
guess; measure.

```bash
# adb shell — does an init_boot partition exist on this device?
ls -l /dev/block/by-name/ | grep -iE 'init_boot|^.*boot_[ab]|vendor_boot'
```

```bash
# adb shell — GKI devices report a generic kernel release
uname -r                       # e.g. 5.15.x-android13-...  -> GKI
getprop ro.build.version.sdk
```

| Situation | Patch this | Flash to |
|---|---|---|
| `init_boot` partition exists (typically Android 13+ GKI launches — Pixel 7 and later) | `init_boot.img` | `init_boot` |
| No `init_boot`; ordinary boot image with a ramdisk (most devices up to Android 12) | `boot.img` | `boot` |
| Legacy "system-as-root" device with no ramdisk in `boot` | `recovery.img` (Magisk installs to recovery; you then boot to recovery to get a rooted boot) | `recovery` |

The Magisk app tells you which case you are in. Install the APK and open it:

```bash
# host
adb install -r Magisk-vXX.X.apk
adb shell monkey -p com.topjohnwu.magisk -c android.intent.category.LAUNCHER 1
```

On the app's home screen, read the **Ramdisk** line:

| App says | Meaning |
|---|---|
| `Ramdisk: Yes` | The boot image contains a ramdisk. Patch `boot.img` (or `init_boot.img` if that partition exists) |
| `Ramdisk: No` | Legacy system-as-root device. You are in the recovery-partition case; read Magisk's install documentation for that path specifically, because the boot procedure differs afterwards |

**Q3.** Look at `/dev/block/by-name/`. Do you see `boot_a` and `boot_b`, or a single `boot`? What
does that tell you about how this device takes updates, and what does it imply about which slot your
flash will land on?

```bash
# adb shell — which slot is active on an A/B device?
getprop ro.boot.slot_suffix       # _a or _b, empty on non-A/B devices
```

### Step 5 — Patch the image with the Magisk app

```bash
# host
adb push init_boot.img /sdcard/Download/       # or boot.img, per Step 4
```

In the Magisk app: **Install → Select and Patch a File → choose the pushed image**. The app runs
`magiskboot` (chapter [§3.1](../README.md#31-the-boot-image-and-what-patching-actually-changes)
walks exactly what happens) and writes the result to `/sdcard/Download/`.

```bash
# host — retrieve it and record what it is
adb shell ls -la /sdcard/Download/magisk_patched*
adb pull /sdcard/Download/magisk_patched-XXXXX_YYYYY.img patched.img
sha256sum patched.img init_boot.img | tee -a "$EV/patched-image-hashes.txt"
ls -la patched.img init_boot.img
```

**Q4.** Compare the sizes and hashes of the stock and patched images. The hash differs, as it must.
Is the size the same, larger, or smaller — and can you explain the direction of the change from what
you know `magiskboot` inserts and how it recompresses the ramdisk?

If you want to look inside rather than take it on faith, and you have `magiskboot` on the device:

```bash
# adb shell as root is NOT yet available; do this later, after Step 7:
#   cd /data/local/tmp && /data/adb/magisk/magiskboot unpack patched.img
#   cpio -t < ramdisk.cpio | grep -E '^\.backup|^overlay\.d|^init$'
```

### Step 6 — `fastboot boot` — test in RAM, do not write yet

**This is the most important habit in the chapter.** `fastboot boot` downloads the image into RAM
and boots it once. Nothing on the device is written. If the image is wrong, you power-cycle and the
device boots the untouched stock image.

```bash
# host
adb reboot bootloader
fastboot devices
fastboot boot patched.img
```

Wait for the device to boot fully — this can take longer than a normal boot the first time.

```bash
# host
adb wait-for-device
adb shell getprop sys.boot_completed          # 1
adb shell "su -c 'magisk -v'"                 # e.g. 27.0:MAGISK
```

The first `su` invocation raises a grant prompt on the device screen. Accept it.

> **The outer double quotes are not decoration.** `adb shell` joins its arguments with spaces
> before the device sees them, so `adb shell su -c 'magisk -v'` arrives as `su -c magisk -v`, the <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this warning teaches -->
> `-v` is eaten by **`su`**, and you get *su's* version string believing it to be Magisk's. On an
> AOSP emulator, `su` takes a uid rather than `-c` — use `adb shell "su 0 magisk -v"` there.

| What happened | What it means | What to do |
|---|---|---|
| Boots, `magisk -v` works | The image is correct | Proceed to Step 7 |
| Boots, but `su` says "not found" | You patched the wrong partition's image, or the device needs the recovery path | Power-cycle back to stock, re-read Step 4 |
| Does not boot; screen stays black or loops | Wrong image, wrong build, or wrong device | **Hold power for 10–20 s to force off.** The device boots stock on the next power-up. Nothing was written |
| `fastboot boot` returns `FAILED (remote: 'unknown command')` or similar | Your OEM disabled RAM-booting | See the note below |

> **Warning — when `fastboot boot` is unavailable**
> Several OEMs disable `fastboot boot`. On those devices you have no free test, and flashing is the
> only path. Before you flash: confirm the full stock factory image is downloaded and extracted on
> the host, confirm you can enter fastboot mode with a hardware key combination (so you are not
> dependent on `adb reboot bootloader`), and write down that key combination. Then accept the risk
> consciously. That sentence — "accept the risk consciously" — is the difference between a
> calculated action and an accident.

### Step 7 — Verify root properly, with evidence

Not "the app says it's installed". Measure.

```bash
# host
EV2="evidence/$SERIAL/$(date +%Y%m%d-%H%M%S)-rooted"
mkdir -p "$EV2"

adb shell "su -c 'magisk -v'"     | tee "$EV2/magisk-version.txt"
adb shell "su -c 'magisk -V'"     | tee -a "$EV2/magisk-version.txt"
adb shell "su -c 'magisk --path'" | tee -a "$EV2/magisk-version.txt"
adb shell "su -c 'id'"            | tee "$EV2/id.txt"
adb shell "su -c 'id -Z'"         | tee -a "$EV2/id.txt"
adb shell getenforce              | tee "$EV2/selinux.txt"
adb shell "su -c 'ls -la /data/adb/'"      > "$EV2/data-adb.txt"
adb shell "su -c 'cat /proc/self/mountinfo'" > "$EV2/mountinfo-root.txt"
adb shell getprop             > "$EV2/props.txt"
```

Check each of these and know what "good" looks like:

| Check | Healthy result | If it is wrong |
|---|---|---|
| `id` | `uid=0(root) gid=0(root)` | You are not root; the grant prompt was denied, or `su` is not the Magisk one |
| `id -Z` | A context containing `magisk` on most builds | Not fatal; contexts vary by version |
| `getenforce` | **`Enforcing`** | If it says `Permissive`, something set `setenforce 0`. Fix it: `su -c 'setenforce 1'`. A permissive device behaves differently and several apps detect it |
| `magisk --path` | A path such as `/debug_ramdisk` | Tells you where the Magisk tmpfs lives — you need this in lab 03 |
| `grep -c magisk mountinfo-root.txt` | Non-zero | Zero here means no modules are mounted yet, which is expected on a fresh install with no modules |

```bash
# host — the diff that shows what rooting changed at the property level
diff "$EV/props.txt" "$EV2/props.txt" > "$EV2/props-diff.txt" || true
grep -E 'verifiedbootstate|flash.locked|vbmeta.device_state' "$EV2/props-diff.txt"
```

**Q5.** Look at the property diff. Did `ro.boot.verifiedbootstate` change because of Magisk, or
because of the unlock in Step 2? Which of the two events is visible to hardware-backed attestation,
and why does that distinction matter when you write a report?

### Step 8 — Flash for persistence

Only now, after a successful `fastboot boot`.

```bash
# host
adb reboot bootloader
fastboot flash init_boot patched.img      # or: fastboot flash boot patched.img
fastboot reboot
adb wait-for-device
adb shell "su -c 'magisk -v'"
```

On an A/B device, `fastboot flash init_boot` writes to the **currently active slot** by default. If
you need to be explicit:

```bash
# host — explicit slot targeting on an A/B device
fastboot getvar current-slot
fastboot flash init_boot_a patched.img     # or _b
```

**Q6.** You flashed to the active slot. What happens to the *inactive* slot's boot image, and what
does that imply the next time the device takes an OTA and switches slots?

### Step 9 — Recovery drills (do these while nothing is wrong)

This is the part people skip and then regret. Practise each of these now, deliberately, while the
device is healthy and you are not panicking.

**Drill 1 — safe mode.** Magisk's safe mode disables all modules for one boot. Learn the gesture for
your device *now*:

```
Power off completely. Power on. As soon as the boot animation starts, hold Volume Down
until the device finishes booting.
```

Verify it worked: the Magisk app will report that modules were disabled.

**Drill 2 — disable modules over adb.** Works if `adb` still comes up, which it often does even on a
device that never reaches the launcher:

```bash
# host
adb wait-for-device
adb shell "su -c 'touch /data/adb/modules/*/disable'" && adb reboot
```

**Drill 3 — restore the stock boot image.** Do it now, then re-flash the patched one, so you know
the sequence works:

```bash
# host
adb reboot bootloader
fastboot flash init_boot init_boot.img       # the STOCK image from Step 3
fastboot reboot
adb wait-for-device
adb shell "su -c 'magisk -v'"                # expect: su: not found  -> you are back to stock
```

**Drill 4 — the full factory image.** Read your factory image's `flash-all.sh` (or `.bat`) before you
ever need to run it, and understand the `-w` flag:

```bash
# host — READ this file, do not just run it
cat flash-all.sh
```

> **Warning**
> `flash-all.sh` normally contains `fastboot -w update image-<device>-<build>.zip`. The `-w` **wipes
> userdata**. If you want to recover a bootlooping device *without* losing its data, remove the `-w`.
> If the bootloop is caused by something in `/data` (a bad module, for instance), you need the wipe.
> Know which situation you are in before you press enter.

**Drill 5 — returning to stock and re-locking, in the right order.** For when you sell or return the
device:

```bash
# host — 1. full stock factory image, including vbmeta and every partition
./flash-all.sh
# 2. boot it, complete setup, confirm ro.boot.verifiedbootstate reports the unlocked state
adb shell getprop ro.boot.verifiedbootstate      # orange, because still unlocked
# 3. ONLY NOW re-lock
adb reboot bootloader
fastboot flashing lock                            # wipes again, and confirms on-screen
```

**Q7.** Explain, in terms of what the bootloader verifies, why steps 1 and 3 must happen in that
order and never the reverse.

### Step 10 — Write the device record

Produce a single file a colleague could read in six months. This is the deliverable.

```bash
# host
cat > "$EV2/DEVICE-RECORD.md" <<'EOF'
# Test device record

| Field | Value |
|---|---|
| Device / codename |  |
| Serial |  |
| Build fingerprint (pre-root) |  |
| Android version / API |  |
| Security patch level |  |
| Bootloader unlocked on (date) |  |
| Partition patched | boot / init_boot / recovery |
| Stock image sha256 |  |
| Patched image sha256 |  |
| Magisk version / versionCode |  |
| Zygisk enabled | yes / no |
| DenyList entries |  |
| Modules installed |  |
| SELinux mode at time of testing |  |
| Notes / deviations |  |
EOF
echo "Fill this in from the files in $EV and $EV2"
```

**Q8.** Which single field in that table would you most regret not recording? Justify the answer
against a scenario where a client disputes a finding.

---

## Troubleshooting

| Symptom | Most likely cause | Fix |
|---|---|---|
| `adb devices` shows nothing | Charge-only cable, or missing USB driver on Windows | Swap the cable first — it is the cause more often than anything else. On Windows, install Google's USB driver and check Device Manager |
| `adb devices` shows `unauthorized` | RSA prompt not accepted | Unlock the screen, accept. If the prompt never appears, revoke USB debugging authorisations in Developer options and replug |
| `fastboot devices` shows nothing but `adb` worked | Fastboot needs its own driver on Windows | Install the driver against the device while it is *in* fastboot mode |
| `FAILED (remote: 'Flashing is not allowed in Lock State')` | Bootloader still locked | Step 2 did not complete. Check `ro.boot.flash.locked` |
| `FAILED (remote: 'unknown command')` on `fastboot boot` | OEM disabled RAM boot | See the warning in Step 6 |
| Boots to a screen saying the device is corrupt and will not start | AVB rejected something you flashed | Flash the full stock factory image. Some devices additionally need `fastboot --disable-verity --disable-verification flash vbmeta vbmeta.img`; read your device's documentation before using it, because it is not universally correct |
| Bootloop after flashing a patched image that `fastboot boot` accepted | Usually a slot mismatch on A/B, or userdata that cannot be decrypted | Re-flash the stock image to the same slot, boot, and start again |
| Boots, but the Magisk app says "Requires additional setup" | Only the app is installed; the boot image is not patched, or you flashed the wrong partition | Redo Steps 4–8 |
| Root worked, then stopped after a system update | The OTA replaced your patched partition | Expected — see the OTA note below |
| Everything works but `getenforce` says `Permissive` | Something in your setup ran `setenforce 0` | `su -c 'setenforce 1'`, then find what did it |

### The OTA problem, stated once

An OTA update patches or replaces the boot partition, which removes Magisk. On A/B devices the
update is written to the inactive slot and the device switches to it at reboot, so the patched
image on the old slot becomes irrelevant.

There are two honest options, and one non-option:

| Option | Procedure |
|---|---|
| **Simplest, always works** | Take the OTA, lose root, download the new factory image, and redo Steps 3–8 with the new build's image |
| **Magisk's "Install to Inactive Slot"** | Download the OTA but do not reboot; use the Magisk app's *Install to Inactive Slot (After OTA)*, which patches the newly written slot before the switch. Read Magisk's install documentation for the version you are running before relying on it |
| **Non-option** | Assuming your existing patched image will keep working. It will not, and the boot images are build-specific, so the old one is not reusable |

---

## Hints

<details>
<summary>Hint 1 — the device does not appear in fastboot on Windows</summary>

`adb` and `fastboot` use different USB interfaces and therefore need different drivers. A device that
works perfectly under `adb` can be invisible under `fastboot` on the same machine. Install the driver
while the device is *in* fastboot mode: open Device Manager, find the unknown "Android" device, and
point it at Google's USB driver directory.

On Linux, the equivalent failure is a missing `udev` rule, and the symptom is `no permissions`
instead of nothing at all. Running `fastboot` under `sudo` proves the diagnosis; a udev rule is the
fix.
</details>

<details>
<summary>Hint 2 — how to tell whether you patched the right partition, before flashing</summary>

You do not have to guess. `fastboot boot patched.img` answers it in ninety seconds:

- Boots and `su` works: right partition.
- Boots and `su` is missing: the image is valid but contains no ramdisk that runs `magiskinit` — you
  patched the wrong file.
- Does not boot: the image is not valid for this device or build.

Three distinct outcomes, three distinct diagnoses, zero permanent changes. This is why the step
exists.
</details>

<details>
<summary>Hint 3 — "it booted but there is no root, and the Magisk app looks fine"</summary>

Check three things in order:

1. `adb shell ls -la /data/adb/` — if this directory is empty or absent, `magiskinit` never ran, and
   the problem is the boot image, not the app.
2. `adb shell "su -c 'magisk --path'"` — if `su` is not found at all, same conclusion.
3. `adb logcat -d | grep -i magisk` and, if you can get one, `dmesg`. `magiskinit` logs to
   `/dev/kmsg`, so kernel log output is where early failures appear.

The Magisk app being installed tells you nothing about whether the boot image is patched. They are
independent.
</details>

<details>
<summary>Hint 4 — you are on an A/B device and confused about slots</summary>

```bash
# host
fastboot getvar current-slot
fastboot getvar has-slot:boot
fastboot getvar has-slot:init_boot
```

An A/B device holds two complete copies of the system partitions. Updates are written to the
inactive slot and the device switches at reboot, which is why an interrupted OTA does not brick the
device. `fastboot flash init_boot` writes the active slot; `fastboot flash init_boot_a` is explicit.
If you flash the inactive slot and reboot, nothing appears to have happened — a symptom that looks
like a failed flash but is a targeting mistake.
</details>

---

## Success criteria

- [ ] You recorded a full pre-root evidence bundle, including the fingerprint, before touching
      anything
- [ ] You confirmed the device is unlockable *before* starting, from `sys.oem_unlock_allowed`
- [ ] You can state in one sentence what unlocking destroys and why that is deliberate
- [ ] You downloaded the factory image matching the recorded fingerprint character for character
- [ ] You determined which partition holds the ramdisk by measurement, not by copying a tutorial
- [ ] You recorded the sha256 of both the stock and patched images
- [ ] You tested with `fastboot boot` before any `fastboot flash` — or, if your device does not
      support it, you wrote down why you accepted the risk and what your recovery path was
- [ ] `su -c id` returns uid 0 and `getenforce` returns `Enforcing`
- [ ] You produced a post-root evidence bundle and a property diff
- [ ] You practised safe mode, the adb module-disable, and a stock-image restore **while the device
      was healthy**
- [ ] You re-flashed the patched image after the restore drill, so you know both directions work
- [ ] You can explain why re-locking a bootloader with a patched image flashed is the fastest way to
      brick the device
- [ ] You filled in `DEVICE-RECORD.md` completely
- [ ] You answered Q1–Q8 in writing

---

## If you cannot do this lab

If you do not have a device you can destroy, you are not locked out of chapter 62. Here is what is
and is not reachable.

| Path | What you get | What you do not get |
|---|---|---|
| **A rooted AVD** — an Android Virtual Device with a Google **APIs** (not Google Play) system image supports `adb root` and a writable `/system` | Enough root to explore `/data/adb`-style layouts, run `frida-server`, and read app private data | Not Magisk. No `magiskd`, no modules, no DenyList, no Zygisk, and therefore none of labs 03–05 as written |
| **A Magisk-patched AVD**, produced by patching the emulator's `ramdisk.img` (community tooling such as `rootAVD` does this) | Real Magisk: modules, DenyList, Zygisk, mount namespaces. **Labs 02, 03, 04 and 05 all work here** | No `fastboot`, no bootloader, no AVB — so this lab's actual subject matter is simulated at best |
| **A second-hand Pixel** (a 4a or 5 is inexpensive) | Everything | Costs money |
| **Borrowing an already-rooted device** | Labs 02–05 | You will not have practised recovery, which is the part that matters when something breaks at 2am |

The honest recommendation: do labs 02–05 on a Magisk-patched AVD now, and buy a cheap second-hand
Pixel before you take on any real engagement. An emulator cannot teach you what a bootloop feels
like, and an engagement is the wrong place to learn.

---

## Next

[Lab 02 — Write a Magisk module](lab-02-write-a-module.md) uses the device you just built. Before
you start it, read [§3.6](../README.md#36-module-structure) so the layout is familiar, and keep the
evidence directory from this lab — lab 03 diffs against the `mountinfo` you captured here.
