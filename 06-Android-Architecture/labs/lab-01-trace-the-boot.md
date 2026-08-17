# Lab 01 — Trace the Boot

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [Chapter 06 §3](../README.md), a device or emulator, `adb`

---

## Objective

Capture a complete boot and identify every milestone from §3 in the logs — bootloader, kernel, `init`,
property service, `servicemanager`, Zygote preload, `system_server` service startup, and boot
completion. By the end the boot sequence stops being a diagram you read and becomes something you have
watched happen.

## Why this matters

Three practical returns.

Boot logs tell you what the OEM added and when it starts — vendor daemons appear here, and they are
where findings concentrate on OEM devices. SELinux denials during boot (`avc: denied`) reveal policy
gaps that are often more interesting than anything an app can reach. And when a device misbehaves
after you flash something, the boot log is the only thing that tells you where it stopped.

---

## Setup

```bash
# host
adb devices
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.type
```

An emulator works fine and is easier to reboot repeatedly. A physical device gives you a more
realistic vendor picture.

```bash
# host — enlarge the log buffer so nothing is lost during boot
adb shell logcat -G 16M
```

---

## Steps

### Step 1 — Capture a full boot

```bash
# host
adb reboot
adb wait-for-device
sleep 45                      # let boot finish
adb logcat -b all -d > boot.log
adb shell dmesg > dmesg.log   # add 'su -c' if dmesg is restricted
wc -l boot.log dmesg.log
```

**Q1.** How many lines did each produce? Which covers earlier events?

### Step 2 — The kernel phase

```bash
# host
head -60 dmesg.log
grep -iE "Linux version|Command line" dmesg.log | head
```

**Q2.** What kernel version is this, and what is on the kernel command line? Look for `androidboot.*`
parameters — the bootloader passes device state to userspace this way.

```bash
grep -oE "androidboot\.[a-z_.]+=[^ ]*" dmesg.log | sort -u
```

**Q3.** Do you see `androidboot.verifiedbootstate`, `androidboot.veritymode` or
`androidboot.flash.locked`? Compare each against the corresponding `ro.boot.*` property:

```bash
adb shell getprop | grep '^\[ro.boot'
```

What is the relationship between the kernel command line and those properties?

### Step 3 — Verified boot and verity

```bash
# host
grep -iE "verity|dm-verity|avb|vbmeta" dmesg.log | head -20
```

**Q4.** Is dm-verity being set up? On which devices? What mode?

### Step 4 — SELinux initialisation

```bash
# host
grep -iE "selinux|avc:" dmesg.log | head -30
```

**Q5.** When does SELinux load policy relative to `init` starting? Are there any `avc: denied` lines
during boot? Record them — boot-time denials frequently indicate policy that was loosened elsewhere to
compensate. See [22-SELinux](../../22-SELinux/README.md).

### Step 5 — init and the property service

```bash
# host
grep -nE "^.*init: " boot.log | head -40
grep -nE "init: Starting service" boot.log | head -30
```

**Q6.** List the first ten services `init` starts, in order. Which of them are you able to explain?

```bash
# host — what does init say about the property service?
grep -iE "property|propert" boot.log | head -20
```

### Step 6 — servicemanager and the Binder foundation

```bash
# host
grep -inE "servicemanager|hwservicemanager|vndservicemanager" boot.log | head
```

**Q7.** Does `servicemanager` start before or after Zygote? Why must that ordering hold?

### Step 7 — Zygote

This is the heart of the lab.

```bash
# host
grep -nE "Zygote|zygote" boot.log | head -40
grep -nE "Preloading|preload" boot.log | head -20
```

**Q8.** Find the preload messages. How many classes and resources were preloaded, and how long did it
take? Look for lines reporting counts and timings.

**Q9.** Are there two Zygote processes? Check:

```bash
adb shell ps -A | grep -i zygote
```

Why would a device have both `zygote` and `zygote64`?

### Step 8 — system_server

```bash
# host
grep -nE "SystemServer" boot.log | head -40
grep -oE "StartingService|Start[A-Za-z]+Service" boot.log | sort | uniq -c | sort -rn | head -30
```

**Q10.** Extract the service startup order. Which services start first, and can you suggest why that
ordering exists? (Hint: consider which services others depend on.)

```bash
# host — the timing breakdown system_server prints
grep -nE "SystemServerTiming|Slow operation" boot.log | head -30
```

### Step 9 — Boot completion

```bash
# host
grep -nE "Boot is finished|sys.boot_completed|BOOT_COMPLETED" boot.log | head
adb shell getprop sys.boot_completed
adb shell getprop ro.runtime.firstboot 2>/dev/null
```

**Q11.** How long did the boot take end to end? Which phase dominated?

### Step 10 — Build the timeline

Produce your own annotated timeline. Fill in the times from your logs:

| Phase | Evidence in the log | Time |
|---|---|---|
| Kernel start | `Linux version ...` in `dmesg` | |
| dm-verity setup | `dm-verity` lines | |
| SELinux policy load | `SELinux: Loaded policy` | |
| `init` first stage | `init: init first stage started` | |
| Property service | `init:` property messages | |
| `servicemanager` | `init: Starting service 'servicemanager'` | |
| Zygote start | `init: Starting service 'zygote'` | |
| Preload complete | `Zygote: ...Preload...` | |
| `system_server` start | `SystemServer` first line | |
| Boot completed | `Boot is finished` | |

**Q12.** Compare your timeline against the diagram in §2 of the chapter. Did anything happen in a
different order than you expected?

### Step 11 — Find the vendor additions

This is the step that produces findings on real devices.

```bash
# host
grep -oE "init: Starting service '[^']+'" boot.log | sed "s/.*'\(.*\)'/\1/" | sort -u > services.txt
wc -l services.txt
```

Now separate the AOSP-typical services from the vendor ones:

```bash
# host
grep -viE '^(init|ueventd|logd|lmkd|vold|servicemanager|hwservicemanager|vndservicemanager|healthd|installd|netd|zygote|zygote64|apexd|keystore2?|adbd|surfaceflinger|audioserver|cameraserver|media|mediaserver|mediadrm|mediaextractor|mediametrics|drm|bluetooth|wifi|statsd|traced.*|gatekeeperd|storaged|thermalservice|tombstoned|update_engine|virtual_touchpad|webview_zygote)' services.txt
```

**Q13.** What is left? For each remaining service, find its init entry on the device:

```bash
adb shell "grep -rA10 \"^service <name>\" /vendor/etc/init/ /system/etc/init/ 2>/dev/null"
```

**Q14.** For each, record: does it declare a `user`? What capabilities? What `seclabel`? Any sockets,
and with what mode? Anything running as root with a `0666` socket is worth a proper look — see
[24-IPC](../../24-IPC/README.md).

### Step 12 — Automate it

```bash
# host
../scripts/device-posture.sh
../scripts/layer-census.sh
```

**Q15.** Do the scripts' findings match what you derived by hand? Anything they caught that you missed?

---

## Hints

<details>
<summary>Hint 1 — logcat has already rotated by the time I capture</summary>

Grow the buffer *before* rebooting:
```bash
adb shell logcat -G 16M
adb reboot
```
Or stream to a file during boot instead of dumping afterwards:
```bash
adb wait-for-device && adb logcat -b all > boot.log &
adb reboot
```
</details>

<details>
<summary>Hint 2 — dmesg is empty or permission denied</summary>

`dmesg` is restricted to root on production builds:
```bash
adb shell "su -c dmesg" > dmesg.log
```
Without root, `logcat -b kernel` may carry some of the same messages, and the
`androidboot.*` parameters are still visible as `ro.boot.*` properties.
</details>

<details>
<summary>Hint 3 — no Zygote preload messages</summary>

Preload logging is verbose and some builds suppress it. Try:
```bash
grep -iE "zygote|preload|PreloadClasses" boot.log
adb logcat -b all -d | grep -i zygote
```
On an emulator you will generally see more. The *timing* may appear under `SystemServerTiming`.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q2–Q3.** The bootloader passes device state to userspace on the kernel command line as
`androidboot.*` parameters. `init` reads them and re-exposes them as `ro.boot.*` properties. So
`androidboot.verifiedbootstate=green` on the command line becomes
`ro.boot.verifiedbootstate=green`. That is the mechanism by which the *bootloader's* view of
integrity reaches Android — and it is why those properties are trustworthy only to the extent the boot
chain is intact.

**Q5.** SELinux policy is loaded by first-stage `init` before most services start, so services are
labelled from the beginning. Boot-time `avc: denied` lines are worth recording: they indicate either
policy that needs a rule or, more interestingly, a vendor component doing something the policy authors
did not anticipate.

**Q7.** `servicemanager` must start **before** Zygote and `system_server`, because it is the registry
those processes publish to and look each other up through. Nothing can find a Binder service before
the service manager exists.

**Q9.** A 64-bit device with 32-bit app support runs **two** Zygotes: `zygote64` and `zygote`. Apps
are forked from whichever matches their ABI. This is also why you may see `zygote_secondary` in the
socket names. It matters when attaching tooling — make sure you target the right one.

**Q10.** Ordering is driven by dependency. Services that others need — power, package manager,
activity manager — start in the bootstrap phase; higher-level services follow. `SystemServer.java`
groups them explicitly into bootstrap, core and other services, which is why reading that file is the
fastest way to understand the framework's shape.

**Q13–Q14.** The residue after filtering AOSP-typical names is the vendor's additions. This is the
highest-value output of the lab. A vendor daemon running as root, with broad capabilities and a
world-accessible socket, is a realistic and productive finding — far more so than hunting kernel bugs.
See [24-IPC](../../24-IPC/README.md) and §5.2 of the chapter.

</details>

---

## Success criteria

- [ ] You captured a complete boot from both `dmesg` and `logcat`
- [ ] You found the `androidboot.*` kernel parameters and matched them to `ro.boot.*` properties
- [ ] You identified where dm-verity and SELinux are initialised
- [ ] You listed the first ten services `init` starts, in order
- [ ] You explained why `servicemanager` must precede Zygote
- [ ] You found the Zygote preload messages and can say what preloading achieves
- [ ] You explained why a device may run two Zygotes
- [ ] You extracted the `system_server` service startup order
- [ ] You built a complete annotated boot timeline
- [ ] You isolated the vendor-added services and audited at least three init entries
- [ ] Your manual findings agree with `device-posture.sh` and `layer-census.sh`
