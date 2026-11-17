# Lab 01 — Device Reconnaissance

**Difficulty:** Beginner
**Time:** 30–45 minutes
**Prerequisites:** A device or emulator with USB debugging enabled, `adb` on your PATH

---

## Objective

Produce a complete, professional device profile using nothing but `adb` and `getprop` — and be able
to explain what every value means for a security test. By the end you should be able to look at a
device you have never seen and, in two minutes, state whether it is rooted, whether verified boot is
intact, how old its security patches are, and which ABI its native libraries must target.

## Why this matters

Every finding you report is a finding *on a specific platform*. A vulnerability that is exploitable
on Android 9 may be impossible on Android 14 because a default changed. If your report does not say
which build you tested, a developer can dismiss it, and six months later you cannot reproduce it
yourself. Recon is not busywork; it is the thing that makes the rest of the report defensible.

## Setup

```bash
# host
adb devices -l
```

If you see `unauthorized`, unlock the device screen and accept the RSA prompt. If you see nothing,
work through FAQ items 1 and 2 in [../faq.md](../faq.md) before continuing.

---

## Steps

### Step 1 — Identity

```bash
# host
adb shell getprop ro.build.fingerprint
adb shell getprop ro.product.manufacturer
adb shell getprop ro.product.model
adb shell getprop ro.product.name
adb shell getprop ro.product.device
```

The **fingerprint** is the single most important value. It has the form
`brand/product/device:release/id/incremental:type/tags` and uniquely identifies the build. Copy it
verbatim into your notes.

### Step 2 — Version and patch level

```bash
# host
adb shell getprop ro.build.version.release       # e.g. 14
adb shell getprop ro.build.version.sdk           # e.g. 34
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.build.version.codename
```

**Question to answer:** how many months behind the current Android security bulletin is this device?
Look up the bulletin for the reported patch date. A device more than three months behind is itself
worth a note in your report when the engagement covers the device rather than only the app.

### Step 3 — Build type and trust

```bash
# host
adb shell getprop ro.build.type      # user | userdebug | eng
adb shell getprop ro.build.tags      # release-keys | test-keys
adb shell getprop ro.debuggable      # 0 | 1
adb shell getprop ro.secure          # 1 on production
```

**Question to answer:** what does `ro.build.tags=test-keys` tell you? (Answer: the image was signed
with the public AOSP test keys rather than the vendor's private release keys — it is a custom or
development build, and any app that checks this value will consider the device untrusted.)

### Step 4 — Verified Boot and bootloader state

```bash
# host
adb shell getprop ro.boot.verifiedbootstate   # green | yellow | orange | red
adb shell getprop ro.boot.flash.locked        # 1 = locked
adb shell getprop ro.boot.veritymode
adb shell getprop ro.boot.vbmeta.device_state
```

| Value | Meaning |
|---|---|
| `green` | Locked bootloader, verified with the OEM key. Fully trusted. |
| `yellow` | Locked bootloader, verified with a user-supplied key. |
| `orange` | Bootloader unlocked. Verification not enforced. |
| `red` | Verification failed. The device should refuse to boot. |

**Question to answer:** if `verifiedbootstate` is `orange`, what can an app conclude, and what can it
*not* conclude? (Answer: it can conclude the boot chain is not guaranteed and that persistent system
modification is possible. It cannot conclude the device is currently rooted — those are different
things.) See [20-Security-Architecture](../../20-Security-Architecture/README.md).

### Step 5 — Architecture

```bash
# host
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.product.cpu.abilist
adb shell uname -a
```

**Question to answer:** which directory inside an APK's `lib/` will actually be used on this device,
and which `frida-server` build must you download?

### Step 6 — Root and SELinux

```bash
# host
adb shell 'command -v su && echo "su present" || echo "no su on PATH"'
adb shell getenforce
adb shell id
adb shell id -Z
```

```bash
# host — if root is available, confirm it. Try BOTH forms: they are not equivalent.
adb shell 'su -c id' 2>/dev/null || echo "su -c did not grant"
adb shell 'su 0 id'  2>/dev/null || echo "su 0 did not grant"
```

> **Warning — one failing form does not mean "not rooted".** Magisk's `su` takes
> `su -c <cmd>`; the AOSP `su` shipped on emulator images takes a **uid** instead, so `su -c id`
> returns `su: invalid uid/gid '-c'` on it while `su 0 id` returns `uid=0(root)`. Measured on the
> `sdk_gphone16k_x86_64` API 35 AVD, the `-c` form fails and the `0` form succeeds. Reading the
> first failure as "the device is not rooted" is a documented error in this repository — see
> [37-RootDetection §3](../../37-RootDetection/README.md) and
> [73-Labs faq](../../73-Labs/faq.md). Always try both before you conclude anything.

**Question to answer:** you have root but `getenforce` says `Enforcing`. Name one thing you still
cannot do. (Many answers; e.g. a process in the wrong SELinux domain cannot read another app's data
even as UID 0 until the policy permits it, which is why Magisk ships `magiskpolicy`.)

### Step 7 — Users and installed software

```bash
# host
adb shell pm list users
adb shell pm list packages -3 | wc -l
adb shell pm list packages -3
adb shell settings get global adb_enabled
adb shell settings get global development_settings_enabled
adb shell settings get global http_proxy
```

**Question to answer:** you find a work profile in `pm list users`. Why does that change how you run
every subsequent command? (Because package and component operations are per-user; you must pass
`--user <id>`, and the same app can exist twice with different UIDs.)

### Step 8 — Automate it

Write your own `device-profile.sh` that produces the whole profile in one run and writes it to a
timestamped file. Do not copy [`../scripts/session.sh`](../scripts/session.sh) — write your own
first, then compare.

---

## Hints

<details>
<summary>Hint 1 — getprop is slow when called repeatedly</summary>

Each `adb shell getprop x` is a full round trip. Fetch everything once with `adb shell getprop` and
parse locally, or use a single `adb shell` invocation containing a loop.
</details>

<details>
<summary>Hint 2 — some properties do not exist on every device</summary>

`ro.boot.flash.locked` is Pixel-centric. On other vendors look for `ro.boot.verifiedbootstate`,
`ro.boot.vbmeta.device_state`, or vendor-specific equivalents. Absence of a property is itself
information: record it rather than silently dropping it.
</details>

---

## Solution

<details>
<summary>Reference implementation</summary>

```bash
#!/usr/bin/env bash
# device-profile.sh — one-shot device profile
set -uo pipefail
OUT="device-profile-$(date +%Y%m%d-%H%M%S).txt"

PROPS="ro.build.fingerprint ro.build.version.release ro.build.version.sdk
ro.build.version.security_patch ro.build.type ro.build.tags ro.debuggable ro.secure
ro.product.manufacturer ro.product.model ro.product.device ro.product.cpu.abi
ro.product.cpu.abilist ro.boot.verifiedbootstate ro.boot.flash.locked ro.boot.veritymode"

{
  echo "# Device profile — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  # One round trip for all properties.
  ALL=$(adb shell getprop)
  for p in $PROPS; do
    v=$(echo "$ALL" | grep "^\[$p\]" | sed 's/.*: \[//;s/\]$//')
    printf "%-36s %s\n" "$p" "${v:-<absent>}"
  done
  echo
  printf "%-36s %s\n" "selinux"  "$(adb shell getenforce | tr -d '\r')"
  printf "%-36s %s\n" "shell id" "$(adb shell id | tr -d '\r')"
  printf "%-36s %s\n" "su"       "$(adb shell 'command -v su >/dev/null && echo present || echo absent' | tr -d '\r')"
  printf "%-36s %s\n" "adb_enabled" "$(adb shell settings get global adb_enabled | tr -d '\r')"
  printf "%-36s %s\n" "http_proxy" "$(adb shell settings get global http_proxy | tr -d '\r')"
  echo
  echo "# Users"
  adb shell pm list users
  echo
  echo "# Third-party packages ($(adb shell pm list packages -3 | wc -l | tr -d ' '))"
  adb shell pm list packages -3
} | tee "$OUT"

echo
echo "Written to $OUT"
```
</details>

---

## Success criteria

- [ ] You can state the device's exact build fingerprint from memory of where to find it
- [ ] You can say how many months behind the current bulletin the patch level is
- [ ] You can explain what `verifiedbootstate=orange` does and does not prove
- [ ] You know which `lib/<abi>/` directory matters on this device
- [ ] You can explain why root plus `Enforcing` SELinux is not unrestricted access
- [ ] Your script runs on a fresh device with no edits and produces a complete profile
- [ ] The output is something you would be comfortable pasting into the "Test Environment" section of
      a client report
