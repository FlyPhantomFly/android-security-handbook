# Magisk — Cheat Sheet

Printable. Tables and commands only. Full explanations in [README.md](README.md).

---

## Install / flash

| Task | Command |
|---|---|
| Check unlock allowed | `adb shell getprop sys.oem_unlock_allowed` |
| Check current lock state | `adb shell getprop ro.boot.flash.locked` |
| Boot state | `adb shell getprop ro.boot.verifiedbootstate` |
| Exact build (must match boot image) | `adb shell getprop ro.build.fingerprint` |
| Reboot to bootloader | `adb reboot bootloader` |
| List fastboot devices | `fastboot devices` |
| Unlock (WIPES DEVICE) | `fastboot flashing unlock` |
| Legacy unlock | `fastboot oem unlock` |
| Test image, non-persistent | `fastboot boot patched.img` |
| Flash boot (pre-GKI) | `fastboot flash boot patched.img` |
| Flash init_boot (Android 13+ GKI) | `fastboot flash init_boot patched.img` |
| Disable verity/verification | `fastboot --disable-verity --disable-verification flash vbmeta vbmeta.img` |
| Relock (returns to stock only) | `fastboot flashing lock` |

---

## Which partition do I patch?

| Device era | Patch |
|---|---|
| Android ≤ 12, most devices | `boot.img` |
| Android 13+ GKI (Pixel 7+, many 2023+ launches) | `init_boot.img` |
| Devices with no ramdisk in boot (older system-as-root) | `recovery.img`, boot to recovery to get root |

Check: if `init_boot.img` exists in the factory image, patch it.

---

## Verify installation

> **The outer double quotes below are load-bearing.** `adb shell` joins its arguments with spaces
> before the device sees them, so `adb shell su -c 'magisk -v'` arrives as `su -c magisk -v`, the <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this warning teaches -->
> `-v` is eaten by **`su`**, and you read *su's* version believing it to be Magisk's. On an AOSP
> emulator whose `su` takes a uid rather than `-c`, use `adb shell "su 0 <cmd>"` instead.

| Task | Command |
|---|---|
| Version string | `adb shell "su -c 'magisk -v'"` |
| Version code | `adb shell "su -c 'magisk -V'"` |
| Magisk base path | `adb shell "su -c 'magisk --path'"` |
| Confirm root | `adb shell "su -c 'id'"` |
| Root SELinux context | `adb shell "su -c 'id -Z'"` |
| SELinux mode | `adb shell getenforce` |
| Magisk mounts | `adb shell "su -c 'grep -i magisk /proc/self/mountinfo'"` |
| Magisk log | `adb shell "su -c 'cat /data/adb/magisk.log'"` |
| Kernel log | `adb shell "su -c 'dmesg \| grep -iE \"magisk\|avc\"'"` |

---

## Filesystem layout

| Path | Contents |
|---|---|
| `/data/adb/magisk/` | Magisk binaries |
| `/data/adb/magisk.db` | Root policy + settings + DenyList (SQLite) |
| `/data/adb/modules/` | Active modules |
| `/data/adb/modules_update/` | Staged for next boot |
| `/data/adb/post-fs-data.d/` | Standalone post-fs-data scripts |
| `/data/adb/service.d/` | Standalone late_start scripts |
| `/data/adb/magisk.log` | Runtime log |

---

## Module skeleton

```
mymodule/
├── module.prop           # id, name, version, versionCode, author, description
├── customize.sh          # install-time, inside the installer
├── post-fs-data.sh       # BLOCKING, before zygote — never hang here
├── service.sh            # non-blocking, late_start
├── boot-completed.sh     # after sys.boot_completed=1
├── uninstall.sh          # on removal
├── system.prop           # key=value applied via resetprop
├── sepolicy.rule         # magiskpolicy rules
├── skip_mount            # empty file: do not apply system/ overlay
├── disable               # empty file: module inert
├── remove                # empty file: delete next boot
├── zygisk/{arm64-v8a,armeabi-v7a,x86_64,x86}.so
└── system/...            # overlay tree mirrored onto /
```

```properties
id=mymodule
name=My Module
version=v1.0
versionCode=1
author=you
description=What it does.
```

| Task | Command |
|---|---|
| Package | `cd mymodule && zip -r ../mymodule.zip . -x '.*'` |
| Install | Magisk app → Modules → Install from storage |
| Install from shell | `adb shell "su -c 'magisk --install-module /sdcard/mymodule.zip'"` |
| Disable all modules | `adb shell "su -c 'touch /data/adb/modules/*/disable && reboot'"` |
| Safe mode | Hold Volume Down through boot (device-dependent) |

---

## Boot stages

| Stage | Blocking? | Framework up? | Use for |
|---|---|---|---|
| `post-fs-data` | Yes | No | File/mount/property setup |
| `late_start service` | No | Coming up | Anything needing the framework |
| `boot-completed` | No | Yes | Late fix-ups |

---

## magiskpolicy

| Task | Command |
|---|---|
| Apply live rule | `magiskpolicy --live "allow untrusted_app magisk_file file { read open }"` |
| Make a domain permissive | `magiskpolicy --live "permissive untrusted_app"` |
| Restore enforcing | `magiskpolicy --live "enforce untrusted_app"` |
| Apply a rule file | `magiskpolicy --live --apply /data/adb/modules/m/sepolicy.rule` |
| Read denials | `dmesg \| grep avc` or `adb logcat -b events \| grep avc` |

| Statement | Meaning |
|---|---|
| `allow S T C P` | Permit |
| `deny S T C P` | Remove permission |
| `auditallow S T C P` | Log allowed access |
| `dontaudit S T C P` | Suppress denial logs |
| `permissive D` / `enforce D` | Per-domain mode |
| `create D` | New domain |
| `genfscon FS PATH CTX` | Label a path |

---

## resetprop

| Task | Command |
|---|---|
| Read (including hidden) | `resetprop ro.boot.verifiedbootstate` |
| Write a `ro.` property | `resetprop ro.build.tags release-keys` |
| Delete | `resetprop --delete ro.boot.vbmeta.device_state` |
| Dump all | `resetprop` |

| Property | Stock value |
|---|---|
| `ro.boot.verifiedbootstate` | `green` |
| `ro.boot.flash.locked` | `1` |
| `ro.boot.vbmeta.device_state` | `locked` |
| `ro.build.tags` | `release-keys` |
| `ro.build.type` | `user` |
| `ro.debuggable` | `0` |
| `ro.secure` | `1` |
| `sys.oem_unlock_allowed` | `0` |

**Spoofing these does not affect Play Integrity.**

---

## Zygisk API (module native code)

| Callback / API | Runs as | Purpose |
|---|---|---|
| `onLoad(Api*, JNIEnv*)` | root (zygote) | Module init |
| `preAppSpecialize(AppSpecializeArgs*)` | root | Pre-UID-drop work |
| `postAppSpecialize(const AppSpecializeArgs*)` | app UID | In-app work |
| `preServerSpecialize` / `postServerSpecialize` | system | `system_server` hooks |
| `getFlags()` | — | `PROCESS_ON_DENYLIST`, etc. |
| `setOption(FORCE_DENYLIST_UNMOUNT)` | — | Request unmount for this process |
| `setOption(DLCLOSE_MODULE_LIBRARY)` | — | Unload the module `.so` after specialise |
| `connectCompanion()` | — | Socket to a root helper forked from `magiskd` |
| `getModuleDir()` | — | FD for the module directory |
| `hookJniNativeMethods()` | — | Replace JNI table entries |
| `pltHookRegister()` / `pltHookCommit()` | — | PLT/GOT hooking |

---

## DenyList

| Hides | Does not hide |
|---|---|
| Magisk bind mounts in that namespace | Play Integrity / hardware attestation |
| Magisk tmpfs mount points | Magisk Manager package (hide it separately) |
| `su` at overlaid paths | SELinux policy containing the `magisk` domain |
| Non-opted-in Zygisk modules | Real boot state signed by the TEE |
| — | Server-side verdicts |
| — | Behavioural / timing side channels |

| Task | Command |
|---|---|
| Confirm unmounted for a process | `adb shell "su -c 'grep -ic magisk /proc/$(adb shell pidof -s PKG)/mountinfo'"` |
| See what a process sees | `adb shell "su -c 'nsenter --mount=/proc/PID/ns/mnt -- ls -la /system/bin/su'"` |
| Compare namespaces | `adb shell "su -c 'ls -l /proc/PID/ns/mnt /proc/1/ns/mnt'"` |

---

## System CA certificate

```bash
# host
openssl x509 -inform DER -in cacert.der -out burp.pem -outform PEM
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
mkdir -p systemca/system/etc/security/cacerts
cp burp.pem "systemca/system/etc/security/cacerts/${HASH}.0"
```

| Android version | Trust store location |
|---|---|
| ≤ 13 | `/system/etc/security/cacerts/` |
| 14+ | `/apex/com.android.conscrypt/cacerts/` (Conscrypt APEX) |

Verify: `adb shell ls /system/etc/security/cacerts/ | wc -l` before and after.

---

## Magisk vs KernelSU vs APatch

| | Magisk | KernelSU | APatch |
|---|---|---|---|
| Privileged code | userspace daemon | kernel | kernel |
| Flash | patched `boot`/`init_boot` | KernelSU kernel image | patched kernel |
| Needs kernel source | No | Non-GKI: yes | Yes |
| Modules | Magisk format | own + OverlayFS | Magisk-compatible + KPM |
| Hiding | DenyList (unmount) | never mounted for app | kernel-side |
| Device breadth | widest | narrower | narrowest |

---

## Module audit before install

```bash
unzip -q module.zip -d /tmp/m
cat /tmp/m/module.prop
cat /tmp/m/customize.sh /tmp/m/post-fs-data.sh /tmp/m/service.sh 2>/dev/null
cat /tmp/m/sepolicy.rule /tmp/m/system.prop 2>/dev/null
find /tmp/m/system /tmp/m/zygisk -type f 2>/dev/null
grep -rnEi 'curl|wget|base64 -d|pm install|pm grant|settings put secure|/data/data/' /tmp/m
```

---

## Detecting Magisk on an image

| Indicator | Where |
|---|---|
| `.backup/` in ramdisk CPIO | Definitive: boot image patched |
| `overlay.d/` in ramdisk | Magisk overlay support |
| `/data/adb/magisk/` | Installed |
| `/data/adb/magisk.db` | Grant history (`sqlite3`) |
| `/data/adb/modules/*` | Installed modules |
| `/init` is not AOSP `init` | Patched |

```bash
magiskboot unpack boot.img
cpio -t < ramdisk.cpio | grep -E '^\.backup|^overlay\.d'
```
