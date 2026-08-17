# 06 — Android Architecture · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these is true.

---

## The stack, bottom up

```
┌──────────────────────────────────────────────┐
│ L6  Applications        UID 10000+           │
├──────────────────────────────────────────────┤
│ L5  Java framework      system_server UID 1000│
├──────────────────────────────────────────────┤
│ L4  ART runtime         (ch 11, 13)          │
├──────────────────────────────────────────────┤
│ L3  Native libraries    Bionic, Skia, media  │
├──────────────────────────────────────────────┤
│ L2  HAL                 Treble, VNDK, /vendor│
├──────────────────────────────────────────────┤
│ L1  Linux kernel        binder, ashmem, LMK  │
└──────────────────────────────────────────────┘
```

---

## Boot chain — the trust transitions

```
fuses → bootloader → vbmeta (AVB) → kernel → dm-verity
      → init → property_service → servicemanager
      → Zygote (preload, fork) → system_server → Launcher
```

| Transition | Asserted | Broken by |
|---|---|---|
| fuses → bootloader | OEM-signed bootloader | bootloader exploit |
| bootloader → vbmeta | boot/dtbo match signed hashes | **unlocked bootloader** |
| vbmeta → dm-verity | every block matches the signed Merkle root | `disable-verity` |
| init → services | each service has only its declared privilege | bad `.rc` entry |
| Zygote → app | irreversible drop to app UID + seccomp + SELinux | Zygote/kernel bug |
| app → system_server | caller UID is authoritative | confused deputy **in system_server** |

---

## `SpecializeCommon()` — where the sandbox is built

`frameworks/base/core/jni/com_android_internal_os_Zygote.cpp`, in order:

```
1. resource limits
2. setgroups()      ← supplementary GIDs (3003 = AID_INET = INTERNET perm)
3. setresgid() / setresuid()
4. capset()         ← drop capabilities
5. PR_SET_NO_NEW_PRIVS
6. seccomp-bpf filter
7. selinux_android_setcontext()  ← using seinfo from system_server
8. process nice name
9. mount namespace for external storage
```

Order matters: capabilities dropped and `NO_NEW_PRIVS` set **before** any app code runs.

---

## Security-relevant properties

```bash
for p in ro.build.fingerprint ro.build.type ro.build.tags ro.build.version.sdk \
         ro.build.version.release ro.build.version.security_patch ro.debuggable \
         ro.secure ro.adb.secure ro.boot.verifiedbootstate ro.boot.flash.locked \
         ro.boot.veritymode ro.crypto.state ro.crypto.type ro.product.cpu.abilist; do
  printf '%-40s %s\n' "$p" "$(getprop $p)"
done
getenforce
```

| Property | Good | Bad → severity |
|---|---|---|
| `ro.build.tags` | `release-keys` | `test-keys` → **CRITICAL** (public keys; anyone signs platform APKs) |
| `ro.debuggable` | `0` | `1` → **CRITICAL** (every app debuggable, `run-as` any package) |
| `ro.secure` | `1` | `0` → **CRITICAL** (adbd as root) |
| `ro.adb.secure` | `1` | `0` → HIGH (no host authorisation prompt) |
| `ro.build.type` | `user` | `userdebug`/`eng` → HIGH |
| `ro.boot.verifiedbootstate` | `green` | `orange` = unlocked, `yellow` = custom key, `red` = failed |
| `ro.boot.flash.locked` | `1` | `0` → HIGH |
| `ro.boot.veritymode` | `enforcing` | otherwise → HIGH |
| `getenforce` | `Enforcing` | `Permissive` → HIGH |
| `ro.crypto.state` | `encrypted` | `unencrypted` → HIGH |
| `persist.sys.usb.config` | — | contains `adb` on a kiosk → HIGH |

⚠️ On **your own** test device, unlocked bootloader / permissive SELinux / root are **methodology**,
not findings. Put them in Test Environment.

---

## Property service asymmetry

| | Read | Write |
|---|---|---|
| Path | `mmap` `/dev/__properties__` from libc | socket → `property_service` in `init` |
| Mechanism | prefix trie walk | `CheckPermissions()` + SELinux `property_service:set` |
| Can SELinux deny it? | **No** | **Yes** |

```bash
getprop -Z ro.debuggable        # show a property's SELinux context
setprop ctl.start <service>     # start an init service
setprop ctl.stop  adbd
```

Three read routes an app can use — a complete bypass must cover **all three**:
1. `SystemProperties.get()` (Java, `@hide`, reflection)
2. `__system_property_get()` (libc)
3. shelling out to `/system/bin/getprop`

---

## Partitions

| Partition | Mount | Verified by | Notes |
|---|---|---|---|
| `boot`, `init_boot`, `vendor_boot`, `dtbo` | — | AVB | kernel + ramdisks |
| `vbmeta`, `vbmeta_system` | — | root key in fuses | the signed hashes |
| `super` | — | AVB per logical | container for the below |
| `system` (logical) | `/`, `/system` | dm-verity | AOSP framework |
| `system_ext`, `vendor`, `odm`, `product` | resp. | dm-verity | **OEM code lives here** |
| `userdata` | `/data` | **NOT verity** (FBE-encrypted) | writable by root |
| `metadata` | `/metadata` | — | encryption metadata |
| `persist` | `/persist` | **often neither** | calibration, sometimes keys |
| `misc` | — | — | bootloader control block |

```bash
ls -l /dev/block/by-name/
lpdump                       # dynamic partition layout (root)
ls -l /dev/block/mapper/     # logical partitions as dm devices
getprop ro.boot.slot_suffix  # _a or _b
mount | grep -E ' /(system|vendor|product|odm) '
```

---

## dm-verity

- Merkle tree over 4 KiB blocks; signed root; verified **on read**
- **Whole-partition granularity** — you cannot change one file in `/system`
- Tamper-**evident**, not tamper-preventing at rest
- `fs-verity` = the per-file equivalent for `/data` (installed APKs)

```bash
adb root && adb disable-verity && adb reboot && adb root && adb remount
# requires an UNLOCKED bootloader
```

Magisk uses overlays precisely because it cannot modify verity-protected blocks.

---

## Mainline / APEX

```bash
ls /apex/
cmd package list packages --apex-only
getprop ro.build.version.security_patch                                  # patch level 1
cmd package dump com.google.android.modulemetadata | grep -m1 versionName # patch level 2
```

**Record BOTH patch levels.** Modularised components are the historic remote surfaces: ART, Conscrypt
(TLS), media/codecs, DNS resolver, network stack, Bluetooth, Wi-Fi, permission controller.

Consequences: Mainline exploits have short lives; **vendor** component exploits last years; and two
devices on the same Android release can differ in runtime internals.

---

## Recovery vs fastboot

| | Recovery | Fastboot / bootloader |
|---|---|---|
| Running | minimal Linux + Android userspace | the bootloader (or `fastbootd`) |
| Kernel? | yes | only for `fastbootd` |
| Enter | `adb reboot recovery` | `adb reboot bootloader` |
| Protocol | `adb sideload` | fastboot USB |
| Does | apply OTA, factory reset, wipe | unlock, flash, boot, getvar |

```bash
adb reboot recovery
adb reboot bootloader
adb reboot fastboot              # fastbootd — needed for dynamic partitions
fastboot getvar all
fastboot boot patched_boot.img   # ⚠️ ALWAYS test with 'boot' before 'flash'
```

---

## Process / privilege inspection

```bash
ps -A -o USER,PID,NAME
ps -A -Z                                    # with SELinux domains
ps -A -Z | awk '{print $1}' | sed 's/:s0.*//' | sort | uniq -c | sort -rn

PID=$(pidof -s com.example.target)
cat /proc/$PID/status | grep -E 'Uid|Gid|Groups|CapEff|Seccomp|NoNewPrivs'
cat /proc/$PID/attr/current
```

| Field | Expected for an app |
|---|---|
| `Uid` | 10000+ |
| `Groups` | includes 3003 if it has INTERNET |
| `CapEff` | `0000000000000000` — anything else is anomalous |
| `Seccomp` | `2` (filter) — `0` means not Zygote-spawned normally |
| `NoNewPrivs` | `1` |
| context | `u:r:untrusted_app_XX:s0:cNNN,cNNN` |

| UID | Layer |
|---|---|
| `root` | init, ueventd, vold, vendor daemons |
| `system` (1000) | system_server |
| `shell` (2000) | adbd, your shell — **not an app** |
| `media*`, `cameraserver`, `bluetooth`, `radio` | native services |
| `u0_aNNN` | apps |
| `u0_iNNN` | isolated processes |

---

## Boot analysis

```bash
adb reboot && adb wait-for-device
adb logcat -b all -d > boot.log
grep -nE "Starting service 'zygote'|Zygote: Preloading|SystemServer|Boot is finished" boot.log
dmesg | grep -iE "verity|avb|selinux|binder"
```

---

## Firmware offline

```bash
unzip factory-image.zip && tar xvf image-*.tar.gz
magiskboot unpack boot.img && cpio -idmv < ramdisk.cpio   # default.prop lives here
lpunpack super.img out/
sudo mount -o loop,ro out/system.img /mnt/system
python3 external/avb/avbtool.py info_image --image vbmeta.img
```

### The init `.rc` audit — highest-value static check

```bash
grep -rhA10 '^service ' /system/etc/init/ /vendor/etc/init/ \
  | grep -E '^service |user |group |capabilities |seclabel |socket '
```

| Pattern | Concern |
|---|---|
| no `user` line | runs as **root** by default |
| broad `capabilities` | more than needed |
| `socket ... 0666` | **any app** can connect — outside the permission model |
| missing `seclabel` | may land in an over-permissive domain |

---

## Chapter scripts

| Script | Use |
|---|---|
| `scripts/device-posture.sh` | Trust posture with per-row verdicts; `--test-device` suppresses your own rooting |
| `scripts/layer-census.sh` | Processes by layer + anomaly checks; `--pkg <name>` for a deep dive |
| `scripts/firmware-triage.sh` | Offline image audit: init privileges, priv-apps, APEX, AVB |

---

## Where findings actually live

On an OEM device, **not** in AOSP:

1. `/vendor` and `/odm` daemons running as root
2. Pre-installed privileged apps in `/system/priv-app`
3. Init `.rc` entries with no `user` line or broad capabilities
4. World-accessible sockets (`0666`) and localhost listeners
5. `privapp-permissions-*.xml` grants

---

## Rules

1. `ro.build.tags=test-keys` is **critical** — the keys are public.
2. Record **two** patch levels: platform and Play system update.
3. `fastboot boot` before `fastboot flash`. Always.
4. Your own unlocked bootloader is **methodology**, not a finding.
5. The real boundary is the kernel — UID, seccomp, SELinux. Not the runtime.
6. `userdata` is encrypted but **not** verity-protected.
7. SELinux can deny property writes, never reads.
8. Zygote forks without exec → shared address-space layout until reboot.
9. On OEM devices, audit `/vendor` before AOSP.
10. An init service with no `user` line runs as root.
