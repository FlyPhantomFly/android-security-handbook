# Lab 03 — Audit a Firmware Image

**Difficulty:** Advanced
**Time:** 3–4 hours
**Prerequisites:** [Lab 02](lab-02-map-the-layers.md), [Chapter 06 §3.11, §8](../README.md),
a Linux host (or WSL/VM) with loop-mount support

---

## Objective

Take a factory firmware image, unpack it completely, and audit it offline: build configuration, init
service privilege budgets, privileged application inventory, AVB descriptors and SELinux policy. Then
produce the assessment you would deliver to a device manufacturer.

## Why this matters

Device assessments happen without the device more often than you would expect. A vendor sends an image
for review before shipping; you inherit a firmware dump from a colleague; the physical device is in
another country.

More importantly, offline analysis is **more thorough**. On a running device you see what is running.
In an image you see everything that *could* run — including services that only start under conditions
you have not triggered.

---

## Setup

You need a factory image. Legitimate sources:

| Source | Notes |
|---|---|
| [Google Pixel factory images](https://developers.google.com/android/images) | Freely downloadable, well-formed, ideal for this lab |
| [Android GSI / AOSP builds](https://developer.android.com/topic/generic-system-image/releases) | Clean AOSP baseline — good for comparison |
| Your own AOSP build | See [07-AOSP](../../07-AOSP/README.md) |
| A vendor image you are authorised to analyse | Real-world vendor content |

> **⚠️ Warning**
> Only analyse images you are authorised to analyse. Manufacturer firmware is copyrighted, and some
> licences restrict reverse engineering. Pixel factory images and AOSP builds are unambiguous; a
> leaked vendor image is not. When in doubt, use a Pixel image for the lab and apply the technique to
> authorised targets.

### Tools

```bash
# host
sudo apt install -y python3 unzip cpio file
# boot image tooling
git clone https://github.com/topjohnwu/Magisk    # magiskboot
# or
git clone https://github.com/cfig/Android_boot_image_editor
# super.img unpacking
# lpunpack from AOSP, or https://github.com/LonelyFool/lpunpack_and_lpmake
# AVB
git clone https://android.googlesource.com/platform/external/avb
```

---

## Steps

### Step 1 — Unpack the outer layers

```bash
# host
unzip <device>-<build>-factory-*.zip
cd <device>-<build>
ls -la
unzip image-<device>-<build>.zip -d image/
ls -la image/
```

**Q1.** What partition images are present? Match each against the table in §3.11.1 of the chapter.
Which are missing, and what does their absence tell you about the device's generation?

### Step 2 — The boot image

```bash
# host
cd image
magiskboot unpack boot.img
ls -la          # kernel, ramdisk.cpio, dtb, ...
mkdir ramdisk && cd ramdisk
cpio -idmv < ../ramdisk.cpio 2>/dev/null
ls -la
```

**Q2.** What is in the ramdisk? Find `init`, the `.rc` files, and the property defaults.

```bash
# host — the properties that are NOT in /system/build.prop
cat default.prop prop.default 2>/dev/null | grep -E 'debuggable|secure|adb'
```

**Q3.** What are `ro.debuggable`, `ro.secure` and `ro.adb.secure`? Why is checking here essential
rather than only reading `/system/build.prop`?

```bash
# host — the first-stage init scripts
ls *.rc
cat init.rc | head -60
```

**Q4.** Which `.rc` files ship in the ramdisk versus on `/system`? What runs first?

### Step 3 — Unpack super.img

```bash
# host
cd ..
lpunpack super.img out/
ls -la out/
```

**Q5.** Which logical partitions came out? Compare against §3.11.3.

```bash
# host — mount them read-only
sudo mkdir -p /mnt/{system,vendor,product,system_ext,odm}
sudo mount -o loop,ro out/system.img     /mnt/system
sudo mount -o loop,ro out/vendor.img     /mnt/vendor
sudo mount -o loop,ro out/product.img    /mnt/product 2>/dev/null
sudo mount -o loop,ro out/system_ext.img /mnt/system_ext 2>/dev/null
ls /mnt/system
```

> **Note.** Some images use `erofs` rather than `ext4`. If the mount fails, check with
> `file out/system.img` and install `erofs-utils` (`fsck.erofs --extract`).

### Step 4 — Build configuration

```bash
# host
for f in /mnt/system/system/build.prop /mnt/vendor/build.prop /mnt/product/etc/build.prop; do
  [ -f "$f" ] && echo "=== $f" && grep -E '^ro\.(build\.(fingerprint|type|tags|version)|product|debuggable|secure)' "$f"
done
```

**Q6.** Record the fingerprint, build type, tags and security patch level. Any of them concerning?

**Q7.** Compare the `system` and `vendor` fingerprints. Do they match? What does a mismatch mean for
Treble?

### Step 5 — THE INIT SERVICE AUDIT

This is the highest-value part of the lab.

```bash
# host
find /mnt/system/system/etc/init /mnt/vendor/etc/init /mnt/product/etc/init -name '*.rc' 2>/dev/null | wc -l
```

```bash
# host — extract every service with its privilege budget
awk '
  /^service /   { if (svc) emit(); svc=$2; bin=$3; usr="root(DEFAULT)"; cap=""; sec=""; sock="" }
  /^[ \t]+user /        { usr=$2 }
  /^[ \t]+capabilities/ { $1=""; cap=substr($0,2) }
  /^[ \t]+seclabel /    { sec=$2 }
  /^[ \t]+socket /      { sock=sock" "$2"("$4")" }
  END { if (svc) emit() }
  function emit() { printf "%-14s %-30s %-40s cap=[%s] sec=[%s] sock=[%s]\n", usr, svc, bin, cap, sec, sock }
' $(find /mnt/system/system/etc/init /mnt/vendor/etc/init -name '*.rc' 2>/dev/null) | sort
```

**Q8.** How many services run as root? How many have **no `user` line at all** (and therefore run as
root by default)?

**Q9.** Which services declare `capabilities`? For each, is the capability set justified by what the
service appears to do?

**Q10.** Any `socket` declarations with mode `0666` or `0777`?

```bash
# host — the world-accessible socket check
grep -rhE '^[ \t]+socket .*0(6|7)(6|7)(6|7)' \
  /mnt/system/system/etc/init /mnt/vendor/etc/init 2>/dev/null
```

**Q11.** For each hit, read the whole service block. What does the daemon do? Could an ordinary app
usefully talk to it? This is the finding shape described in §9.4 of the chapter.

### Step 6 — Privileged applications

```bash
# host
find /mnt/system/system/priv-app -name '*.apk' 2>/dev/null | wc -l
find /mnt/product/priv-app -name '*.apk' 2>/dev/null | wc -l
find /mnt/vendor/app /mnt/vendor/priv-app -name '*.apk' 2>/dev/null | wc -l
```

**Q12.** How many privileged apps are there? Which are AOSP and which are vendor additions?

```bash
# host — which packages get privileged permissions, and which?
cat /mnt/system/system/etc/permissions/privapp-permissions-*.xml 2>/dev/null \
  | grep -E '<privapp-permissions package|<permission name' | head -60
```

**Q13.** Pick the three most interesting vendor privileged apps. For each, extract it and run the
[32-Manifest](../../32-Manifest/README.md) audit:

```bash
# host
cp /mnt/vendor/priv-app/SomeApp/SomeApp.apk .
aapt2 dump xmltree SomeApp.apk --file AndroidManifest.xml | grep -A3 -E 'exported|permission'
```

Any exported components? Any that perform privileged actions?

### Step 7 — AVB descriptors

```bash
# host
python3 avb/avbtool.py info_image --image vbmeta.img
```

**Q14.** Record: the signing algorithm, the rollback index, and the descriptors present. Is the
`--flags` field set to disable verification?

```bash
# host — check each chained partition
python3 avb/avbtool.py info_image --image vbmeta.img | grep -A5 "Chain Partition"
python3 avb/avbtool.py info_image --image boot.img
```

**Q15.** Which partitions have hashtree descriptors (verity) and which have hash descriptors? Why the
difference?

### Step 8 — SELinux policy

```bash
# host
ls -la /mnt/system/system/etc/selinux/
ls -la /mnt/vendor/etc/selinux/
wc -l /mnt/system/system/etc/selinux/plat_property_contexts 2>/dev/null
wc -l /mnt/vendor/etc/selinux/vendor_property_contexts 2>/dev/null
```

**Q16.** How much vendor policy is there relative to platform policy? A large vendor policy is not
inherently bad, but it is a large amount of security-relevant configuration written by the party with
the least review.

```bash
# host — vendor domains that look permissive
grep -rhE 'permissive ' /mnt/vendor/etc/selinux/*.cil 2>/dev/null | head
```

**Q17.** Any `permissive` domains in vendor policy? Each is a domain where SELinux logs but does not
block.

### Step 9 — Run the script

```bash
# host
../scripts/firmware-triage.sh /mnt/system /mnt/vendor /mnt/product
```

**Q18.** Does the automated output match your manual findings? What did it catch that you missed?

### Step 10 — Write the assessment

Produce a device-manufacturer-facing report:

1. **Build configuration** — fingerprint, type, tags, patch level, and any concerns
2. **Init service privilege** — every root service, every capability grant, every world-accessible
   socket, with a justification assessment for each
3. **Privileged applications** — inventory, permission grants, and any exported components found
4. **Boot integrity** — AVB configuration, rollback index, verity coverage
5. **SELinux** — vendor policy size, any permissive domains
6. **Prioritised recommendations**

**Q19.** For each concern, state the **threat model**: who is the attacker, what access do they start
with, and what do they gain? A concern without a threat model is an observation, not a finding.

**Q20.** Which of your concerns would you rate High, and can you defend that rating against a vendor
who pushes back?

---

## Hints

<details>
<summary>Hint 1 — lpunpack is not available</summary>

Options, in order of convenience:

```bash
# From an AOSP checkout
m lpunpack && out/host/linux-x86/bin/lpunpack super.img out/

# Prebuilt
# https://github.com/LonelyFool/lpunpack_and_lpmake

# Python alternative
pip install --user android-tools  # varies by distro
```

If the image is an OTA `payload.bin` rather than a factory image, use
[payload-dumper-go](https://github.com/ssut/payload-dumper-go) first.
</details>

<details>
<summary>Hint 2 — mount fails with "wrong fs type"</summary>

```bash
file out/system.img
```

If it says `erofs`, install `erofs-utils` and extract rather than mount:
```bash
fsck.erofs --extract=/mnt/system out/system.img
```

If it says "Android sparse image", convert first:
```bash
simg2img out/system.img system_raw.img
sudo mount -o loop,ro system_raw.img /mnt/system
```
</details>

<details>
<summary>Hint 3 — the awk service parser misses services</summary>

Vendor `.rc` files sometimes use tabs, sometimes spaces, and sometimes put options on the same line.
Sanity-check the count:

```bash
grep -rhc '^service ' /mnt/vendor/etc/init/*.rc | paste -sd+ | bc
```

Compare against your parser's output count. If they differ, read a few files by hand and adjust.
</details>

<details>
<summary>Hint 4 — magiskboot is not built</summary>

Alternatives that need no compilation:

```bash
# Android_boot_image_editor (needs Java)
./gradlew unpack

# Or the simple approach for many images
python3 -c "
import sys
d=open('boot.img','rb').read()
i=d.find(b'\x1f\x8b')          # gzip magic — the ramdisk
open('ramdisk.gz','wb').write(d[i:])
"
gunzip -c ramdisk.gz | cpio -idmv
```
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1.** A modern device shows `boot.img`, `init_boot.img` (Android 13+), `vendor_boot.img`,
`dtbo.img`, `vbmeta*.img` and `super.img`. The absence of separate `system.img`/`vendor.img` at the
top level means dynamic partitions — they are inside `super`. The absence of `recovery.img` means an
A/B device where recovery lives in `boot`.

**Q3.** `ro.debuggable` and `ro.secure` are set in the **boot ramdisk's** `default.prop` (or
`prop.default`), not in `/system/build.prop`. An audit that only reads `/system/build.prop` will miss
them entirely — which is precisely why this step exists and why the chapter's script prints a warning
about it.

**Q7.** A `system` and `vendor` fingerprint mismatch is normal and expected under Treble — that is the
whole point of the split. It becomes interesting when the vendor image is much older than the system
image, which can indicate a GSI on top of stale vendor code with unpatched HALs.

**Q8–Q11.** The root-service count and the capability grants are the core output. A service with **no
`user` line runs as root** — that default is the single most common privilege mistake in vendor init
files. A `0666` socket is reachable by every app on the device, entirely outside the framework
permission model; if the daemon behind it performs privileged operations on request, any app can ask
it to. See [24-IPC](../../24-IPC/README.md).

**Q14–Q15.** `boot` gets a **hash** descriptor (the whole image is hashed once, verified at load).
`system`/`vendor`/`product` get **hashtree** descriptors (a Merkle tree, verified per-block on read)
because they are large read-only filesystems mounted for the device's lifetime. A `--flags 2` value
means verification is disabled, which on a production image would be a critical finding.

**Q17.** A `permissive` domain in vendor policy means SELinux logs violations for that domain but does
not block them. It is sometimes a legitimate staging state during development; on a shipping image it
removes MAC enforcement for whatever runs in that domain, and is worth reporting.

**Q19–Q20.** The threat model is what turns an observation into a finding. "A vendor daemon runs as
root" alone is an observation. "A vendor daemon runs as root, exposes a `0666` socket, and accepts a
command that writes to an arbitrary path — so any installed app achieves arbitrary file write as root"
is a High finding with a defensible rating. If you cannot articulate the attacker and the gain, it is
a note, and reporting it as more damages your credibility.

</details>

---

## Success criteria

- [ ] You unpacked the factory image down to individual logical partitions
- [ ] You extracted the boot ramdisk and read `default.prop` — not just `/system/build.prop`
- [ ] You produced a complete init service table with user, capabilities, seclabel and sockets
- [ ] You identified every service with no `user` line and can explain why that matters
- [ ] You found any world-accessible sockets and assessed what the daemon behind each does
- [ ] You inventoried privileged apps and cross-referenced the `privapp-permissions` grants
- [ ] You audited at least three vendor privileged APKs for exported components
- [ ] You read the AVB descriptors and can explain hash vs hashtree
- [ ] You assessed vendor SELinux policy size and checked for permissive domains
- [ ] Your manual findings agree with `firmware-triage.sh`
- [ ] Every concern in your report has an explicit threat model, and you can defend each severity
