# Lab 02 — Dissecting vbmeta, and catching a phone in a lie

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Chapter:** [20 — Security Architecture](../README.md) §3.1, §3.2, §4.1, §6.5
**Prerequisites:** [Lab 01](lab-01-device-posture.md) — you need its posture record and, in
particular, its cmdline-versus-property comparison. Python 3.7+. A device you own, ideally rooted.
**Reading:** [§3.1 Verified Boot and AVB 2.0](../README.md#31-verified-boot-and-android-verified-boot-20-avb),
[§3.2 dm-verity](../README.md#32-dm-verity--integrity-for-partitions-too-large-to-hash-at-boot),
[§6.5 reading the platform's own artefacts](../README.md#65-reading-the-platforms-own-artefacts).
**Tool:** [`../scripts/parse-vbmeta.py`](../scripts/parse-vbmeta.py) — ships with this chapter,
standard library only, no `avbtool` and no network required.

---

## Objective

Open a real `vbmeta` blob, enumerate every AVB descriptor inside it, follow the chain to a second
vbmeta, locate the dm-verity root hashes, and correlate all of it against what the running device
reports.

Then do the thing that turns this from an anatomy lesson into a technique: **take one hash
descriptor and check it against the actual partition.** On the device this lab was written against,
that single comparison proved the boot image had been modified — on a phone whose properties claim
`verifiedbootstate=green` and `flash.locked=1`.

## Why this lab exists

Almost nobody who talks about Verified Boot has ever opened a vbmeta blob. Doing it once removes the
mystery permanently. You discover that it is a small signed structure — a 256-byte header followed
by a packed list of tagged records — containing hashes, a few strings, and nothing magical. Every
claim anyone makes about AVB afterwards becomes checkable.

It also teaches the one skill that makes device-integrity work honest. Lab 01 showed you a property
that lies. It did **not** show you a way to establish the truth without a TEE. This lab does:
`vbmeta` is a signed statement of what every partition *should* hash to, and partitions are readable
block devices. Anyone with root can therefore verify the boot chain **from the outside**, with `dd`
and `sha256sum` — no attestation, no Play Integrity, no vendor cooperation.

> **Mental Model**
> Think of `vbmeta` as a **manifest**, in the shipping sense: a signed list saying "the crate marked
> `boot` weighs exactly this much and its seal reads exactly this". The bootloader is the customs
> officer who checks the manifest against the crates. On an unlocked device that officer has gone
> home — but **the manifest is still on the crate**, and you can do the check yourself. That is the
> whole lab.

---

## Setup

### Which image to work on

Three routes. Pick the first one that is available to you.

**Route A — pull it off your own device (preferred; needs root).**
This is the best route because everything you find can be correlated against a live system, and
because it is the only route where the partition contents are available for the hash check in
Step 6. The reads are non-destructive: `dd` from a block device to a file.

```bash
# adb shell — dump the top-level vbmeta. 128 KiB is more than enough;
# the structure is a few kilobytes and the rest of the partition is padding.
su -c 'dd if=/dev/block/by-name/vbmeta of=/data/local/tmp/vbmeta.img bs=4096 count=32'
```
```bash
# host
adb pull /data/local/tmp/vbmeta.img
adb shell "su -c 'rm -f /data/local/tmp/vbmeta.img'"
```

> **Warning**
> `dd` **to** a block device destroys a phone. Every `dd` in this lab has the block device as `if=`
> (input) and a file as `of=` (output). Read the direction of every `dd` you type here twice, and
> never copy one from a forum post without doing so. There is no undo.

**Route B — a factory image.** Download a Pixel factory image from Google's official page, unzip it,
then unzip the inner `image-*.zip` to obtain `vbmeta.img`, `boot.img`, `dtbo.img` and the rest. This
gives you a *pristine* vbmeta, which is the perfect control: compare it against Route A's and any
difference is tampering.

**Route C — the emulator.** `$ANDROID_HOME/system-images/…/vbmeta.img` exists on most images.
Emulator vbmeta is structurally reduced — few descriptors, often unsigned — and Steps 5–7 will not
work, but Steps 1–4 will.

> **Only work with images for devices you own, obtained from the manufacturer.** Redistributing
> OEM firmware is frequently a licence violation, and pulling firmware off a device you do not own
> is a different problem entirely.

### The tool

The canonical tool is `avbtool`, from AOSP:

```bash
# host — the reference tool, if you have network access
git clone --depth 1 https://android.googlesource.com/platform/external/avb
python3 avb/avbtool.py info_image --image vbmeta.img
```

This chapter also ships [`../scripts/parse-vbmeta.py`](../scripts/parse-vbmeta.py), which needs
neither the clone nor the network, prints the **file offset** of every descriptor alongside its
contents, and refuses to imply that parsing is verifying. Use it for the lab and `avbtool` to
cross-check if you have it.

```bash
# host
python3 -B ../scripts/parse-vbmeta.py vbmeta.img
```

---

## Steps

### Step 1 — Dump the top-level vbmeta and read the header

```bash
# host
python3 -B ../scripts/parse-vbmeta.py vbmeta.img
```

Measured output from the Redmi `M2101K6P` (`sweetin`, MIUI 12.5, Android 11):

```text
Header
  Magic                        : AVB0
  Required libavb version      : 1.0
  Authentication block size    : 320 bytes
  Auxiliary block size         : 3200 bytes
  Algorithm                    : SHA256_RSA2048   (SHA-256 digest, RSA-2048 PKCS#1 v1.5 signature)
  Public key size              : 520 bytes
  Rollback Index               : 0
  Rollback Index Location      : 0
  Flags                        : 0x0
  Release String               : 'avbtool 1.1.0'

Descriptors: 16
```

Record four things and be able to defend each:

1. **Algorithm.** `SHA256_RSA2048` here. Google's own devices use `SHA256_RSA4096`. RSA-2048 is not
   broken, but it is the weaker end of what AVB supports, and it is a defensible line in a report
   about an OEM's platform posture. Note the digest and the signature are separate choices —
   `SHA512_RSA2048` exists too.
2. **Rollback Index** and **Rollback Index Location.** Both `0`. Location `0` means this vbmeta's
   counter occupies slot 0 of the device's rollback storage; index `0` means **no anti-rollback
   protection is in effect for this image** — any signed image with index ≥ 0 is acceptable, which
   is all of them. Come back to this at Step 8.
3. **Flags.** `0x0`. Two bits matter and both are absent here:
   `AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED` (0x1) and
   `AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED` (0x2). A vbmeta with 0x2 set asks the bootloader
   to verify nothing. That is exactly what `fastboot --disable-verification flash vbmeta` writes,
   and finding it set on a device presented as stock is a complete finding on its own.
4. **Release String.** `avbtool 1.1.0` — the tool version that *built* the image. Free build-process
   intelligence, and occasionally the thing that dates an OEM's toolchain.

> **Under the Hood — the layout, so the offsets stop being magic**
> A vbmeta image is three blocks in a fixed order:
>
> | Block | Contents |
> |---|---|
> | Header, 256 bytes, **big-endian** | Magic `AVB0`, versions, the sizes and offsets of everything below, rollback index, flags, release string |
> | Authentication block (320 bytes here) | The SHA-256 hash of the auxiliary block, then the RSA signature over it |
> | Auxiliary block (3200 bytes here) | The public key, then the descriptor list |
>
> Every descriptor starts with an 8-byte tag and an 8-byte `num_bytes_following`, and is padded to an
> 8-byte boundary. That uniform prefix is why a five-year-old bootloader can skip a descriptor type
> invented last year instead of failing. It is also why a parser is 200 lines rather than 2000 —
> run the script with `--hex` to see the header with the field boundaries marked.

### Step 2 — Classify every descriptor

Read the full descriptor list and sort each entry into one of the five types from
[§3.1](../README.md#31-verified-boot-and-android-verified-boot-20-avb).

Measured on the same device — 16 descriptors, abbreviated:

```text
  [0] Chain Partition descriptor   (tag 4, at file offset 0x240)
      Partition Name          : vbmeta_system
      Rollback Index Location : 2
      Public key size         : 520 bytes
      Public key SHA-1        : cdbb77177f731920bbe0a0f94f84d9038ae0617d

  [1] Property descriptor   (tag 0, at file offset 0x4b8)
      Key                     : com.android.build.vendor.fingerprint
      Value                   : Redmi/sweetin/sweetin:11/RKQ1.200826.002/V12.5.10.0.RKFINXM:user/release-keys

  [3] Property descriptor
      Key                     : com.android.build.vendor.security_patch
      Value                   : 2021-12-01

  [9] Property descriptor
      Key                     : com.android.build.odm.fingerprint
      Value                   : Redmi/sweetin/sweetin:11/RKQ1.200826.002/V12.5.10.0.RKFINXM:user/test-keys

  [12] Hash descriptor   (tag 2, at file offset 0x948)
      Partition Name          : boot
      Image Size              : 21880832 bytes
      Hash Algorithm          : sha256
      Salt                    : 4d6bf69daa8e967133b5cc96e9d62415b1e09b7bd7ca2ba7ccf97533b47021b8
      Digest                  : 9895a0e21db8565ddd295e125b6613f62de390c22e9063748487f6e0c01b7b70

  [13] Hash descriptor   (tag 2, at file offset 0xa10)
      Partition Name          : dtbo
      Image Size              : 6384882 bytes
      Hash Algorithm          : sha256
      Salt                    : a3bd202a5b395c922d2ce5b4af3441cfd91d68ed223fb6111e49854adbaf771d
      Digest                  : d55683f396142fc350a25eda2a261ee255285a57dbecadbd877aa4bfe9170c7c

  [14] Hashtree descriptor   (tag 1, at file offset 0xad8)
      Partition Name          : odm
      Image Size              : 1024000 bytes      Data Block Size : 4096
      Hash Algorithm          : sha1
      Root Digest             : 102ea7ac70478c43c2e586b959caeeeed1fec472

  [15] Hashtree descriptor   (tag 1, at file offset 0xbc8)
      Partition Name          : vendor
      Image Size              : 1430822912 bytes   Data Block Size : 4096
      Hash Algorithm          : sha1
      Root Digest             : 4c56a6a83f3ac349c7a19914e78acbfe3c3dcc48
```

**Answer these before moving on.**

- **Why does `boot` get a Hash descriptor and `vendor` a Hashtree descriptor?** Because `boot` is
  21 MB and the bootloader must load all of it anyway, so hashing it whole costs nothing extra.
  `vendor` is 1.4 GB; hashing it at boot would add minutes to every start-up. A hashtree lets the
  kernel verify each 4 KiB block **as it is read**, paying only for the blocks actually touched. The
  choice is a performance decision, not a security one — both give the same guarantee. See
  [§3.2](../README.md#32-dm-verity--integrity-for-partitions-too-large-to-hash-at-boot).
- **Why is the hashtree algorithm `sha1` while the hash descriptors use `sha256`?** Because the
  hashtree's collision resistance is not what protects you — the *root digest* is covered by the
  vbmeta signature, and an attacker who could find a SHA-1 collision for a specific 4 KiB block
  still cannot re-sign the vbmeta. It is a speed choice, made per block, millions of times. It is
  still worth a line in a report as a hygiene observation, phrased as *hygiene*, not as a break.
- **What is descriptor [9] telling you?** Every other fingerprint in this image ends `release-keys`.
  The `odm` one ends **`test-keys`**. On a shipping retail device. That is a real observation from a
  real phone: some partition in this build was signed with AOSP's public test keys. Note it, and
 you found it by reading a structure most testers never open.

> **Pentester's Note — property descriptors are free reconnaissance.**
> This image carries the vendor, boot, odm and dtbo fingerprints, OS versions and security patch
> levels **inside the signed structure**. Those cannot be edited by a root module the way
> `ro.build.*` can, because editing them invalidates the signature. So if `getprop` and the vbmeta
> property descriptors disagree about the security patch level, `getprop` is the one lying. That is a
> second, independent cross-check to add to Lab 01's cmdline comparison.

### Step 3 — Follow the chain

Descriptor [0] is a **Chain Partition descriptor**: instead of carrying `system`'s hashtree itself,
this vbmeta delegates to `vbmeta_system`, which has **its own public key and its own rollback index
location** (2, here — not 0).

The parser tells you exactly what to run next:

```text
This vbmeta CHAINS to 1 other partition(s). Parse each of them
too -- each has its own key and its own rollback index:
    adb shell "su -c 'dd if=/dev/block/by-name/vbmeta_system of=/data/local/tmp/vbmeta_system.img'"
    python3 -B ../scripts/parse-vbmeta.py vbmeta_system.img
```

Measured result — 14 more descriptors:

```text
Header
  Algorithm                    : SHA256_RSA2048
  Rollback Index               : 0
  Release String               : 'avbtool 1.1.0'

Descriptors: 14
  [0]  Property   com.android.build.product.fingerprint
                  qti/qssi/qssi:11/RKQ1.200826.002/V12.5.10.0.RKFINXM:user/test-keys
  [4]  Property   com.android.build.system.fingerprint
                  qti/qssi/qssi:11/RKQ1.200826.002/V12.5.10.0.RKFINXM:user/release-keys
  [8]  Property   com.android.build.system_ext.fingerprint
                  qti/qssi/qssi:11/RKQ1.200826.002/V12.5.10.0.RKFINXM:user/test-keys
  [11] Hashtree   product      1485168640 bytes  sha1  root 010afa311700e224daafbf69cc5dd2af7cde6174
  [12] Hashtree   system       2853302272 bytes  sha1  root 700d658a55ff49922cf4c651b435c7047e1df9ca
  [13] Hashtree   system_ext    464105472 bytes  sha1  root 700d... (see your own output)
```

Two things to write down.

**Why Treble made this split necessary.** Before Treble, one vendor built and signed the whole
image, so one vbmeta with one key was enough. Treble separates the OS (`system`, `system_ext`,
`product`) from the hardware support (`vendor`, `odm`), so that the SoC vendor's partitions and the
OEM's OS can ship on independent schedules — and be signed by *different parties*. A chain partition
descriptor is what makes independent signing possible: the top-level vbmeta commits to the *key*
that will sign `vbmeta_system`, not to `vbmeta_system`'s contents. The OS half can be re-signed and
re-shipped without re-signing the vendor half.

Note the fingerprints confirm it: the top-level vbmeta's partitions say `Redmi/sweetin`, while the
chained one's say `qti/qssi` — Qualcomm's generic system image. Two builders, two trees, one device.

**And the separate rollback index location matters** for the same reason: the OS half must be able
to advance its anti-rollback counter without touching the vendor half's.

### Step 4 — Read the dm-verity parameters

A hashtree descriptor contains, directly, the fields of a device-mapper verity table:

```
<version> <data_dev> <hash_dev> <data_block_size> <hash_block_size>
<num_data_blocks> <hash_start_block> <algorithm> <root_hash> <salt>
```

Compare against `system`'s descriptor: version 1, data block size 4096, hash block size 4096,
algorithm `sha1`, root digest `700d658a55ff49922cf4c651b435c7047e1df9ca`, plus the salt. Everything
the kernel needs is here.

**That root digest is the top of the Merkle tree from [§3.2](../README.md#32-dm-verity--integrity-for-partitions-too-large-to-hash-at-boot).**
2,853,302,272 bytes of `system` — 696,607 blocks of 4 KiB — reduce to those 20 bytes. Change one
byte anywhere in `system` and the root digest changes, which is why the tree exists and why it can
be checked lazily.

> **Warning — your device may have no `Kernel Cmdline descriptor` at all, and mine does not.**
> Many write-ups tell you to find a descriptor whose value begins `dm="` and parse the verity table
> out of it. On this device there is **no kernel-cmdline descriptor in either vbmeta** — the dm
> parameters come from the hashtree descriptors directly and `init` assembles the table. Do not
> conclude your dump is broken. Count your descriptor types, and if there is no tag-3 descriptor,
> read the tag-1 ones instead; they hold the same values in structured form, which is easier.

### Step 5 — Correlate with the running device

Everything so far came off a partition image. Now check it against the live system.

```bash
# adb shell
getprop ro.boot.vbmeta.digest
getprop ro.boot.veritymode
su -c 'cat /proc/cmdline' | tr ' ' '\n' | grep -E 'androidboot.vbmeta'
su -c 'ls -l /dev/block/mapper/'
```

Measured:

```text
ro.boot.vbmeta.digest = e8ff1960b98291b6a5ee5ffba80da2be5cdde2594a5a79966871675a47abe7d3
ro.boot.veritymode    = enforcing

androidboot.vbmeta.device_state=unlocked
androidboot.vbmeta.hash_alg=sha256
androidboot.vbmeta.size=6720
androidboot.vbmeta.digest=e8ff1960b98291b6a5ee5ffba80da2be5cdde2594a5a79966871675a47abe7d3
androidboot.vbmeta.invalidate_on_error=yes

odm -> /dev/block/dm-4          odm-verity        -> /dev/block/dm-9
product -> /dev/block/dm-2      product-verity    -> /dev/block/dm-7
system -> /dev/block/dm-0       system-verity     -> /dev/block/dm-5
system_ext -> /dev/block/dm-1   system_ext-verity -> /dev/block/dm-6
vendor -> /dev/block/dm-3       vendor-verity     -> /dev/block/dm-8
```

Now count. **Five `*-verity` device-mapper targets exist on the live device: `odm`, `product`,
`system`, `system_ext`, `vendor`.** And you parsed exactly five hashtree descriptors — two in
`vbmeta` (`odm`, `vendor`) and three in `vbmeta_system` (`product`, `system`, `system_ext`). The
structure you read off the partition and the devices the kernel actually created agree, one for one.

That correlation is the point of the step. It means the hashtree descriptors are not documentation;
they are the live configuration, and `dm-N` is where the kernel is enforcing them right now.

Note also `androidboot.vbmeta.size=6720` — the signed portion of the image is 6,720 bytes: 256
(header) + 320 (authentication) + 3200 (auxiliary) for the top-level, plus the chained one. The
128 KiB you dumped is almost entirely zero padding, which is why `count=32` was enough.

### Step 6 — Verify a hash descriptor by hand, and run a control

This is the step that matters. Take the `boot` hash descriptor and check the actual partition
against it.

The digest is computed over **salt ‖ the first `Image Size` bytes of the partition** — not the whole
partition, which is 128 MiB of which only 21 MB is the image.

`21880832 / 4096 = 5342` exactly, so one clean `dd` does it:

```bash
# host — write the 32-byte salt to a file (do NOT hash the hex string)
python3 -B -c "import binascii,sys; open('salt.bin','wb').write(binascii.unhexlify(
  '4d6bf69daa8e967133b5cc96e9d62415b1e09b7bd7ca2ba7ccf97533b47021b8'))"
adb push salt.bin /data/local/tmp/salt.bin
```
```bash
# adb shell — prepend the salt, then stream exactly Image Size bytes
su -c '(cat /data/local/tmp/salt.bin;
        dd if=/dev/block/by-name/boot bs=4096 count=5342 2>/dev/null) | sha256sum'
```

Measured:

```text
expected (from the vbmeta descriptor):
  9895a0e21db8565ddd295e125b6613f62de390c22e9063748487f6e0c01b7b70

actual (hashed off the live partition):
  c63c859f91ba6e8225bf14e4d48270f38e3ecc85fb2e91e436f3fe9e49ea44cb
```

**They do not match.** The `boot` partition on this device is not the `boot` partition its own signed
vbmeta describes.

Before you write that down, **run the control.** A mismatch is equally consistent with "the image is
modified" and with "you hashed it wrong", and only one of those is a finding. So repeat the exact
procedure on a partition you have no reason to suspect — `dtbo`. Its `Image Size` of 6,384,882 is
not a multiple of 4096, so read whole blocks and trim:

```bash
# host
python3 -B -c "import binascii; open('salt2.bin','wb').write(binascii.unhexlify(
  'a3bd202a5b395c922d2ce5b4af3441cfd91d68ed223fb6111e49854adbaf771d'))"
adb push salt2.bin /data/local/tmp/salt2.bin
```
```bash
# adb shell
su -c '(cat /data/local/tmp/salt2.bin;
        dd if=/dev/block/by-name/dtbo bs=4096 count=1559 2>/dev/null | head -c 6384882) | sha256sum'
```
```text
expected: d55683f396142fc350a25eda2a261ee255285a57dbecadbd877aa4bfe9170c7c
actual  : d55683f396142fc350a25eda2a261ee255285a57dbecadbd877aa4bfe9170c7c
```

**Exact match.** The method is sound. Therefore the `boot` mismatch is a real detection of a modified
boot image — which is precisely what a Magisk- or APatch-patched device has, because patching the
ramdisk to inject the root daemon is how that root was installed.

Clean up after yourself:

```bash
# adb shell
su -c 'rm -f /data/local/tmp/salt.bin /data/local/tmp/salt2.bin'
```

> **Pentester's Note — you now have three independent proofs of the same lie.**
> The device reports `ro.boot.verifiedbootstate=green` and `ro.boot.flash.locked=1`. Against that:
>
> | # | Evidence | Source | Needs |
> |---|---|---|---|
> | 1 | `androidboot.verifiedbootstate=orange`, `vbmeta.device_state=unlocked` | Kernel command line | root (or group `radio`) |
> | 2 | `boot` hashes to `c63c859f…`, vbmeta says `9895a0e2…` | Partition + signed manifest | root |
> | 3 | Key attestation reports `verifiedBootState=Unverified`, `deviceLocked=false` | The TEE | **no root** — any app can ask |
>
> Three sources, three mechanisms, one conclusion. Evidence 3 is the one that works from inside an
> ordinary app, and it is the reason [50 — HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md)
> exists. Evidence 1 and 2 are the ones you can *show a client on their own hardware* without
> explaining what a TEE is, which is often worth more in a room.

### Step 7 — Inspect the boot image you just caught

```bash
# host — Magisk's boot tool; get magiskboot from the Magisk APK for your host arch
magiskboot unpack boot.img
ls -la
cat cmdline 2>/dev/null
```

Note the kernel version, the ramdisk, and whether `magiskboot` reports the image as **already
patched**. On a Magisk-patched image it prints `[!] Boot image patched by unsupported programs` or
identifies the injected `init`; that is the qualitative confirmation of what Step 6 proved
quantitatively.

If you cannot obtain `magiskboot`, the hash comparison in Step 6 is the stronger evidence anyway —
it is a cryptographic statement, not a heuristic — and you can look at the ramdisk with
`unpackbootimg` or by hand from the Android boot image header. Do not skip Step 6 in favour of this
step; do this one for colour.

### Step 8 — Reason about rollback

Answer these in writing. They are the questions an interviewer asks after you say "Verified Boot".

1. **Where is the *stored* rollback counter kept, and why must it be there rather than in a file?**
   In tamper-evident storage the normal world cannot rewrite — RPMB (Replay Protected Memory Block)
   on the eMMC/UFS, or one-time-programmable fuses. A file on `userdata` would be writable by
   exactly the attacker the counter exists to stop: rollback protection is *only* meaningful if the
   counter is monotonic against an adversary with full software control.

2. **What happens if you flash an image whose index is lower than the stored value?** A locked
   bootloader refuses to boot it, even though its signature is perfectly valid. This is the point
   people miss: **a valid signature is necessary and not sufficient.** Last year's officially signed
   image, containing last year's patched vulnerabilities, remains genuinely signed forever.

3. **Why is this irreversible even for the device's legitimate owner?** Because the counter only
   advances, by design. There is no downgrade path that an attacker could not also take. That is a
   deliberate trade: security against the owner's convenience, resolved in favour of security.

4. **And on *this* device?** `Rollback Index: 0` in both vbmetas. Anti-rollback is present as
   machinery and carries no protection here, because nothing can be lower than zero. Whether that is
   worth reporting depends on the engagement — say what you measured,it is an OEM
   platform choice rather than an app defect, and do not inflate it.

---

## Hints

<details>
<summary>Hint 1 — the parser says "bad magic" or the tool cannot read my image</summary>

`AVB0` must be at offset 0. If it is not, one of three things is true:

- **You dumped the wrong partition.** `ls -l /dev/block/by-name/ | grep -i vbmeta` — on an A/B device
  the real one may be `vbmeta_a` or `vbmeta_b`, and `ro.boot.slot_suffix` tells you which is active.
  On this device `ro.boot.slot_suffix` is empty, meaning non-A/B, so plain `vbmeta` is correct.
- **It is an Android sparse image.** Convert first: `simg2img system.img system_raw.img`. Sparse
  images start with the magic `0x3AFF26ED`.
- **It is inside an OTA container.** `payload.bin`-style OTAs need `payload_dumper`; some OEMs use a
  proprietary container needing their own tool.
</details>

<details>
<summary>Hint 2 — the digest does not match, and I do not think the image is patched</summary>

Four causes, in order of how often they are the answer:

1. **Trimmed to the wrong length.** `Image Size` is the size of the *payload*. The partition is
   larger, and the tail contains padding plus, on some partitions, an AVB footer. Hashing the whole
   partition never matches.
2. **Hashed the hex string instead of the bytes.** `unhexlify` the salt. A 64-character ASCII string
   and 32 raw bytes are different inputs.
3. **Salt in the wrong position.** It is `sha256(salt ‖ data)`, prepended, not appended and not HMAC.
4. **`dd` block arithmetic.** If `Image Size` is not a multiple of your `bs`, read whole blocks and
   trim with `head -c <Image Size>`, as the `dtbo` control does above.

**Then run the control.** Verify a partition you have no reason to suspect. If the control matches
and the target does not, the target is modified and you have a finding. If neither matches, your
method is wrong. Never publish a mismatch you have not controlled for — this is the single most
important habit in the lab.
</details>

<details>
<summary>Hint 3 — I have no Hashtree descriptor at all</summary>

They are in a chained vbmeta. Look for a `Chain Partition descriptor` and parse the partition it
names (Step 3). Newer devices split into `vbmeta_system` and `vbmeta_vendor`; this one has both
partitions present but only chains to `vbmeta_system`.

If there is no chain descriptor *and* no hashtree descriptor, you are probably on an emulator, where
verification is stubbed.
</details>

<details>
<summary>Hint 4 — I have no root, so Route A is closed</summary>

Then you cannot read block devices, and Steps 5–7 are unavailable. Use **Route B**: a factory image
for a device you own gives you the full structure for Steps 1–4 and 8, which is most of the lab's
teaching.

What you lose is the comparison against a live device — and that loss is itself the lesson worth
recording: **verifying a device's boot chain from outside requires privileges the device gives only
to its owner.** An app cannot do it. That is not a gap in your tooling; it is why key attestation
exists, and why an app asking `getprop` is asking the wrong component.
</details>

<details>
<summary>Hint 5 — `dd` is very slow, or the shell dies part-way</summary>

Use a larger `bs`. `bs=4096` on a 21 MB read is fine; on a 1.4 GB partition it is not. `bs=1M` with
the count adjusted is fast, and for a final partial block, `head -c` after the `dd` rather than
`bs=1`.

Never pull a multi-gigabyte partition to the host just to hash it. Hash it **on the device** with
`sha256sum`, as Step 6 does; only the 32-byte answer needs to cross the USB cable.
</details>

---

## Verification — did you actually do this?

From your own output, not from memory:

1. What algorithm signs your vbmeta, and how many descriptors did it contain?
2. Name every partition covered by a **hash** descriptor and every one covered by a **hashtree**
   descriptor, and say why each got the type it did.
3. Does your device chain to another vbmeta? If so, is its rollback index location the same as the
   top-level one, and why does the answer matter?
4. How many `*-verity` targets are in `/dev/block/mapper/`, and does that number equal your count of
   hashtree descriptors across **all** the vbmetas you parsed? If not, which one is unaccounted for?
5. Did your hand-computed digest match? **Did you run a control on a second partition?** If you did
   not run the control, you do not yet know whether a mismatch means anything.

---

## Success criteria

- [ ] You can list every descriptor in a real `vbmeta.img` and state what each one protects.
- [ ] You followed a chain partition descriptor to a second vbmeta and can explain what Treble has
      to do with its existence.
- [ ] You extracted at least one dm-verity root digest and can say what it is the root *of*, in
      blocks and in bytes.
- [ ] You reproduced a hash descriptor's digest by hand **and ran a control on a second partition**,
      so that a match and a mismatch both mean something.
- [ ] You can explain, without notes, why `system` uses a hashtree descriptor while `boot` uses a
      hash descriptor — and why the answer is about boot time, not about strength.
- [ ] You can explain what changes when the bootloader is unlocked, and name the exact circular-trust
      problem that makes on-device verification meaningless once it is.
- [ ] You can describe where the rollback counter is stored, why it cannot be a file, and why a
      correctly signed image can still be refused.
- [ ] You can state the three independent proofs from Step 6's note, and say which one an ordinary
      app can obtain.

---

## Going further

**1. Sign your own.** Use `avbtool make_vbmeta_image` and `avbtool add_hashtree_footer` to build a
signed vbmeta over a small test filesystem image, then verify it with `avbtool verify_image`. Doing
the *signing* side is what makes the design click — you generate the key, and you immediately
understand why the device's copy of the public key has to live somewhere you cannot write.

**2. Diff a factory image against your device.** Pull `vbmeta` from your phone (Route A) and parse
the manufacturer's `vbmeta.img` for the same build (Route B). Every difference is a modification
someone made after the phone left the factory. This is the highest-value form of firmware triage and
it is two commands plus `diff` — use `--json` output for that:

```bash
# host
python3 -B ../scripts/parse-vbmeta.py --json factory-vbmeta.img > factory.json
python3 -B ../scripts/parse-vbmeta.py --json device-vbmeta.img  > device.json
diff factory.json device.json
```

**3. Extend the tool.** `parse-vbmeta.py` deliberately does not verify signatures, and the reason it
gives is worth arguing with: implement RSA PKCS#1 v1.5 verification over the auxiliary block using
the public key inside the image, watch it pass, and then explain **why passing proves nothing**. The
key you verified against came out of the file you are verifying. Only a key the device holds
independently — in fuses — makes the check mean anything. That circularity is the same one behind
the unlocked-bootloader problem in Step 8, and implementing it is the fastest way to never confuse
"signed" with "trusted" again.

**4. Take it to the app layer.** You now know the device's real boot state by three routes. Go and
watch an app try to determine the same thing from inside its own process, and fail:
[Lab 03](lab-03-integrity-gate-bypass.md).
