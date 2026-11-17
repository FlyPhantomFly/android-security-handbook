# Lab 03 — vbmeta, verity, and the one byte that matters

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Chapter 61 §3.8](../README.md#38-vbmeta-flags-and-what---disable-verity-actually-disables),
[§4.3](../README.md#43-the-two-flag-constants-in-their-own-header),
[20-Security-Architecture §3.1–§3.2](../../20-Security-Architecture/README.md#31-verified-boot-and-android-verified-boot-20-avb),
[Lab 01](lab-01-device-posture.md)
**You need:** `python3`. Parts 1–4 need a `vbmeta.img`, obtainable from a rooted device, an emulator,
or any OEM factory image download. Part 5 needs a rooted device or emulator.

> **Nothing in this lab flashes anything.** You will produce a modified `vbmeta.img` on your host
> in Part 3. **Do not flash it.** The lab's entire purpose is to show you why you would not want to,
> and the file exists so you can measure it rather than believe a claim about it.

---

## Objective

Answer, from bytes rather than from documentation:

1. What is *in* a `vbmeta` partition, structurally?
2. Where exactly does `fastboot --disable-verity` write, and how much does it change?
3. **What does that edit do to the image's own integrity hash** — and what does the answer imply
   about when the flag can be used at all?
4. Which partitions does the flag actually affect on *your* device, by matching descriptors against
   live dm-verity mappings?
5. Where is the boundary between "a hashtree descriptor exists" and "verity is running"?

## Why this matters

`--disable-verity` is one line in `fastboot --help`:

```
--disable-verity           Sets disable-verity when flashing vbmeta.
```

That is not enough to reason with, and the gap gets filled with folklore. The two claims you will
hear most often are that it "turns off Verified Boot" and that you can "disable verity and then
relock". The first is imprecise in a way that matters; the second describes a brick. This lab
replaces both with a measurement you performed.

The technique also generalises. **Recomputing a format's own integrity check and getting the stored
value back** is the strongest possible evidence that you have parsed it correctly — stronger than
"the field names look plausible". Once the hash matches, every other conclusion you draw from the
structure is on solid ground.

---

## Setup

### Get a `vbmeta.img`

**Option A — from an emulator or rooted device you own:**

```bash
# host
SIZE=$(adb shell getprop ro.boot.vbmeta.size | tr -d '\r')
echo "vbmeta.size = $SIZE"

# try both su forms -- the emulator wants `su 0`, Magisk wants `su -c`
adb shell "su 0 dd if=/dev/block/by-name/vbmeta bs=1 count=$SIZE 2>/dev/null | base64" \
  | base64 -d > vbmeta.img
ls -l vbmeta.img         # must equal $SIZE
xxd -l 4 vbmeta.img      # must start AVB0
```

**Option B — from an OEM factory image**, which needs no device at all:

```bash
# host
unzip factory-image.zip
unzip image-<device>-<build>.zip vbmeta.img
```

**Option C — synthetic**, if you have neither. The chapter's tool builds a structurally valid,
self-consistent vbmeta for its own self-test:

```bash
python3 -B <chapter>/scripts/vbmeta-flags.py selftest
```

19 checks; all must pass. The synthetic image has a real hash invariant and a placeholder signature,
which is enough for Parts 1–3.

### Verify the tools

```bash
python3 -B <chapter>/scripts/vbmeta-flags.py selftest
python3 -B <chapter>/scripts/sparse-tool.py  selftest
```

---

## Part 1 — Parse the header by hand

### Step 1.1 — The structure

From `external/avb/libavb/avb_vbmeta_image.h`. **Every multi-byte field is big-endian**, which is
unusual on an ARM or x86 device and is the single most common reason a hand-written AVB parser
produces nonsense instead of an error.

```
AvbVBMetaImageHeader -- exactly 256 bytes
  offset  size  field
  0       4     magic[4]                        "AVB0"
  4       4     required_libavb_version_major
  8       4     required_libavb_version_minor
  12      8     authentication_data_block_size
  20      8     auxiliary_data_block_size
  28      4     algorithm_type
  32      8     hash_offset          } offsets are RELATIVE to their block,
  40      8     hash_size            } not to the file
  48      8     signature_offset
  56      8     signature_size
  64      8     public_key_offset
  72      8     public_key_size
  80      8     public_key_metadata_offset
  88      8     public_key_metadata_size
  96      8     descriptors_offset
  104     8     descriptors_size
  112     8     rollback_index
  120     4     flags                           <-- THE FIELD
  124     4     rollback_index_location
  128     48    release_string[48]
  176     80    reserved[80]
```

Layout on disk: `header (256) || authentication block || auxiliary block`.

### Step 1.2 — Parse it yourself

Write this before running the tool.

```python
#!/usr/bin/env python3
# /tmp/lab03/parse.py -- run with python3 -B
import struct, sys

d = open(sys.argv[1], "rb").read()
assert d[:4] == b"AVB0", "not a vbmeta image"

ver_maj, ver_min       = struct.unpack(">II", d[4:12])
auth_sz, aux_sz        = struct.unpack(">QQ", d[12:28])
algorithm,             = struct.unpack(">I",  d[28:32])
hash_off, hash_sz      = struct.unpack(">QQ", d[32:48])
sig_off,  sig_sz       = struct.unpack(">QQ", d[48:64])
desc_off, desc_sz      = struct.unpack(">QQ", d[96:112])
rollback,              = struct.unpack(">Q",  d[112:120])
flags, rbi_loc         = struct.unpack(">II", d[120:128])
release                = d[128:176].rstrip(b"\x00").decode()

for k, v in [("libavb", "%d.%d" % (ver_maj, ver_min)), ("auth block", auth_sz),
             ("aux block", aux_sz), ("algorithm", algorithm),
             ("descriptors", "off=%d size=%d" % (desc_off, desc_sz)),
             ("rollback_index", rollback), ("flags", "0x%08x" % flags),
             ("rbi_location", rbi_loc), ("release", release)]:
    print("%-16s %s" % (k, v))
```

Measured output from a real `vbmeta` pulled off an Android 15 / API 35 emulator:

```
libavb           1.0
auth block       576
aux block        4224
algorithm        2
descriptors      off=0 size=3176
rollback_index   0
flags            0x00000000
rbi_location     0
release          avbtool 1.3.0
```

**Q1.** `algorithm_type = 2` is `SHA256_RSA4096`. The authentication block is 576 bytes. Account for
every byte of it.

<details>
<summary>Answer</summary>

32 bytes of SHA-256 digest + 512 bytes of RSA-4096 signature + 32 bytes of padding = 576.

`hash_offset = 0, hash_size = 32` and `signature_offset = 32, signature_size = 512` confirm the first
two directly. The remaining 32 is alignment padding — the auxiliary block must start on a boundary,
and `avbtool` rounds the authentication block up to reach it.

Padding you can account for is a good sign that you have the layout right. Padding you cannot is a
sign that you do not.
</details>

**Q2.** `required_libavb_version` is `1.0` but `release_string` says `avbtool 1.3.0`. Contradiction?

<details>
<summary>Answer</summary>

No — and the distinction is deliberate and useful.

`required_libavb_version` is a **compatibility floor**: the minimum libavb version a *verifier* needs
to parse this image correctly. `release_string` records which avbtool *produced* it.

A 1.3.0 tool that emitted only 1.0-era features correctly declares a 1.0 floor, so a device with an
older libavb can still verify it. This is forward-compatibility done properly: the producer states
the minimum capability required rather than its own version.

The same device reported `ro.boot.avb_version = 1.3` — that is the version of libavb the *bootloader*
runs, which is a third distinct number. Three version fields, three meanings; conflating them
produces confident wrong statements about compatibility.
</details>

---

## Part 2 — Recompute the integrity hash

This is the step that proves your parse is right.

### Step 2.1 — How AVB computes it

From `avb_vbmeta_image_verify()` in `external/avb/libavb/avb_vbmeta_image.c`, the hash is computed
over:

```
sha256( header[0:256]  ||  auxiliary_block )
```

and compared against the digest stored at `hash_offset` inside the **authentication** block. Note
what is and is not included: the header is hashed **as it appears on disk**, all 256 bytes; the
authentication block itself is *not* hashed (it contains the hash, so it cannot be).

### Step 2.2 — Do it

```python
#!/usr/bin/env python3
# /tmp/lab03/rehash.py
import struct, hashlib, sys

d = open(sys.argv[1], "rb").read()
auth_sz, aux_sz = struct.unpack(">QQ", d[12:28])

header = d[:256]
auth   = d[256:256 + auth_sz]
aux    = d[256 + auth_sz:256 + auth_sz + aux_sz]

stored = auth[0:32]
calc   = hashlib.sha256(header + aux).digest()

print("stored     ", stored.hex())
print("recomputed ", calc.hex())
print("MATCH" if stored == calc else "MISMATCH")
```

Measured against the emulator's real `vbmeta`:

```
stored      93dfae214512fd0b4109c245337a01e885809c29b6c6388d117d16a5cabe3b7b
recomputed  93dfae214512fd0b4109c245337a01e885809c29b6c6388d117d16a5cabe3b7b
MATCH
```

**Q3.** If your recomputation had come out wrong, name three plausible causes before assuming the
image is corrupt.

<details>
<summary>Answer</summary>

1. **Endianness.** Reading `auth_sz`/`aux_sz` as little-endian gives absurd offsets, and slicing at
   absurd offsets yields empty or wrong regions. This is the overwhelmingly likely cause and it is
   why the format note is repeated everywhere in this chapter.
2. **Wrong region boundaries.** Including the authentication block in the hash, or excluding part of
   the auxiliary block, or hashing the whole file. The layout is header, then auth, then aux — and
   only the first and third are hashed.
3. **Wrong digest length for the algorithm.** `algorithm_type` 4, 5 and 6 are SHA-512 variants with a
   64-byte digest. Slicing `auth[0:32]` on one of those compares half a hash.

Only after excluding all three would "the image is corrupt" be the right conclusion — and a genuinely
corrupt vbmeta on a booting device is very unlikely, because the device would not have booted.
</details>

---

## Part 3 — Find the byte

### Step 3.1 — Flip it

```python
#!/usr/bin/env python3
# /tmp/lab03/flip.py
import struct, hashlib, sys

FLAG_HASHTREE_DISABLED     = 1 << 0
FLAG_VERIFICATION_DISABLED = 1 << 1

orig = open(sys.argv[1], "rb").read()
auth_sz, aux_sz = struct.unpack(">QQ", orig[12:28])
aux = orig[256 + auth_sz:256 + auth_sz + aux_sz]

def rehash(blob):
    return hashlib.sha256(blob[:256] + aux).digest()

print("flags field, offset 120..124 =", orig[120:124].hex())
print("stored hash                  =", orig[256:288].hex()[:32], "...")
print()

for label, bit in [("--disable-verity", FLAG_HASHTREE_DISABLED),
                   ("--disable-verification", FLAG_VERIFICATION_DISABLED),
                   ("both", FLAG_HASHTREE_DISABLED | FLAG_VERIFICATION_DISABLED)]:
    m = bytearray(orig)
    cur, = struct.unpack(">I", m[120:124])
    m[120:124] = struct.pack(">I", cur | bit)
    changed = [i for i in range(len(orig)) if orig[i] != m[i]]
    ok = rehash(bytes(m)) == orig[256:288]
    print("%-24s flags -> 0x%08x  bytes changed: %-8s  hash still valid: %s"
          % (label, cur | bit, changed, ok))
```

Measured:

```
flags field, offset 120..124 = 00000000
stored hash                  = 93dfae214512fd0b ...

--disable-verity         flags -> 0x00000001  bytes changed: [123]     hash still valid: False
--disable-verification   flags -> 0x00000002  bytes changed: [123]     hash still valid: False
both                     flags -> 0x00000003  bytes changed: [123]     hash still valid: False
```

**Q4.** The flags field is at offset **120** and it is four bytes wide. Why did only byte **123**
change?

<details>
<summary>Answer</summary>

Because the field is **big-endian**, so the least-significant byte is the last one — offset 123. Both
defined flag bits live in the low byte, so bytes 120, 121 and 122 stay zero.

Two things follow that are worth carrying:

- **This is a one-byte edit.** The entire difference between a device that integrity-checks every
  read of `/system` and one that does not is byte 123 of a 6,784-byte partition.
- **Struct arithmetic and the observed diff agree.** Counting field offsets by hand from the header
  gives 120; the measured diff gives 123; big-endian reconciles them. Neither alone would be
  convincing evidence, and the agreement is what makes it a fact rather than a belief.
</details>

### Step 3.2 — The conclusion

**Q5.** The hash no longer matches. State precisely what that means for the modified image on a
**locked** device and on an **unlocked** one.

<details>
<summary>Answer</summary>

The flags field is inside the 256 bytes AVB hashes. Editing it changes the computed hash, which no
longer equals the stored digest, and the RSA signature over that digest therefore no longer verifies
against the OEM public key.

**On a locked device:** verification fails, boot state goes **RED**, and the device refuses to boot.
This is exactly what Verified Boot exists to do, working correctly.

**On an unlocked device:** verification still runs and still fails, but failure is *advisory* — the
bootloader continues. AVB then reads the flags it just failed to authenticate, sees
`HASHTREE_DISABLED`, and skips setting up dm-verity.

So: **`fastboot --disable-verity` is not a supported option that AVB honours. It is a deliberate
corruption that only an unlocked bootloader will accept.** Anyone who tells you to "flash vbmeta with
`--disable-verity` and then relock" is describing a brick, and now you can say why in one sentence
rather than three paragraphs.
</details>

**Q6.** Compare `--disable-verity` (bit 0) and `--disable-verification` (bit 1). Which is larger in
effect, and which should you reach for?

<details>
<summary>Answer</summary>

**Bit 1 is strictly larger.** Bit 0 makes AVB ignore every `AvbHashtreeDescriptor`, so dm-verity is
never set up — but the boot image hash is still checked and chained vbmetas are still verified. Bit 1
skips the **entire** chain: nothing is verified at all.

Reach for the smaller one, and usually for neither. The common misunderstanding is that
`--disable-verity` is what lets a patched boot image run. It is not — the *unlocked state* is.
`--disable-verity` is what lets you **modify `/system`**, because with the hashtree gone there is no
per-block hash to violate.

On a device where you only want to run a patched boot image, you typically need neither flag.
</details>

### Step 3.3 — Cross-check with the chapter's tool

```bash
python3 -B <chapter>/scripts/vbmeta-flags.py show vbmeta.img
python3 -B <chapter>/scripts/vbmeta-flags.py set  vbmeta.img noverity.img --disable-verity
python3 -B <chapter>/scripts/vbmeta-flags.py diff vbmeta.img noverity.img
python3 -B <chapter>/scripts/vbmeta-flags.py clear noverity.img restored.img
cmp vbmeta.img restored.img && echo "clear round-trips exactly"
```

**Q7.** `clear` restores the original bytes and the hash validates again. Does that mean the flag
change was harmless?

<details>
<summary>Answer</summary>

Only because nothing else was touched. Clearing the flags restores byte 123 to `0x00`, and since that
was the only byte changed, the file is byte-identical to the original and the hash matches again.

The reason to notice this is that it identifies exactly what the operation is: **a reversible one-byte
edit that breaks a signature.** It is not a re-signing operation and it does not attempt to be. If you
had *legitimate* signing keys you would set the flag in `avbtool` and re-sign, producing a valid image
with verity disabled — which is what a device manufacturer or a custom-ROM project with its own key
does, and is how a YELLOW-state device gets built.

That is the honest distinction between "disabled verity" done by an owner with a key and done by
`fastboot --disable-verity`. Same flag, completely different trust story.
</details>

---

## Part 4 — Which partitions does the flag actually affect?

### Step 4.1 — Enumerate the descriptors

Descriptors live in the auxiliary block at `descriptors_offset`, each one an 8-byte tag, an 8-byte
following-length, and a body. Tags: 0 PROPERTY, 1 HASHTREE, 2 HASH, 3 KERNEL_CMDLINE, 4
CHAIN_PARTITION. Each is padded to an 8-byte boundary.

Use chapter 20's full parser rather than rewriting it:

```bash
python3 -B ../../20-Security-Architecture/scripts/parse-vbmeta.py vbmeta.img
```

Measured on the emulator's `vbmeta`:

```
CHAIN     system       rollback_index_location=1, public key 520 bytes
HASH      vendor_boot  image_size=98304        sha256   digest 56bc7759...
HASHTREE  product      image_size=2110955520   4 KiB blocks, FEC roots 2
HASHTREE  system_dlkm  image_size=6995968
HASHTREE  system_ext   image_size=214192128
HASHTREE  vendor       image_size=109670400
```

**Q8.** `--disable-verity` disables hashtree descriptors. Which entries above survive it, and why?

<details>
<summary>Answer</summary>

Two kinds survive:

- **`HASH vendor_boot`** — an `AvbHashDescriptor` is a whole-partition hash checked once at boot, not
  a Merkle tree checked lazily on read. Bit 0 names hashtrees specifically and does not touch it.
- **`CHAIN system`** — an `AvbChainPartitionDescriptor` delegates verification of `system` to a
  *separate* vbmeta signed with a different key. Bit 0 in *this* vbmeta does not reach into that one.
  (Bit 1, `VERIFICATION_DISABLED`, would, because it skips the whole chain.)

So on this device `--disable-verity` disables verity for `product`, `system_dlkm`, `system_ext` and
`vendor`, and leaves `system` and `vendor_boot` alone.

**That precision is what a report needs.** "Disable-verity turns off Verified Boot" is the sentence to
avoid; "disable-verity clears the hashtree descriptors in the top-level vbmeta, which on this device
covers four of six protected partitions and does not affect the chained `system` vbmeta" is a
sentence you can defend.
</details>

### Step 4.2 — Match descriptors to live mappings

Now the part that separates image analysis from runtime reality. On the same device:

```bash
# host, root needed
adb shell "su 0 dmctl list devices" 2>&1 | grep -v '^com\.android\.'
adb shell "su 0 dmctl table system-verity" 2>&1
adb shell "su 0 grep -E ' (/|/vendor|/product|/system_ext) ' /proc/mounts"
```

Measured on the API 35 emulator:

```
system : 254:0     system-verity : 254:5     vendor : 254:4
system_ext : 254:2 system_dlkm : 254:1       product : 254:3

/dev/block/dm-5 /            ext4 ro    <- system-verity
/dev/block/dm-4 /vendor      ext4 ro    <- vendor, NO verity layer
/dev/block/dm-3 /product     ext4 ro    <- product, NO verity layer
/dev/block/dm-2 /system_ext  ext4 ro    <- system_ext, NO verity layer
```

**Q9.** Four partitions have hashtree descriptors. **One** has a verity device. Reconcile that.

<details>
<summary>Answer</summary>

You cannot fully, from the device, and the honest answer is to say so.

What is certain: **a hashtree descriptor existing in a vbmeta is not the same as dm-verity running at
runtime.** The descriptor is a statement in an image; the mapping is a fact about the kernel. On this
device `product`, `system_dlkm`, `system_ext` and `vendor` all have descriptors and all mount plain
linear targets with no verity layer, while `system` — whose descriptor is not even in this vbmeta,
being behind a chain — is the only one with a verity device.

Possible causes include an emulator-specific first-stage-init path, or a build configuration that
emits descriptors without enabling the mappings. **The cause was not determined and is not guessed
at here.** The emulator is explicitly not a reference for boot behaviour, so generalising from it
would be exactly the error this chapter's §7.6 warns about.

The transferable rule: when you are asked "is this partition integrity-protected at runtime?", read
`dmctl`, not the image's descriptors. And when you can see an effect but not its cause, record the
observation and say the cause is undetermined — a hedged true statement beats a confident invented one.
</details>

### Step 4.3 — Read a verity table properly

```
system-verity 0-1800416: verity, 1 254:0 254:0 4096 4096 225052 225052 sha256 \
              d7b94a2a42e4648f6f87c80f2e4ab7b8f7b41a50612b7320504363134315363f \
              34f93a31db2a530c5ec009dee328bcad680cfda410ff4799f39ab2b6d4b7bc09 \
              10 restart_on_corruption ignore_zero_blocks use_fec_from_device 254:0 \
              fec_blocks 226826 fec_start 226826 fec_roots 2
```

**Q10.** `1800416 = 225052 × 8`. Why 8, and what does that tell you about the two block sizes?

<details>
<summary>Answer</summary>

Device-mapper counts in **512-byte sectors**; verity counts in **4,096-byte data blocks**. 4096 ÷ 512
= 8. So 225,052 data blocks is 1,800,416 sectors, and the two numbers in the table are the same
quantity in two units.

Getting this wrong by a factor of 8 is a classic source of confusion when correlating dm tables with
AVB descriptors, because AVB's `image_size` is in *bytes*: 225,052 × 4,096 = 921,812,992 bytes, which
is what an `AvbHashtreeDescriptor` for this partition would report.

Three units, one quantity. Convert explicitly every time.
</details>

**Q11.** `hash_start_block` is also 225,052, and both device arguments are `254:0`. What does that
tell you about where the hash tree lives?

<details>
<summary>Answer</summary>

**Inside `system` itself, immediately after the data.** Data device and hash device are the same
device (`254:0`, the `system` linear target), and the tree starts at exactly the block where the data
ends.

This is why a partition image is larger than its filesystem: the image is `filesystem || hash tree ||
FEC data`. `fec_start 226826` shows the forward-error-correction data starting after the tree, and
`fec_roots 2` means it can repair up to two symbol errors per codeword — verity that can *correct*
minor corruption rather than only detect it.

`restart_on_corruption` is the policy when it cannot: the device **reboots** rather than returning an
error to the reader. That is why verity evidence lives in the previous boot's log
(`adb logcat -L`, or `/sys/fs/pstore/`) rather than the current one.
</details>

---

## Part 5 — Put it together

**Q12.** You are handed a device. Someone claims verity is disabled on it. Design the check, using
only what this lab taught, and state the confidence of each step.

<details>
<summary>Answer</summary>

Four steps, in increasing strength:

1. **`getprop ro.boot.veritymode`** — `enforcing`, `logging` or `disabled`. **Weakest.** It is a
   property; root rewrites it in one command.
2. **`dmctl list devices | grep verity`** — does a verity device-mapper device exist for each
   read-only partition? **Strong**, because it reports live kernel state. Still defeatable by an
   attacker with kernel-level control, but that is a much higher bar.
3. **Pull `vbmeta` and check byte 123 with `vbmeta-flags.py show`.** Tells you what the *image* asks
   for, and whether the image's own hash still validates. A `MISMATCH` here is decisive: an edited
   vbmeta is on the device and the bootloader accepted it, which means the bootloader is unlocked.
4. **Hardware key attestation `deviceLocked` and `verifiedBootState`.** **Evidence, not a claim** —
   the only step whose answer root cannot change, because it is computed inside the TEE.

The correct report combines them: "`ro.boot.veritymode` reports enforcing; `dmctl` shows a verity
device for `system` only; the on-device `vbmeta` has `flags = 0` and its integrity hash validates;
hardware attestation reports `deviceLocked = false`." Those four facts together tell a much more
precise story than any one of them, and the disagreements between them are often the most interesting
part.
</details>

**Q13.** Extend `vbmeta-flags.py` with a `verify-against-device` subcommand: pull `vbmeta` from a
connected device, parse its hashtree descriptors, enumerate live verity dm devices, and print a table
of descriptor-present versus mapping-present for each partition. The rows where those two disagree are
the interesting ones, and Part 4 showed there are usually some.

---

## Success criteria

- [ ] Parse a vbmeta header by hand, big-endian, without the tool
- [ ] Account for every byte of the authentication block
- [ ] Explain the three distinct version numbers in play and what each means
- [ ] Recompute AVB's integrity hash and get the stored value back
- [ ] Name three causes of a mismatch before concluding the image is corrupt
- [ ] Locate the flags field at offset 120 and explain why only byte 123 changes
- [ ] State what an edited vbmeta does on a locked device and on an unlocked one
- [ ] Explain why `--disable-verification` is strictly larger than `--disable-verity`
- [ ] Say which descriptors survive `--disable-verity` and why
- [ ] Explain the difference between a hashtree descriptor and a live verity mapping
- [ ] Convert between sectors, verity blocks and AVB byte sizes without error
- [ ] Design a four-step verity check with the confidence of each step stated

## Cleanup

```bash
rm -f noverity.img restored.img *.simg
find . -name __pycache__ -type d       # must print nothing
```

**Do not flash `noverity.img`.** Delete it. It exists only so you could measure what it is.

## Next

[Lab 04 — CTF: The Bricked Vault](lab-04-ctf-bricked-vault.md).
