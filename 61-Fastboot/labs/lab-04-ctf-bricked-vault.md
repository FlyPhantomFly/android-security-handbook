# Lab 04 — CTF: The Bricked Vault

**Difficulty:** CTF — assumes labs 01–03
**Time:** 2–4 hours
**Prerequisites:** [Lab 01](lab-01-device-posture.md), [Lab 02](lab-02-sparse-images.md),
[Lab 03](lab-03-vbmeta-and-verity.md), and chapter 61
[§2.3](../README.md#23-the-lock-state-machine--the-most-important-diagram-in-this-chapter),
[§3.5](../README.md#35-sparse-images-how-a-3-gb-image-crosses-a-256-mb-buffer),
[§3.7](../README.md#37-dynamic-partitions-and-the-super-partition),
[§3.8](../README.md#38-vbmeta-flags-and-what---disable-verity-actually-disables)
**You need:** `python3` and this chapter's `scripts/` directory. **No device. Nothing to brick.**

---

## The scenario

A repair shop sends you a bag of files and a dead phone.

The technician rooted the device for a customer, did the work, then tried to "put it back to normal"
and produced a phone that shows *"Your device is corrupt. It can't be trusted and will not boot."*
Power-cycling gives the same screen. Fastboot mode is reachable by key combination, and every command
that might fix it is refused.

The customer's recovery passphrase lived on the device and is gone. The technician salvaged four
artefacts off their workstation before giving up, and swears fragments of it are recoverable.

**Recover the flag.**

```
APN61{PART1_PART2_PART3_PART4}
```

## Generate the challenge

```bash
# host, from the chapter root
python3 -B scripts/make-ctf-images.py /tmp/ctf-vault
cd /tmp/ctf-vault
ls -la
cat BRIEFING.txt
```

You should have six files:

| File | ~size | What it claims to be |
|---|---:|---|
| `BRIEFING.txt` | 1.8 KB | The scenario and the rules |
| `recovery.simg` | 4.2 KB | A partition image, salvaged |
| `vbmeta.img` | 1.3 KB | Pulled off the device before the last reboot |
| `super.img` | 5.2 MB | A container, partially readable |
| `super-dm-table.txt` | 263 B | `dmctl table` output for the above |
| `fastboot-session.log` | 2.3 KB | The technician's terminal history |

**Instructors:** `python3 -B scripts/make-ctf-images.py /tmp/ctf-vault --solve` prints every answer.
`--selftest` generates the artefacts, solves all four stages programmatically, checks that the stage-3
trap actually traps, verifies that part 4's token is not stored anywhere in the files, and cleans up.
The output is deterministic, so every student's images are byte-identical.

> **⚠️ Everything here is a file.** Nothing is bootable, nothing is signed with any real key, and
> nothing can be flashed to anything. Do not connect a device. The whole point of this CTF is that
> the entire skill set transfers without hardware at risk.

---

## Rules

1. Offline only. No device, no emulator, no network.
2. Use the chapter's tools — `sparse-tool.py`, `vbmeta-flags.py` — or write your own. Writing your own
   is better.
3. Tokens are upper-case. Join them with underscores, in order.
4. **`strings` will get you two of the four tokens in about ten seconds, and you will have learned
   nothing and be unable to finish.** Stage 3 needs a number that only appears if you solved stage 1
   properly, and stage 4's token is not in any file. The shortcut is deliberately a dead end.

---

## Stage 1 — What is in the recovery image?

**Worth:** PART1, plus a number you will need in stage 3.

```bash
file recovery.simg
xxd -l 32 recovery.simg
```

The magic is `3a ff 26 ed` little-endian: `0xED26FF3A`.

```bash
python3 -B <chapter>/scripts/sparse-tool.py info   recovery.simg
python3 -B <chapter>/scripts/sparse-tool.py verify recovery.simg
```

<details>
<summary>Hint 1</summary>

It is a sparse image with three chunks. The first is a `FILL`, the second is a `RAW`, the third is a
`DONT_CARE`. The whole file is 4,164 bytes and describes 790,528 bytes of output.
</details>

<details>
<summary>Hint 2</summary>

`strings recovery.simg` finds the token immediately, because the `RAW` chunk is stored verbatim. That
is not the solve. Read the note the token is embedded in — it tells you that the **offset** matters,
and the offset only exists in the *expanded* image, not in the sparse file.
</details>

<details>
<summary>Solution</summary>

```bash
python3 -B <chapter>/scripts/sparse-tool.py expand recovery.simg recovery.img
ls -l recovery.img          # 790528 bytes

python3 -B - <<'EOF'
d = open("recovery.img", "rb").read()
i = d.find(b"SPARSE")
print("token at byte offset:", i)
print("block-aligned offset:", (i // 4096) * 4096)
print(d[(i//4096)*4096:(i//4096)*4096+180].split(b"\x00")[0].decode())
EOF
```

```
token at byte offset: 524336
block-aligned offset: 524288
# recovery partition, salvaged
# stage 1 token: SPARSE
# the offset at which you found this line is the seed for stage 3.
```

**PART1 = `SPARSE`**, and the number to keep is **524288** — the block-aligned offset, which is
128 × 4096.

The reason the offset only exists after expansion: in the sparse file, the `RAW` chunk sits at byte
44. Its *position in the partition* is 524,288, and that is entirely determined by the 128-block
`FILL` chunk in front of it — sixteen bytes on disk describing half a megabyte of output. **The
sparse file does not contain the offset; the sparse file contains the instructions for computing it.**

That is the whole idea of the format, and it is why `strings` on a sparse image can find data whose
location it cannot tell you.
</details>

---

## Stage 2 — What did the technician do to `vbmeta`?

**Worth:** PART2, and the diagnosis of the whole incident.

```bash
xxd -l 16 vbmeta.img                  # AVB0
python3 -B <chapter>/scripts/vbmeta-flags.py show vbmeta.img
```

<details>
<summary>Hint 1</summary>

Two things in that output matter, not one. The flags field is the obvious one. Look at the last line
before the verdict.
</details>

<details>
<summary>Hint 2</summary>

The token is in the auxiliary block, and `strings` will find it. The token is not the interesting part
of this stage — the token is `BYTE123`, and the stage is asking whether you can say *why*.
</details>

<details>
<summary>Solution</summary>

```
flags                     0x00000001   (uint32 big-endian at offset 120;
                                       low byte therefore at offset 123)
  bit 0  SET    AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED
  bit 1  clear  AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED

integrity hash            MISMATCH -- the header has been edited
                          after signing. A LOCKED bootloader will
                          refuse this image (boot state RED).

VERDICT: dm-verity DISABLED
```

**PART2 = `BYTE123`.**

The diagnosis, which is the actual point:

- `flags = 0x00000001` means `HASHTREE_DISABLED` is set. This image was produced by
  `fastboot --disable-verity`.
- The field is a big-endian `uint32` at offset 120, so the byte that changed is **123**.
- **The integrity hash mismatches.** The flags field lives inside the 256 bytes AVB hashes, so setting
  it invalidated the image's own digest and therefore the signature over it.

Prove the second and third points yourself:

```bash
python3 -B <chapter>/scripts/vbmeta-flags.py clear vbmeta.img fixed.img
python3 -B <chapter>/scripts/vbmeta-flags.py show  fixed.img | grep integrity
#   integrity hash            MATCH
python3 -B <chapter>/scripts/vbmeta-flags.py diff  vbmeta.img fixed.img
#   bytes changed: 1
#      123: 01 -> 00  FLAGS FIELD
```

Clearing one byte makes the hash valid again. **One byte is the entire difference between an image
that verifies and one that does not** — and that single fact is why the phone is dead, as stage 4
will confirm.
</details>

---

## Stage 3 — Carve the vault out of `super.img`

**Worth:** PART3.

```bash
cat super-dm-table.txt
ls -l super.img
```

```
system_ext   0-512: linear, 253:2 2048
vendor       0-256: linear, 253:2 4096
vault        0-1024: linear, 253:2 6144
```

<details>
<summary>Hint 1</summary>

The format is `0-LENGTH: linear, MAJOR:MINOR START`, and the file says both numbers are in 512-byte
sectors. You want the partition called `vault`.
</details>

<details>
<summary>Hint 2</summary>

If you extracted `0xEE` repeated, you assumed the partitions are packed end to end: 512 + 256 = 768
sectors. They are not. Read the `START` column, and notice what all three start values have in common.
</details>

<details>
<summary>Solution</summary>

```bash
# vault: start 6144 sectors, length 1024 sectors
dd if=super.img bs=512 skip=6144 count=1024 2>/dev/null | tr -d '\0' | head -5
```

```
stage3:ALIGNED;
seed=524288
# every logical partition starts on a 1 MiB boundary.
```

**PART3 = `ALIGNED`**, and `seed=524288` cross-checks stage 1.

The trap and the lesson:

| | Start sector | ÷ 2048 |
|---|---:|---:|
| `system_ext` | 2,048 | 1 |
| `vendor` | 4,096 | 2 |
| `vault` | 6,144 | 3 |

Every start is a multiple of 2,048 sectors = **1 MiB**, which is `liblp`'s default partition
alignment. The partitions are 512, 256 and 1,024 sectors long — so if they were packed contiguously
`vault` would start at sector 768. It starts at 6,144. Everything between is padding, filled with
`0xEE` so the failure is obvious rather than subtle.

This is not an invented puzzle. Measured on a real Android 15 device, the five logical partitions
inside `super` started at sectors 2,048 / 1,832,960 / 1,847,296 / 2,273,280 / 6,463,488 — every one a
whole multiple of 2,048, with gaps of 1,472 and 984 sectors between them purely to reach the next
boundary. See [`../examples/measured-avd-boot-state.md`](../examples/measured-avd-boot-state.md) §4.

**Consequence beyond the CTF:** anyone rebuilding a `super` image by concatenating partition images
without reproducing the alignment produces something that flashes cleanly and does not boot, with no
error message pointing at alignment.
</details>

---

## Stage 4 — Which command killed the phone?

**Worth:** PART4. **This token is not stored in any file.** You have to know the answer.

```bash
cat fastboot-session.log
```

The task: find the **single command** that turned a recoverable situation into an unrecoverable one,
by its timestamp. PART4 is that command's **verb**, upper-cased.

<details>
<summary>Hint 1</summary>

At `00:02:15` the device was unlocked, rooted, and working. At `00:37:15` it is dead. Something
between those two points was irreversible. There is only one candidate, and it is not the flash.
</details>

<details>
<summary>Hint 2</summary>

Look at what the device refuses at `00:35:40` and `00:36:02`, and ask *why* it refuses. Then ask what
would have had to be true for `flashing unlock` to succeed — and which component sets that.
</details>

<details>
<summary>Hint 3</summary>

Stage 2 told you the `vbmeta` on this device fails its own integrity check. What does a **locked**
bootloader do with an image that fails verification?
</details>

<details>
<summary>Solution</summary>

**`[00:31:20] $ fastboot flashing lock`**

**PART4 = `LOCK`.**

The full chain, and this is the answer worth being able to give in an interview:

1. **`00:01:02`** — a patched boot image was flashed. Fine on an unlocked device.
2. **`00:01:40`** — `--disable-verity flash vbmeta`. The host's own log line
   `Rewriting vbmeta struct at offset: 0` shows the host editing the image before sending it. As stage
   2 proved, that edit **invalidates the image's own hash**. Also fine on an unlocked device, because
   an unlocked bootloader treats a verification failure as advisory.
3. **`00:31:20`** — `fastboot flashing lock`. **This is the fatal command.** The device now has a
   bootloader that *enforces* verification, and two images on it that cannot pass: a patched `boot`
   and a `vbmeta` whose hash does not match its signature.
4. **`00:33:00`** — boot state **RED**. "Your device is corrupt." Exactly correct behaviour: this is
   Verified Boot doing precisely what it exists to do.
5. **`00:35:40`** — `flashing unlock` fails with `oem unlock is not allowed`. **This is the trap door
   closing.** Unlocking requires `get_unlock_ability = 1`, and that flag is set only by a booted,
   screen-unlocked Android session. Android will not boot. There is no fastboot-side way to set it.
6. **`00:36:02`** — `flash boot_a` fails with `Device is locked. Cannot flash images`. The locked
   bootloader refuses writes, so the good image cannot be put back.

**The device is now in a cycle with no exit through software you own.** Locked, so it will not flash;
unbootable, so it cannot be unlocked; and unlocking is the only thing that would permit the flash that
would make it bootable.

### What should have happened

The safe order for returning a device to stock is not negotiable:

```
1. fastboot flash <every partition from the STOCK factory image>   # or flashall / update
2. fastboot reboot
3. confirm it boots, confirm it is stock, confirm ro.boot.verifiedbootstate is orange
4. adb reboot bootloader
5. fastboot flashing lock
```

**Flash stock, boot it, verify it, then lock.** The technician did steps 4 and 5 and skipped 1 to 3.

### Why the other candidates are wrong

- `flash boot_a magisk_patched...` — reversible. Flash the stock boot image back.
- `--disable-verity flash vbmeta` — reversible. Flash the stock `vbmeta` back. Stage 2 even showed you
  that clearing one byte restores the hash.
- `flashing unlock`, earlier in the device's life — destructive of *data*, but it is the state that
  made everything above recoverable.
- `reboot` — a reboot.

Every one of those is undoable **while the bootloader is unlocked**. `flashing lock` is the command
that removes the ability to undo anything, and it does so while the device is in a state that cannot
survive being locked.
</details>

---

## Assemble

```
APN61{SPARSE_BYTE123_ALIGNED_RELOCK}
```

Note that PART4 is `RELOCK`, not `LOCK` — the token is the *operation*, which is a relock. If you
answered `LOCK` you identified the right command; the briefing asked for the verb of what the
technician was doing, which was putting the device back.

Verify:

```bash
python3 -B <chapter>/scripts/make-ctf-images.py /tmp/verify --solve | tail -3
rm -rf /tmp/verify
```

---

## Post-mortem questions

These are the point of the exercise. The flag is a receipt.

**Q1.** At `00:35:40` the technician tried `fastboot flashing unlock` and got
`oem unlock is not allowed`. Explain, in terms of *which component holds which piece of state*, why
that refusal is correct behaviour and not a bug.

<details>
<summary>Answer</summary>

The unlock decision is split across two components on purpose, and neither can act alone:

- **Android** owns the "OEM unlocking" flag. Setting it requires a booted system and the owner's
  screen-lock credential. It is stored where the bootloader can read it and normal-world software
  cannot forge it.
- **The bootloader** owns the lock state and reads that flag at boot, exposing it as
  `flashing get_unlock_ability`.

The split is what makes physical theft a dead end: a thief with a locked, powered-off phone cannot
unlock the bootloader, because unlocking requires first defeating the screen lock, and the screen lock
is what the unlock was going to help them defeat.

The technician's device is collateral damage from a control working exactly as designed. Any vendor
path that let you unlock without that flag would be a serious vulnerability — it is on the bug-bounty
list in [§5.10](../README.md#510-bug-bounty-patterns) for that reason.
</details>

**Q2.** Suppose the technician had relocked but the `vbmeta` had been the **stock** one, with only the
boot image patched. Same outcome, or different?

<details>
<summary>Answer</summary>

**Same outcome.** The stock `vbmeta` carries an `AvbHashDescriptor` for `boot` with the *stock* boot
image's hash. A patched boot image does not match it, so a locked bootloader refuses to boot for that
reason instead. RED either way.

The corollary matters more than the answer: **`--disable-verity` is not what made this
unrecoverable.** The patched boot image alone was enough. `--disable-verity` was about being able to
modify `/system`, and it is an aggravating factor rather than the cause.

This is the precision the chapter argues for in [§3.8](../README.md#38-vbmeta-flags-and-what---disable-verity-actually-disables):
"disable-verity turns off Verified Boot" is a sentence to avoid, because it leads to exactly this
misdiagnosis.
</details>

**Q3.** The `vbmeta` in stage 2 has `rollback_index = 11`. Is that relevant to this incident?

<details>
<summary>Answer</summary>

**No — it is a deliberate red herring**, and noticing that it is irrelevant is the skill.

Rollback indexes defeat *downgrade* attacks: a bootloader refuses an image whose index is lower than
the value stored in tamper-evident storage. Nothing here is a downgrade. The device is refusing an
image that fails its *signature*, which is a different check that happens earlier and for a different
reason.

Rollback indexes do bite in a related situation worth knowing: if the technician had tried to restore
an **older** factory image after the device had taken an OTA, the bootloader could refuse it for
anti-rollback reasons even though it is a genuine, correctly-signed OEM image. That is a real way to
be stuck with a working fastboot and no usable image, and it is why
[20-Security-Architecture §3.1](../../20-Security-Architecture/README.md#31-verified-boot-and-android-verified-boot-20-avb)
says to check the anti-rollback version before accepting an OTA on a device you intend to downgrade.
</details>

**Q4.** Write the one-paragraph incident report you would hand the shop owner. Cause, why the recovery
attempts failed, what should have been done, and what — honestly — can be done now.

<details>
<summary>Model answer</summary>

> The device was returned to a locked bootloader while modified images were present on it. A locked
> bootloader enforces Verified Boot: it refuses to start any boot image that does not verify against
> the manufacturer's key. Both the boot image (patched for root) and the `vbmeta` image (edited by
> `fastboot --disable-verity`, which invalidates that image's own signature) fail that check, so the
> device stops at the "corrupt" screen. Recovery attempts then failed for a structural reason rather
> than a technical one: re-unlocking requires a flag that only a fully booted, screen-unlocked Android
> can set, and Android cannot start; while the bootloader remains locked it refuses every write that
> would fix the images. The correct procedure is to flash the complete stock factory image, boot it,
> confirm it works, and only then relock. What can be done now depends entirely on the manufacturer:
> some provide a low-level recovery path — an emergency download mode taking a vendor-signed loader —
> which can rewrite storage below the bootloader's refusal. That path is vendor-specific, may require
> an authorised service centre, and does not exist for every model. **No software the shop owns will
> recover it**, and any tool advertising otherwise for this model should be treated with suspicion.
> Customer data written after the original unlock is unaffected by this incident but is not reachable
> without a working boot, and any recovery via factory image will erase it.

The parts that make this a good report rather than a plausible one: it names the mechanism, it
explains why the *attempts* failed separately from why the device broke, it gives the correct
procedure so it does not recur, and it is **honest about the limits of what can be done now** rather
than promising a fix that depends on the vendor.
</details>

**Q5.** Design a pre-flight check the shop could run before any `fastboot flashing lock`, that would
have prevented this. What does it check, and what does it refuse?

<details>
<summary>Model answer</summary>

Before permitting a lock, verify **every** partition the bootloader will verify:

1. Require the stock factory image for the **exact** `ro.build.fingerprint` currently on the device,
   character for character, present on the workstation.
2. Hash `boot`, `init_boot`, `vbmeta` and every `vbmeta_*` on the device (or the images about to be
   flashed) against that factory image. Any mismatch is a refusal.
3. Parse each `vbmeta` and require `flags == 0` **and** an integrity hash that validates — exactly
   what [`../scripts/vbmeta-flags.py`](../scripts/vbmeta-flags.py) reports. A `MISMATCH` is an
   absolute refusal.
4. On an A/B device, check **both** slots. Locking with a patched image on the inactive slot is the
   same brick, delayed until the next slot switch.
5. Require the device to have **booted successfully** from the images now on it, and confirm
   `ro.boot.verifiedbootstate` reads `orange` rather than being absent — an unlocked device that boots
   clean is the only state from which locking is safe.
6. Only then permit the lock.

The general principle, which applies well beyond phone repair: **make the irreversible operation
conditional on a verifiable precondition, and make the check mechanical.** The technician here knew
the rule — flash stock first — and skipped it under time pressure, which is what people do. A check
that refuses does not get tired at 6pm.
</details>

---

## Success criteria

- [ ] All four tokens recovered and the flag assembled
- [ ] Stage 1 solved by **expanding** the sparse image, not by `strings`, and the 524288 offset
      explained in terms of the `FILL` chunk
- [ ] Stage 2's `MISMATCH` explained: which byte, why it broke the hash, and what that implies about
      the bootloader that accepted the image
- [ ] Stage 3 solved from the dm table, with the 1 MiB alignment stated and the contiguous-packing
      trap explained
- [ ] Stage 4's fatal command named **and** the full six-step chain to the dead device reconstructed
- [ ] The `rollback_index` red herring correctly dismissed, with the situation where it *would* matter
- [ ] The incident report written, including honest limits on what can be recovered
- [ ] A pre-flight check designed that would have refused the lock

## Cleanup

```bash
rm -rf /tmp/ctf-vault /tmp/verify
find . -name __pycache__ -type d       # must print nothing
```

## Where to go next

- [62-Magisk](../../62-Magisk/README.md) — the rooting side, and
  [its lab 01](../../62-Magisk/labs/lab-01-root-a-device.md), which is the one lab in this repository
  that does perform the destructive procedure, on hardware you are willing to lose
- [20-Security-Architecture](../../20-Security-Architecture/README.md) — AVB, dm-verity and the boot
  states in full
- [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) — the only non-forgeable
  answer to "is this device locked?"
- [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) — build a C harness and find
  the integer overflow that lab 02's Python tool structurally cannot exhibit
